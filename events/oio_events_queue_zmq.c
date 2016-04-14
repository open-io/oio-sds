/*
OpenIO SDS event queue
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>
#include <zmq.h>

#include <core/oio_core.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_zmq.h"
#include "oio_events_queue_buffer.h"

#define HEADER_SIZE 14

struct event_s
{
	/* fields used as unique key */
	guint32 rand;
	guint32 recv_time;
	guint32 evtid;
	guint16 procid;

	/* and then the payload */
	guint16 size;
	gint64 last_sent;
	guint8 message[];
};

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static void _q_set_max_pending (struct oio_events_queue_s *self, guint v);
static void _q_set_buffering(struct oio_events_queue_s *self, gint64 v);
static GError * _q_run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending));

static struct oio_events_queue_vtable_s vtable_AGENT =
{
	_q_destroy, _q_send, _q_send_overwritable, _q_is_stalled,
	_q_set_max_pending, _q_set_buffering, _q_run
};

struct _queue_AGENT_s
{
	struct oio_events_queue_vtable_s *vtable;

	gchar *url;

	/* A queue to transmit events from request workers to the events worker. */
	GAsyncQueue *queue;

	/* counter of events currently waiting for ACKS. Not supposed to be
	   written by any thread other than the interal threads. */
	volatile guint gauge_pending;

	/* used to compute the event id */
	guint16 procid;
	guint32 counter;

	/* how many events are received each time the queue becomes active.
	   A low value helps preventing starvation but leads to more contexts
	   switches. */
	guint max_recv_per_round;

	/* how many events may be stored in the queue, before the queue reports
	   a stalled state. */
	guint max_events_in_queue;

	/* stats on events streams, managed only by the ZMQ2AGENT thead */
	guint64 counter_received;
	guint64 counter_sent;
	guint64 counter_ack;
	guint64 counter_ack_notfound;

	struct oio_events_queue_buffer_s buffer;
};

struct _zmq2agent_ctx_s
{
	GList *pending_events;
	struct _queue_AGENT_s *q;
	const guint32 r;
	void *zpull;
	void *zagent;
	time_t last_error;
};

struct _gq2zmq_ctx_s
{
	GAsyncQueue *queue;
	struct _queue_AGENT_s *q;
	void *zpush;
	gboolean (*running) (gboolean pending);
};

/* -------------------------------------------------------------------------- */

GError *
oio_events_queue_factory__create_zmq (const char *zurl,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT (zurl != NULL);
	EXTRA_ASSERT (out != NULL);

	struct _queue_AGENT_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_AGENT;
	self->queue = g_async_queue_new ();
	self->url = g_strdup (zurl);
	self->max_recv_per_round = 32;
	self->max_events_in_queue = OIO_EVTQ_MAXPENDING;
	self->procid = getpid();
	oio_events_queue_buffer_init(&(self->buffer), 1 * G_TIME_SPAN_SECOND);
	*out = (struct oio_events_queue_s *) self;
	return NULL;
}

static void
_q_set_max_pending (struct oio_events_queue_s *self, guint v)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s *)self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_AGENT);
	if (q->max_events_in_queue != v) {
		GRID_INFO("max events in queue set to [%u]", v);
		q->max_events_in_queue = v;
	}
}

static void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s *)self;
	oio_events_queue_buffer_set_delay(&(q->buffer), v);
}


static void
_q_destroy (struct oio_events_queue_s *self)
{
	if (!self) return;
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s*) self;
	EXTRA_ASSERT(q->vtable == &vtable_AGENT);
	g_async_queue_unref (q->queue);
	oio_str_clean (&q->url);
	oio_events_queue_buffer_clean(&(q->buffer));
	g_free (q);
}

static void
_q_send (struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_AGENT);
	g_async_queue_push (q->queue, msg);
}

	static void
_q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s*) self;
	oio_events_queue_buffer_put(&(q->buffer), key, msg);
}

static gboolean
_q_is_stalled (struct oio_events_queue_s *self)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_AGENT);
	const int l = g_async_queue_length (q->queue);
	const guint waiting = q->gauge_pending;
	return (waiting + (guint)(l>0?l:0)) >= q->max_events_in_queue;
}

/* -------------------------------------------------------------------------- */

#define more ZMQ_SNDMORE|ZMQ_MORE

static gboolean
_zmq2agent_send_event (time_t now, struct _zmq2agent_ctx_s  *ctx,
		struct event_s *evt, const char *dbg)
{
	int rc;

	if (ctx->last_error == now) {
		GRID_DEBUG("ZMQ2AGENT event delayed, stream paused");
		return FALSE;
	}

	evt->last_sent = now;
retry:
	rc = zmq_send (ctx->zagent, "", 0, more|ZMQ_DONTWAIT);
	if (rc == 0) {
		rc = zmq_send (ctx->zagent, evt, HEADER_SIZE, more|ZMQ_DONTWAIT);
		if (rc == HEADER_SIZE)
			rc = zmq_send (ctx->zagent, evt->message, evt->size, ZMQ_DONTWAIT);
	}

	if (rc < 0) {
		if (EINTR == (rc = zmq_errno ()))
			goto retry;
		ctx->last_error = evt->last_sent;
		GRID_INFO("EVT:ERR %s (%d) %s", dbg, rc, zmq_strerror(rc));
		return FALSE;
	} else {
		++ ctx->q->counter_sent;
		ctx->last_error = 0;
		GRID_DEBUG("EVT:SNT %s", dbg);
		return TRUE;
	}
}

static gboolean
_zmq2agent_manage_event (guint32 r, struct _zmq2agent_ctx_s *ctx, zmq_msg_t *msg)
{
	const time_t now = oio_ext_monotonic_seconds();
	if (!ctx->zagent) return TRUE;

	const size_t len = zmq_msg_size(msg);
	struct event_s *evt = g_malloc (sizeof(struct event_s) + len);
	memcpy (evt->message, zmq_msg_data(msg), len);
	evt->last_sent = now;
	evt->rand = r;
	evt->evtid = ctx->q->counter ++;
	evt->procid = ctx->q->procid;
	evt->size = len;
	evt->recv_time = evt->last_sent;

	ctx->pending_events = g_list_prepend (ctx->pending_events, evt);
	ctx->q->gauge_pending ++;

	gchar strid[1+ 2*HEADER_SIZE];
	oio_str_bin2hex(evt, HEADER_SIZE, strid, sizeof(strid));
	GRID_DEBUG("EVT:DEF %s (%u) %.*s", strid,
			ctx->q->gauge_pending, evt->size, evt->message);

	return _zmq2agent_send_event (now, ctx, evt, strid);
}

static gint
_cmp (gconstpointer a, gconstpointer b)
{
	const struct event_s *e0 = a, *e1 = b;
	return memcmp(e0, e1, HEADER_SIZE);
}

static void
_zmq2agent_manage_ack (struct _zmq2agent_ctx_s *ctx, zmq_msg_t *msg)
{
	if (zmq_msg_size (msg) != HEADER_SIZE)
		return;

	gchar strid[1+(2*HEADER_SIZE)];
	void *d = zmq_msg_data (msg);
	oio_str_bin2hex(d, HEADER_SIZE, strid, sizeof(strid));

	GList *li = g_list_find_custom (ctx->pending_events, d, _cmp);
	if (!li) {
		GRID_INFO("EVT:OUT %s", strid);
		++ ctx->q->counter_ack_notfound;
	} else {
		GRID_DEBUG("EVT:ACK %s", strid);
		ctx->pending_events = g_list_remove_link (ctx->pending_events, li);
		g_list_free_full (li, g_free);
		-- ctx->q->gauge_pending;
		++ ctx->q->counter_ack;
	}
}

static void
_retry_events (struct _zmq2agent_ctx_s *ctx)
{
	gchar strid[1+(2*HEADER_SIZE)];
	const time_t now = oio_ext_monotonic_seconds ();
	const time_t oldest = now > 5 ? now - 5 : 0;

	for (GList *l=g_list_last(ctx->pending_events); l ;l=l->prev) {
		struct event_s *evt = l->data;
		if (evt->last_sent < oldest) {
			oio_str_bin2hex(evt, HEADER_SIZE, strid, sizeof(strid));
			if (!_zmq2agent_send_event (now, ctx, evt, strid))
				break;
		}
	}
}

static void
_zmq2agent_receive_acks (struct _zmq2agent_ctx_s *ctx)
{
	int rc;
	zmq_msg_t msg;
	do {
		zmq_msg_init (&msg);
		rc = zmq_msg_recv (&msg, ctx->zagent, ZMQ_DONTWAIT);
		if (rc > 0)
			_zmq2agent_manage_ack (ctx, &msg);
		zmq_msg_close (&msg);
	} while (rc >= 0);
}

static gboolean
_zmq2agent_receive_events (struct _zmq2agent_ctx_s *ctx)
{
	int rc, ended = 0;
	guint i = 0;
	do {
		zmq_msg_t msg;
		zmq_msg_init (&msg);
		rc = zmq_msg_recv (&msg, ctx->zpull, ZMQ_DONTWAIT);
		ended = (rc == 0); // empty frame is an EOF
		if (rc > 0) {
			++ ctx->q->counter_received;
			if (!_zmq2agent_manage_event (oio_ext_rand_int(), ctx, &msg))
				rc = 0; // make it break
		}
		zmq_msg_close (&msg);
	} while (rc > 0 && i++ < ctx->q->max_recv_per_round);
	return !ended;
}

static void
_zmq2agent_worker (struct _zmq2agent_ctx_s *ctx)
{
	/* XXX(jfs): a dedicated PRNG avoids locking the glib's PRNG for each call
	   (such global locks are present in the GLib) and opening it with a seed
	   from the glib's PRNG avoids syscalls to the special file /dev/urandom */
	gint64 last_debug = oio_ext_monotonic_time ();

	zmq_pollitem_t pi[2] = {
		{ctx->zpull, -1, ZMQ_POLLIN, 0},
		{ctx->zagent, -1, ZMQ_POLLIN, 0},
	};

	for (gboolean run = TRUE; run ;) {
		int rc = zmq_poll (pi, 2, 1000);
		if (rc < 0) {
			int err = zmq_errno();
			if (err != ETERM && err != EINTR)
				GRID_WARN("ZMQ poll error : (%d) %s", err, zmq_strerror(err));
			if (err != EINTR)
				break;
		}
		if (pi[1].revents)
			_zmq2agent_receive_acks (ctx);
		_retry_events (ctx);
		if (pi[0].revents)
			run = _zmq2agent_receive_events (ctx);

		/* Periodically write stats in the log */
		gint64 now = oio_ext_monotonic_time ();
		if ((now - last_debug) > 2 * G_TIME_SPAN_MINUTE) {
			GRID_INFO("ZMQ2AGENT recv=%"G_GINT64_FORMAT" sent=%"G_GINT64_FORMAT
					" ack=%"G_GINT64_FORMAT"+%"G_GINT64_FORMAT" queue=%u",
					ctx->q->counter_received, ctx->q->counter_sent,
					ctx->q->counter_ack, ctx->q->counter_ack_notfound,
					ctx->q->gauge_pending);
			last_debug = now;
		}
	}

	GRID_INFO ("Thread stopping [NOTIFY-ZMQ2AGENT]");
}

static gboolean
_forward_event (void *zpush, gchar *encoded)
{
	gboolean rc = TRUE;
	size_t len = strlen(encoded);
	if (zpush) {
retry:
		if (0 > zmq_send (zpush, encoded, len, 0)) {
			int err = zmq_errno();
			if (err == EINTR)
				goto retry;
			if (err == ETERM)
				rc = FALSE;
			GRID_WARN("EVT:ERR - %s %s", encoded, zmq_strerror(err));
		}
	} else {
		GRID_DEBUG("EVT:END - %s", encoded);
	}
	g_free (encoded);
	return rc;
}

static guint
_gq2zmq_has_pending (struct _gq2zmq_ctx_s *ctx)
{
	return (0 < ctx->q->gauge_pending) || (0 < g_async_queue_length (ctx->queue));
}

static void
_maybe_send_overwritable(struct oio_events_queue_s *self)
{
	struct _queue_AGENT_s *q = (struct _queue_AGENT_s *)self;
	gboolean __send(gpointer key, gpointer msg, gpointer udata)
	{
		(void) udata;
		g_free(key);
		_q_send(self, (gchar*)msg);
		return TRUE;
	}

	oio_events_queue_buffer_maybe_flush(&(q->buffer), __send, NULL);
}

static gpointer
_gq2zmq_worker (struct _gq2zmq_ctx_s *ctx)
{
	while (ctx->running (_gq2zmq_has_pending (ctx))) {
		_maybe_send_overwritable((struct oio_events_queue_s *)ctx->q);
		gchar *tmp =
			(gchar*) g_async_queue_timeout_pop (ctx->queue, G_TIME_SPAN_SECOND);
		if (tmp && !_forward_event (ctx->zpush, tmp))
			break;
	}

	for (;;) { /* manage what remains in the GQueue */
		gchar *tmp = g_async_queue_try_pop (ctx->queue);
		if (!tmp || !_forward_event (ctx->zpush, tmp))
			break;
	}

	zmq_send (ctx->zpush, "EOF", 0, 0);
	GRID_INFO ("Thread stopping [NOTIFY-GQ2ZMQ]");
	return ctx;
}

static void _zset (void *z, int opt, int val) {
	zmq_setsockopt (z, opt, &val, sizeof(val));
}

static GError *
_q_run (struct oio_events_queue_s *self, gboolean (*running) (gboolean pending))
{
	int rc;
	GError *err = NULL;
	void *zctx = NULL, *zpush = NULL, *zpull = NULL, *zagent = NULL;
	GThread *th_gq2zmq = NULL;
	struct _zmq2agent_ctx_s zmq2agent = {0};

	struct _queue_AGENT_s *q = (struct _queue_AGENT_s *)self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_AGENT);

	/* Pair of interconnected sockets between the gq2zmq thread and the
	   zmq2agent thread */
	if (!(zctx = zmq_init (1))) {
		err = SYSERR("ZMQ context init error");
		goto exit;
	}
	if (!(zpush = zmq_socket (zctx, ZMQ_PUSH))) {
		err = SYSERR("ZMQ socket init error (push)");
		goto exit;
	}
	if (!(zpull = zmq_socket (zctx, ZMQ_PULL))) {
		err = SYSERR("ZMQ socket init error (pull)");
		goto exit;
	}
	if (!(zagent = zmq_socket (zctx, ZMQ_DEALER))) {
		err = SYSERR("ZMQ socket init error (agent)");
		goto exit;
	}

	_zset (zpush, ZMQ_LINGER, 1000);
	_zset (zpull, ZMQ_SNDHWM, 16);
	_zset (zpull, ZMQ_RCVHWM, 16);
	_zset (zagent, ZMQ_LINGER, 1000);
	_zset (zagent, ZMQ_SNDBUF, 64*1024);
	_zset (zagent, ZMQ_RCVBUF, 64*1024);
	_zset (zagent, ZMQ_SNDHWM, 64);
	_zset (zagent, ZMQ_RCVHWM, 64);

	if (0 > (rc = zmq_bind (zpush, "inproc://events"))) {
		rc = zmq_errno ();
		err = SYSERR("ZMQ connection error (event-agent) : (%d) %s",
				rc, zmq_strerror (rc));
		goto exit;
	}
	if (0 > (rc = zmq_connect (zpull, "inproc://events"))) {
		rc = zmq_errno ();
		err = SYSERR("ZMQ connection error (event-agent) : (%d) %s",
				rc, zmq_strerror (rc));
		goto exit;
	}
	if (0 > (rc = zmq_connect (zagent, q->url))) {
		rc = zmq_errno ();
		err = SYSERR("ZMQ connection error (event-agent) : (%d) %s",
				rc, zmq_strerror (rc));
		goto exit;
	}

	/* Runs the converter for GAsyncQueue to ZMQ */
	struct _gq2zmq_ctx_s gq2zmq = {
		.queue = q->queue, .q = q, .zpush = zpush, .running = running
	};
	th_gq2zmq = g_thread_try_new("notifier-gq2zmq",
			(GThreadFunc) _gq2zmq_worker, &gq2zmq, &err);
	if (err)
		goto exit;

	/* Runs the events worker */
	zmq2agent.q = q;
	zmq2agent.zpull = zpull;
	zmq2agent.zagent = zagent;
	_zmq2agent_worker (&zmq2agent);

exit:
	if (th_gq2zmq) g_thread_join (th_gq2zmq);
	if (zmq2agent.pending_events) g_list_free_full (zmq2agent.pending_events, g_free);
	if (zagent) zmq_close (zagent);
	if (zpull) zmq_close (zpull);
	if (zpush) zmq_close (zpush);
	if (zctx) zmq_term (zctx);
	return err;
}
