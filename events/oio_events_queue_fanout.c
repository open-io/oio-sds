/*
OpenIO SDS event queue
Copyright (C) 2016-2019 OpenIO SAS, as part of OpenIO SDS

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
#include <errno.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <glib.h>
#include <math.h>

#include <core/oio_core.h>
#include <events/events_variables.h>
#include <metautils/lib/metautils_sockets.h>
#include <metautils/lib/metautils_resolv.h>
#include <metautils/lib/metautils_syscall.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_buffer.h"
#include "oio_events_queue_fanout.h"

#define EXPO_BACKOFF(DELAY,TRY,MAX_TRIES) \
	g_usleep((1 << MIN(TRY, MAX_TRIES)) * DELAY); \
	TRY++

#define NETERR(FMT,...) NEWERROR(CODE_NETWORK_ERROR, FMT, ##__VA_ARGS__)

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static gint64 _q_get_health(struct oio_events_queue_s *self);

static void _q_set_buffering (struct oio_events_queue_s *self, gint64 v);
static GError * _q_start (struct oio_events_queue_s *self);

static struct oio_events_queue_vtable_s vtable_FANOUT =
{
	.destroy = _q_destroy,
	.send = _q_send,
	.send_overwritable = _q_send_overwritable,
	.is_stalled = _q_is_stalled,
	.get_health = _q_get_health,
	.set_buffering = _q_set_buffering,
	.start = _q_start
};

struct _queue_FANOUT_s
{
	struct oio_events_queue_vtable_s *vtable;
	GAsyncQueue *queue;
	GThread *worker;

	gint64 pending_events;

	struct oio_events_queue_s **output_tab;
	guint output_nb;

	volatile gboolean running;

	struct oio_events_queue_buffer_s buffer;
};

/* -------------------------------------------------------------------------- */

GError *
oio_events_queue_factory__create_fanout (
		struct oio_events_queue_s **subv, guint sublen,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT(subv != NULL);
	EXTRA_ASSERT(sublen > 0);
	EXTRA_ASSERT(out != NULL);
	*out = NULL;

	struct _queue_FANOUT_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_FANOUT;
	self->queue = g_async_queue_new ();
	self->output_tab = subv;
	self->output_nb = sublen;
	oio_events_queue_buffer_init(&(self->buffer));

	/* Turn the buffering off, it is already done in the fanout layer */
	for (guint i = 0; i < sublen; i++) {
		struct oio_events_queue_s *sub = subv[i];
		oio_events_queue__set_buffering(sub, 0);
	}

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}

static void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s *)self;
	if (q->buffer.delay != v) {
		GRID_INFO("events buffering delay set to %"G_GINT64_FORMAT"s",
				v / G_TIME_SPAN_SECOND);
		oio_events_queue_buffer_set_delay(&(q->buffer), v);
	}
}

static void
_flush_buffered(struct _queue_FANOUT_s *q, gboolean total)
{
	const gint avail =
		oio_events_common_max_pending - g_async_queue_length(q->queue);
	if (avail < (gint) oio_events_common_max_pending / 100) {
		GRID_WARN("Pending events queue is reaching maximum: %d/%d",
				g_async_queue_length(q->queue),
				oio_events_common_max_pending);
	}

	/* This is not an else clause, we want to send the buffered events
	 * (even if we do it slowly). */
	const guint half = MAX(1U, (guint)avail / 2);
	oio_events_queue_send_buffered(
			(struct oio_events_queue_s*)q, &q->buffer,
			total ? G_MAXUINT : half);
}

static GError *
_q_run (struct _queue_FANOUT_s *q)
{
	GError *err = NULL;
	gchar *saved = NULL;
	gint64 last_flush = 0;
	guint next_output = 0;

	/* run the agent loop of the current queue */
	while (q->running
			|| !oio_events_queue_buffer_is_empty(&q->buffer)
			|| g_async_queue_length(q->queue) > 0	) {

		const gint64 now = oio_ext_monotonic_time();

		/* Build the deadline for the timed wait */
		if (now - last_flush > q->buffer.delay / 10 || !q->running) {
			last_flush = now;
			_flush_buffered(q, !q->running);
		}

		/* find an event, prefering the last that failed */
		gchar *msg = saved;
		saved = NULL;
		if (!msg) msg = g_async_queue_timeout_pop (q->queue, 300 * G_TIME_SPAN_MILLISECOND);
		if (!msg) continue;

		/* forward the event as a beanstalkd job */
		if (*msg) {
			struct oio_events_queue_s *out =
				q->output_tab[ next_output++ % q->output_nb ];
			oio_events_queue__send(out, msg);
			msg = NULL;
		}

		oio_str_clean (&msg);
	}

	if (saved)
		g_async_queue_push (q->queue, saved);
	saved = NULL;
	return err;
}

static gpointer
_q_worker(gpointer p)
{
	metautils_ignore_signals();
	GError *err = _q_run((struct _queue_FANOUT_s*)p);
	if (err) {
		GRID_WARN("Events queue run error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
	return p;
}

static GError *
_q_start (struct oio_events_queue_s *self)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	g_assert_nonnull(q);
	g_assert(q->vtable == &vtable_FANOUT);
	g_assert_null(q->worker);

	GError *err = NULL;

	/* Start each endpoint */
	if (!q->output_tab)
		err = NEWERROR(CODE_INTERNAL_ERROR, "No endpoint registered");

	for (guint i=0; !err && i<q->output_nb ;++i)
		err = oio_events_queue__start(q->output_tab[i]);

	/* Start our worker */
	if (!err) {
		q->running = TRUE;
		q->worker = g_thread_try_new("events|fanout", _q_worker, q, &err);
		GRID_WARN("%s worker started %p: (%d) %s", __FUNCTION__, q->worker,
				err ? err->code : 0, err ? err->message : "");
	}

	return err;
}

static void
_q_destroy (struct oio_events_queue_s *self)
{
	if (!self)
		return;

	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	g_assert(q->vtable == &vtable_FANOUT);

	q->running = FALSE;

	if (q->worker) {
		g_thread_join(q->worker);
		q->worker = NULL;
	}

	if (q->output_tab) {
		for (guint i=0; i<q->output_nb ;++i) {
			oio_events_queue__destroy(q->output_tab[i]);
			q->output_tab[i] = NULL;
		}
		g_free(q->output_tab);
	}

	g_async_queue_unref (q->queue);
	oio_events_queue_buffer_clean(&(q->buffer));

	q->vtable = NULL;
	g_free (q);
}

static void
_q_send (struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_FANOUT);
	g_async_queue_push (q->queue, msg);
}

static void
_q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	oio_events_queue_buffer_put(&(q->buffer), key, msg);
}

static gboolean
_q_is_stalled (struct oio_events_queue_s *self)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_FANOUT);
	const int l = g_async_queue_length (q->queue);
	if (l <= 0)
		return FALSE;
	return ((guint)l) >= oio_events_common_max_pending;
}

static gint64
_q_get_health(struct oio_events_queue_s *self)
{
	struct _queue_FANOUT_s *q = (struct _queue_FANOUT_s*) self;
	EXTRA_ASSERT(q != NULL && q->vtable == &vtable_FANOUT);

	gint64 health = 1;
	if (q->output_nb) {
		for (guint i=0; i< q->output_nb; ++i) {
			const gint64 h0 = oio_events_queue__get_health(q->output_tab[i]);
			health = MAX(health, h0);
		}
	}
	return health;
}
