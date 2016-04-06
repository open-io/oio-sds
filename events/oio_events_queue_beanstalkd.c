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
#include <errno.h>
#include <poll.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <glib.h>
#include <zmq.h>

#include <core/oio_core.h>
#include <metautils/lib/metautils_sockets.h>
#include <metautils/lib/metautils_resolv.h>
#include <metautils/lib/metautils_syscall.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_beanstalkd.h"
#include "oio_events_queue_buffer.h"

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static void _q_set_max_pending (struct oio_events_queue_s *self, guint v);
static void _q_set_buffering (struct oio_events_queue_s *self, gint64 v);
static GError * _q_run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending));

static struct oio_events_queue_vtable_s vtable_BEANSTALKD =
{
	_q_destroy, _q_send, _q_send_overwritable, _q_is_stalled,
	_q_set_max_pending, _q_set_buffering, _q_run
};

struct _queue_BEANSTALKD_s
{
	struct oio_events_queue_vtable_s *vtable;
	GAsyncQueue *queue;
	gchar *endpoint;
	guint max_events_in_queue;

	struct oio_events_queue_buffer_s buffer;
};

/* -------------------------------------------------------------------------- */

GError *
oio_events_queue_factory__create_beanstalkd (const char *endpoint,
		struct oio_events_queue_s **out)
{
	EXTRA_ASSERT(endpoint != NULL);
	EXTRA_ASSERT(out != NULL);
	*out = NULL;

	if (!metautils_url_valid_for_connect (endpoint))
		return BADREQ("Invalid beanstalkd endpoint [%s]", endpoint);

	struct _queue_BEANSTALKD_s *self = g_malloc0 (sizeof(*self));
	self->vtable = &vtable_BEANSTALKD;
	self->queue = g_async_queue_new ();
	self->max_events_in_queue = OIO_EVTQ_MAXPENDING;
	self->endpoint = g_strdup (endpoint);

	oio_events_queue_buffer_init(&(self->buffer), 1 * G_TIME_SPAN_SECOND);

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}

static void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	oio_events_queue_buffer_set_delay(&(q->buffer), v);
}

static void
_q_set_max_pending (struct oio_events_queue_s *self, guint v)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	if (q->max_events_in_queue != v) {
		GRID_NOTICE("max events in queue set to [%u]", v);
		q->max_events_in_queue = v;
	}
}

static int
_send (int fd, struct iovec *iov, unsigned int iovcount)
{
	int w;
retry:
	w = writev (fd, iov, 3);
	if (w < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct pollfd pfd = {0};
			pfd.fd = fd;
			pfd.events = POLLOUT;
			metautils_syscall_poll (&pfd, 1, 1000);
			goto retry;
		}
		return 0;
	}

	while (w > 0 && iovcount > 0) {
		if (iov[0].iov_len <= (size_t)w) {
			w -= iov[0].iov_len;
			iov[0].iov_len = 0;
			iov ++;
			iovcount --;
		} else {
			iov[0].iov_len -= w;
			w = 0;
		}
	}
	if (iovcount > 0)
		goto retry;

	GRID_TRACE("BEANSTALKD put sent!");
	return 1;
}

static int
_put (int fd, struct iovec *iov, unsigned int iovcount)
{
	if (!_send(fd, iov, iovcount))
		return 0;

	GError *err = NULL;
	guint8 buf[256];
	int r = sock_to_read (fd, 1000, buf, sizeof(buf), &err);
	if (r < 0) {
		GRID_WARN("reply error: (%d) %s", err->code, err->message);
		r = 0;
	} else if (r == 0) {
		GRID_WARN("reply error: closed by peer");
		r = 0;
	} else {
		GRID_TRACE("Reply: %.*s", r, buf);
		r = 1;
	}

	if (err)
		g_clear_error (&err);
	return r;
}

static void
_maybe_send_overwritable(struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gboolean __send(gpointer key, gpointer msg, gpointer udata)
	{
		(void) udata;
		g_free(key);
		_q_send(self, (gchar*)msg);
		return TRUE;
	}

	oio_events_queue_buffer_maybe_flush(&(q->buffer), __send, NULL);
}

static GError *
_q_run (struct oio_events_queue_s *self, gboolean (*running) (gboolean pending))
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gchar *saved = NULL;
	int fd = -1;

	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	EXTRA_ASSERT (running != NULL);

	while ((*running)(0 < g_async_queue_length(q->queue))) {
		_maybe_send_overwritable(self);

		/* find an event, prefering the last that failed */
		gchar *msg = saved;
		saved = NULL;
		if (!msg) msg = g_async_queue_timeout_pop (q->queue, G_TIME_SPAN_SECOND);
		if (!msg) continue;

		/* forward hat event */
		if (*msg) {

			/* lazy-reconnection */
			if (fd < 0) {
				GError *err = NULL;
				if (0 > (fd = sock_connect (q->endpoint, &err))) {
					GRID_WARN("BEANSTALKD: reconnection failed to %s: (%d) %s",
							q->endpoint, err->code, err->message);
					g_clear_error (&err);
					saved = msg;
					msg = NULL;

					/* Avoid looping crazily until the beanstalkd becomes up
					 * again, let's sleep a little bit. */
					g_usleep (250 * G_TIME_SPAN_MILLISECOND);
					continue;
				} else {
					GRID_DEBUG("BEANSTALKD: reconnected to %s", q->endpoint);
				}
			}

			/* prepare the header, and the buffers to be sent */
			struct iovec iov[3];
			gsize msglen = strlen(msg);
			GString *header = g_string_new ("");
			g_string_printf (header, "put %u %u %u %"G_GSIZE_FORMAT"\r\n",
					OIO_EVT_BEANSTALKD_DEFAULT_PRIO,
					OIO_EVT_BEANSTALKD_DEFAULT_DELAY,
					OIO_EVT_BEANSTALKD_DEFAULT_TTR,
					msglen);
			iov[0].iov_base = header->str;
			iov[0].iov_len = header->len;
			iov[1].iov_base = msg;
			iov[1].iov_len = msglen;
			iov[2].iov_base = "\r\n";
			iov[2].iov_len = 2;

			if (!_put (fd, iov, 3)) {
				sock_set_linger(fd, 1, 1);
				metautils_pclose (&fd);
				saved = msg;
				msg = NULL;
			}

			g_string_free (header, TRUE);
			header = NULL;
		}

		oio_str_clean (&msg);
	}

	if (fd >= 0)
		sock_set_linger(fd, 1, 1);
	metautils_pclose (&fd);

	if (saved)
		g_async_queue_push (q->queue, saved);
	saved = NULL;
	return NULL;
}

static void
_q_destroy (struct oio_events_queue_s *self)
{
	if (!self) return;
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT(q->vtable == &vtable_BEANSTALKD);
	g_async_queue_unref (q->queue);
	oio_str_clean (&q->endpoint);
	oio_events_queue_buffer_clean(&(q->buffer));
	q->vtable = NULL;
	g_free (q);
}

static void
_q_send (struct oio_events_queue_s *self, gchar *msg)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	g_async_queue_push (q->queue, msg);
}

static void
_q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	oio_events_queue_buffer_put(&(q->buffer), key, msg);
}

static gboolean
_q_is_stalled (struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s*) self;
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	const int l = g_async_queue_length (q->queue);
	if (l <= 0)
		return FALSE;
	return ((guint)l) >= q->max_events_in_queue;
}
