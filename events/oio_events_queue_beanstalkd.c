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
#include <metautils/lib/server_variables.h>
#include <metautils/lib/metautils_sockets.h>
#include <metautils/lib/metautils_resolv.h>
#include <metautils/lib/metautils_syscall.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_beanstalkd.h"
#include "oio_events_queue_buffer.h"

#define INSERTED_PREFIX "INSERTED"
#define USING_PREFIX "USING"

#define EXPO_BACKOFF(DELAY,TRY,MAX_TRIES) \
	g_usleep((1 << MIN(TRY, MAX_TRIES)) * DELAY); \
	TRY++

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static GError * _q_run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending));

static struct oio_events_queue_vtable_s vtable_BEANSTALKD =
{
	_q_destroy, _q_send, _q_send_overwritable, _q_is_stalled, _q_run
};

/* Used by tests to intercept the result of the parsing of beanstalkd
 * replies */
typedef void (*_queue_BEANSTALKD_interceptor_f) (GError *err);

static _queue_BEANSTALKD_interceptor_f intercept_errors = NULL;

struct _queue_BEANSTALKD_s
{
	struct oio_events_queue_vtable_s *vtable;
	GAsyncQueue *queue;
	gchar *endpoint;
	gchar *tube;

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
	self->tube = g_strdup(OIO_EVT_BEANSTALKD_DEFAULT_TUBE);
	self->endpoint = g_strdup (endpoint);

	oio_events_queue_buffer_init(&self->buffer);

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}

static int
_send (int fd, struct iovec *iov, unsigned int iovcount)
{
	int w;
retry:
	w = writev (fd, iov, iovcount);
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
		GRID_WARN("BEANSTALKD failed to put: [errno=%d] %s",
				errno, strerror(errno));
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

static gboolean
_is_success(gchar *buf)
{
	return g_str_has_prefix(buf, INSERTED_PREFIX)
		|| g_str_has_prefix(buf, USING_PREFIX);
}

static GError *
_send_and_read_reply (int fd, struct iovec *iov, unsigned int iovcount)
{
	if (!_send(fd, iov, iovcount))
		return NEWERROR(CODE_NETWORK_ERROR,
				"send error: (%d) %s",
				errno, strerror(errno));

	GError *err = NULL;
	guint8 buf[256];
	int r = sock_to_read (fd, 1000, buf, sizeof(buf)-1, &err);
	if (r < 0)
		return NEWERROR(CODE_NETWORK_ERROR,
				"read error: (%d) %s", err->code, err->message);
	if (r == 0)
		return NEWERROR(CODE_NETWORK_ERROR,
				"read error: closed by peer: (%d) %s",
				errno, strerror(errno));

	buf[r+1] = 0;

	if (!_is_success((gchar*) buf))
		return NEWERROR(CODE_BAD_REQUEST, "reply error: unexpected");
	return NULL;
}

static void
_maybe_send_overwritable(struct oio_events_queue_s *self)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gboolean __send(gpointer key, gpointer msg, gpointer u UNUSED) {
		g_free(key);
		_q_send(self, (gchar*)msg);
		return TRUE;
	}

	oio_events_queue_buffer_maybe_flush(&(q->buffer), __send, NULL);
}

static GError *
_put (int fd, gchar *msg, size_t msglen)
{
	gchar buf[256];
	struct iovec iov[3];

	gsize len = g_snprintf (buf, sizeof(buf),
			"put %u %u %u %"G_GSIZE_FORMAT"\r\n",
			oio_events_beanstalkd_default_prio,
			(guint) oio_events_beanstalkd_default_delay,
			(guint) oio_events_beanstalkd_default_ttr,
			msglen);
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	iov[1].iov_base = msg;
	iov[1].iov_len = msglen;
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;

	return _send_and_read_reply (fd, iov, 3);
}

static GError *
_use_tube (int fd, const char *name)
{
	if (!oio_str_is_set(name))
		return NULL;

	gchar buf[256];
	gsize len = g_snprintf(buf, sizeof(buf), "use %s\r\n", name);

	if (len >= sizeof(buf))
		return NEWERROR(CODE_INTERNAL_ERROR, "BUG: tube name too long");

	struct iovec iov[1];
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	return _send_and_read_reply (fd, iov, 1);
}

static GError *
_poll_out (int fd)
{
	int rc = 0;
	struct pollfd pfd = {0};
	do {
		pfd.fd = fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
	} while (!(rc = metautils_syscall_poll(&pfd, 1, 1000)));
	if (pfd.revents != POLLOUT)
		return socket_get_error(fd);
	return NULL;
}

static GError *
_q_run (struct oio_events_queue_s *self, gboolean (*running) (gboolean pending))
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gchar *saved = NULL;
	int fd = -1;
	int try_count = 0;

	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	EXTRA_ASSERT (running != NULL);

	while ((*running)(0 < g_async_queue_length(q->queue))) {
		_maybe_send_overwritable(self);

		/* find an event, prefering the last that failed */
		gchar *msg = saved;
		saved = NULL;
		if (!msg) msg = g_async_queue_timeout_pop (q->queue, G_TIME_SPAN_SECOND);
		if (!msg) continue;

		/* forward the event */
		if (*msg) {
			GError *err = NULL;

			/* lazy-reconnection, with backoff sleeping to avoid crazy-looping */
			if (fd < 0) {
				fd = sock_connect(q->endpoint, &err);
				if (!err)
					err = _poll_out (fd);
				if (!err) {
					err = _use_tube (fd, q->tube);
					if (intercept_errors)
						(*intercept_errors) (err);
				}
				if (err) {
					metautils_pclose(&fd);
					GRID_WARN("BEANSTALKD: reconnection failed to %s: (%d) %s",
							q->endpoint, err->code, err->message);
					g_clear_error (&err);
					saved = msg;
					msg = NULL;

					EXPO_BACKOFF(250 * G_TIME_SPAN_MILLISECOND, try_count, 4);
					continue;
				} else {
					GRID_INFO("BEANSTALKD: connected to %s", q->endpoint);
					try_count = 0;
				}
			}

			/* prepare the header, and the buffers to be sent */
			err = _put (fd, msg, strlen(msg));
			if (intercept_errors)
				(*intercept_errors) (err);
			if (err) {
				g_clear_error (&err);
				sock_set_linger(fd, 1, 1);
				metautils_pclose (&fd);
				saved = msg;
				msg = NULL;
			}
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
	oio_str_clean (&q->tube);
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
	return ((guint)l) >= oio_events_common_max_pending;
}
