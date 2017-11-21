/*
OpenIO SDS event queue
Copyright (C) 2016-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <events/events_variables.h>
#include <metautils/lib/metautils_sockets.h>
#include <metautils/lib/metautils_resolv.h>
#include <metautils/lib/metautils_syscall.h>

#include "oio_events_queue.h"
#include "oio_events_queue_internals.h"
#include "oio_events_queue_beanstalkd.h"
#include "oio_events_queue_buffer.h"

#define EXPO_BACKOFF(DELAY,TRY,MAX_TRIES) \
	g_usleep((1 << MIN(TRY, MAX_TRIES)) * DELAY); \
	TRY++

#define NETERR(FMT,...) NEWERROR(CODE_NETWORK_ERROR, FMT, ##__VA_ARGS__)

static void _q_destroy (struct oio_events_queue_s *self);
static void _q_send (struct oio_events_queue_s *self, gchar *msg);
static void _q_send_overwritable(struct oio_events_queue_s *self, gchar *key, gchar *msg);
static gboolean _q_is_stalled (struct oio_events_queue_s *self);
static void _q_set_buffering (struct oio_events_queue_s *self, gint64 v);
static GError * _q_run (struct oio_events_queue_s *self,
		gboolean (*running) (gboolean pending));

static struct oio_events_queue_vtable_s vtable_BEANSTALKD =
{
	.destroy = _q_destroy,
	.send = _q_send,
	.send_overwritable = _q_send_overwritable,
	.is_stalled = _q_is_stalled,
	.set_buffering = _q_set_buffering,
	.run = _q_run
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

	oio_events_queue_buffer_init(&(self->buffer), 1 * G_TIME_SPAN_SECOND);

	*out = (struct oio_events_queue_s*) self;
	return NULL;
}

static void
_q_set_buffering(struct oio_events_queue_s *self, gint64 v)
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	if (q->buffer.delay != v) {
		GRID_INFO("events buffering delay set to %"G_GINT64_FORMAT"s",
				v / G_TIME_SPAN_SECOND);
		oio_events_queue_buffer_set_delay(&(q->buffer), v);
	}
}

static GError *
_match_common_error(gchar *buf)
{
	if (g_str_has_prefix(buf, "JOB_TOO_BIG"))
		return SYSERR("Job too big");
	if (g_str_has_prefix(buf, "OUT_OF_MEMORY"))
		return BUSY("Beanstald is OOM");
	return BADREQ("Invalid beanstalkd request/reply: %s", buf);
}

static int
_send (int fd, struct iovec *iov, unsigned int iovcount)
{
	const int timeout =
		oio_events_beanstalkd_timeout / G_TIME_SPAN_MILLISECOND;

	int w;
retry:
	w = writev (fd, iov, iovcount);
	if (w < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct pollfd pfd = {};
			pfd.fd = fd;
			pfd.events = POLLOUT;
			metautils_syscall_poll (&pfd, 1, timeout);
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

	return 1;
}

static GError *
_send_and_read_reply (int fd, struct iovec *iov, unsigned int iovcount,
		gchar *dst, gsize dst_len)
{
	const int timeout =
		oio_events_beanstalkd_timeout / G_TIME_SPAN_MILLISECOND;

	if (!_send(fd, iov, iovcount))
		return NETERR("Send error: (%d) %s", errno, strerror(errno));

	GError *err = NULL;
	int r = sock_to_read (fd, timeout, dst, dst_len - 1, &err);
	if (r < 0) {
		g_prefix_error(&err, "Read error: ");
		return err;
	}

	if (r == 0)
		return NETERR("EOF");

	dst[r] = 0;
	return NULL;
}

static GError *
_put_job (int fd, gchar *msg, size_t msglen)
{
	gchar buf[256];

	/* send the request */
	gsize len = g_snprintf (buf, sizeof(buf),
			"put %u %u %u %"G_GSIZE_FORMAT"\r\n",
			oio_events_beanstalkd_default_prio,
			(guint) oio_events_beanstalkd_default_delay,
			(guint) oio_events_beanstalkd_default_ttr,
			msglen);
	struct iovec iov[3] = {};
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	iov[1].iov_base = msg;
	iov[1].iov_len = msglen;
	iov[2].iov_base = "\r\n";
	iov[2].iov_len = 2;
	GError *err = _send_and_read_reply(fd, iov, 3, buf, sizeof(buf));
	if (err) return err;

	/* No need to retry, the event has been saved ... or explicitely
	 * dropped. */
	const char * const replies_ok[] = { "INSERTED", "BURIED", "DRAINING", NULL };
	for (const char * const *pmsg = replies_ok; *pmsg ;++pmsg) {
		if (g_str_has_prefix(buf, *pmsg))
			return NULL;
	}

	return _match_common_error(buf);
}

static GError *
_use_tube (int fd, const char *name)
{
	gchar buf[256];

	if (!oio_str_is_set(name))
		return NULL;

	/* senf the request */
	gsize len = g_snprintf(buf, sizeof(buf), "use %s\r\n", name);
	if (len >= sizeof(buf))
		return SYSERR("BUG: tube name too long");
	struct iovec iov[1] = {};
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	GError *err = _send_and_read_reply(fd, iov, 1, buf, sizeof(buf));
	if (err) return err;

	/* parse the reply */
	if (g_str_has_prefix(buf, "USING"))
		return NULL;
	return _match_common_error(buf);
}

static GError *
_check_server(int fd)
{
	gchar buf[2048];

	/* send the request */
	strcpy(buf, "stats\r\n");
	struct iovec iov[1] = {};
	iov[0].iov_base = buf;
	iov[0].iov_len = strlen(buf);
	GError *err = _send_and_read_reply(fd, iov, 1, buf, sizeof(buf));
	if (err) return err;

	/* parse the reply */
	if (!g_str_has_prefix(buf, "OK"))
		return _match_common_error(buf);

	gint64 total = 0;
	gchar **lines = g_strsplit(buf, "\n", -1);
	if (lines) {
		for (gchar **pline = lines; *pline ;++pline) {
			gchar *line = *pline;
			gint64 count = 0;
			if (!g_str_has_prefix(line, "current-jobs-"))
				continue;
			if (!(line = strchr(line, ':')))
				continue;
			if (!oio_str_is_number(g_strchug(line+1), &count))
				continue;
			total += count;
		}
		g_strfreev(lines);
	}

	const gint64 max_jobs = oio_events_beanstalkd_check_level_deny;
	if (max_jobs > 0 && total > max_jobs) {
		return BUSY("FULL (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ")", total, max_jobs);
	}

	const gint64 alert = oio_events_beanstalkd_check_level_alert;
	if (alert > 0 && total > alert) {
		GRID_WARN("Beanstalkd load alert (current=%" G_GINT64_FORMAT
				" > limit=%" G_GINT64_FORMAT ")", total, alert);
	}
	return NULL;
}

static GError *
_poll_out (int fd)
{
	const int timeout =
		oio_events_beanstalkd_timeout / G_TIME_SPAN_MILLISECOND;

	int rc = 0;
	struct pollfd pfd = {};
	do {
		pfd.fd = fd;
		pfd.events = POLLOUT;
		pfd.revents = 0;
	} while (!(rc = metautils_syscall_poll(&pfd, 1, timeout)));
	if (pfd.revents != POLLOUT)
		return socket_get_error(fd);
	return NULL;
}

static void
_flush_buffered(struct oio_events_queue_s *self, struct _queue_BEANSTALKD_s *q)
{
	gint avail =
		oio_events_common_max_pending - g_async_queue_length(q->queue);
	if (avail < (gint) oio_events_common_max_pending / 100) {
		GRID_WARN("Pending events queue is reaching maximum: %d/%d",
				g_async_queue_length(q->queue),
				oio_events_common_max_pending);
	}
	/* This is not an else clause, we want to send the buffered events
	 * (even if we do it slowly). */
	oio_events_queue_send_buffered(self, &(q->buffer), MAX(1, avail / 2));
}

static GError *
_q_run (struct oio_events_queue_s *self, gboolean (*running) (gboolean pending))
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gchar *saved = NULL;
	int fd = -1;
	guint attempts_connect = 0, attempts_check = 0, attempts_put = 0;
	gint64 last_flush = 0, last_check = 0;

	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	EXTRA_ASSERT (running != NULL);

	while ((*running)(0 < g_async_queue_length(q->queue))) {

		const gint64 now = oio_ext_monotonic_time();

		/* Maybe reconnect to the beanstalkd */
		if (fd < 0) {
			GError *err = NULL;
			fd = sock_connect(q->endpoint, &err);
			if (!err)
				err = _poll_out (fd);
			if (err) {
				g_prefix_error(&err, "Connection error: ");
			} else {
				err = _use_tube (fd, q->tube);
				if (intercept_errors)
					(*intercept_errors) (err);
				if (err)
					g_prefix_error(&err, "USE command error: ");
			}
			if (err) {
				metautils_pclose(&fd);
				GRID_WARN("BEANSTALK error to %s: (%d) %s", q->endpoint,
						err->code, err->message);
				g_clear_error (&err);

				EXPO_BACKOFF(250 * G_TIME_SPAN_MILLISECOND, attempts_connect, 4);
				continue;
			} else {
				GRID_INFO("BEANSTALKD: connected to %s", q->endpoint);
				attempts_connect = 0;
			}
		}

		/* Maybe do a periodic check of the beanstalkd tube */
		if (oio_events_beanstalkd_check_period > 0 &&
				last_check < OLDEST(now, oio_events_beanstalkd_check_period)) {
			GError *err = _check_server(fd);
			if (intercept_errors)
				(*intercept_errors) (err);
			if (err) {
				GRID_WARN("Beanstalkd error [%s]: (%d) %s", q->endpoint, err->code, err->message);
				g_clear_error(&err);
				EXPO_BACKOFF(250 * G_TIME_SPAN_MILLISECOND, attempts_check, 4);
				continue;
			} else {
				last_check = now;
				attempts_check = 0;
			}
		}

		/* Build the deadline for the timed wait */
		if (now - last_flush > q->buffer.delay / 10) {
			last_flush = now;
			_flush_buffered(self, q);
		}

		/* find an event, prefering the last that failed */
		gchar *msg = saved;
		saved = NULL;
		if (!msg) msg = g_async_queue_timeout_pop (q->queue, G_TIME_SPAN_SECOND);
		if (!msg) continue;

		/* forward the event as a beanstalkd job */
		if (*msg) {
			const size_t msglen = strlen(msg);
			GError *err = _put_job (fd, msg, msglen);
			if (intercept_errors)
				(*intercept_errors) (err);
			if (!err) {
				attempts_put = 0;
			} else {
				if (CODE_IS_RETRY(err->code) || CODE_IS_NETWORK_ERROR(err->code)) {
					saved = msg;
					msg = NULL;
					EXPO_BACKOFF(250 * G_TIME_SPAN_MILLISECOND, attempts_put, 4);
				} else {
					GRID_WARN("Unrecoverable error with beanstalkd at [%s]: (%d) %s",
							q->endpoint, err->code, err->message);
					GRID_NOTICE("dropped %d %.*s",
							(int)msglen, (int)MIN(msglen,2048), msg);
					attempts_put = 0;
				}
				g_clear_error (&err);
				sock_set_linger(fd, 1, 1);
				metautils_pclose (&fd);
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
