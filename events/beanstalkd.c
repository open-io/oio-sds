/*
OpenIO SDS event queue
Copyright (C) 2021 OVH SAS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <core/internals.h>
#include <core/oio_core.h>
#include <events/events_variables.h>
#include <metautils/lib/metautils_resolv.h>
#include <metautils/lib/metautils_sockets.h>
#include <metautils/lib/metautils_syscall.h>

#include "beanstalkd.h"

#define NETERR(FMT,...) NEWERROR(CODE_NETWORK_ERROR, FMT, ##__VA_ARGS__)

GError *
beanstalkd_factory(const gchar *endpoint, const gchar *tube,
		struct beanstalkd_s **out)
{
	EXTRA_ASSERT(endpoint != NULL);
	EXTRA_ASSERT(tube != NULL);
	EXTRA_ASSERT(out != NULL);
	*out = NULL;

	if (g_str_has_prefix(endpoint, BEANSTALKD_PREFIX))
		endpoint = endpoint + strlen(BEANSTALKD_PREFIX);

	if (!metautils_url_valid_for_connect(endpoint))
		return BADREQ("Invalid beanstalkd endpoint [%s]", endpoint);

	struct beanstalkd_s *beanstalkd = g_malloc0(sizeof(struct beanstalkd_s));
	beanstalkd->endpoint = g_strdup(endpoint);
	beanstalkd->tube = g_strdup(tube);
	beanstalkd->fd = -1;

	*out = beanstalkd;
	return NULL;
}

static GError *
_poll_out(int fd)
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
_send(int fd, struct iovec *iov, unsigned int iovcount)
{
	const int timeout =
		oio_events_beanstalkd_timeout / G_TIME_SPAN_MILLISECOND;

	int w;
retry:
	w = writev(fd, iov, iovcount);
	if (w < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			struct pollfd pfd = {};
			pfd.fd = fd;
			pfd.events = POLLOUT;
			metautils_syscall_poll(&pfd, 1, timeout);
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
_send_and_read_reply(int fd, struct iovec *iov, unsigned int iovcount,
		gchar *dst, gsize dst_len)
{
	const int timeout =
		oio_events_beanstalkd_timeout / G_TIME_SPAN_MILLISECOND;

	if (!_send(fd, iov, iovcount))
		return NETERR("Send error: (%d) %s", errno, strerror(errno));

	GError *err = NULL;
	int r = sock_to_read(fd, timeout, dst, dst_len - 1, &err);
	if (r < 0) {
		g_prefix_error(&err, "Read error: ");
		return err;
	}

	if (r == 0)
		return NETERR("EOF");

	dst[r] = 0;
	return NULL;
}

GError *
beanstalkd_reconnect(struct beanstalkd_s *beanstalkd)
{
	EXTRA_ASSERT(beanstalkd != NULL);

	GError *err = NULL;

	if (beanstalkd->fd >= 0)
		return err;

	/* Try to reconnect and reconfigure the tube */
	beanstalkd->fd = sock_connect(beanstalkd->endpoint, &err);
	if (!err)
		err = _poll_out(beanstalkd->fd);
	if (err) {
		g_prefix_error(&err, "Connection error: ");
	} else {
		err = beanstalkd_use_tube(beanstalkd, NULL);
		if (err)
			g_prefix_error(&err, "USE command error: ");
	}

	if (err) {
		metautils_pclose(&(beanstalkd->fd));
		GRID_WARN("Beanstalkd error with [%s] using tube [%s]: (%d) %s",
				beanstalkd->endpoint, beanstalkd->tube, err->code,
				err->message);
	} else {
		GRID_INFO("Beanstalkd connected to [%s] using tube [%s]",
				beanstalkd->endpoint, beanstalkd->tube);
	}

	return err;
}

GError *
beanstalkd_use_tube(struct beanstalkd_s *beanstalkd, const gchar *tube)
{
	EXTRA_ASSERT(beanstalkd != NULL);

	GError *err = NULL;
	gchar buf[256];

	if (oio_str_is_set(tube))
		oio_str_replace(&(beanstalkd->tube), tube);

	if ((err = beanstalkd_reconnect(beanstalkd))) {
		g_prefix_error(&err, "Reconnect error: ");
		return err;
	}

	/* senf the request */
	gsize len = g_snprintf(buf, sizeof(buf), "use %s\r\n", beanstalkd->tube);
	if (len >= sizeof(buf)) {
		err = SYSERR("BUG: tube name too long");
		return err;
	}
	struct iovec iov[1] = {};
	iov[0].iov_base = buf;
	iov[0].iov_len = len;
	err = _send_and_read_reply(beanstalkd->fd, iov, 1, buf, sizeof(buf));
	if (err)
		return err;

	/* parse the reply */
	if (g_str_has_prefix(buf, "USING"))
		return NULL;
	return _match_common_error(buf);
}

GError *
beanstalkd_put_job(struct beanstalkd_s *beanstalkd, void *msg, size_t msglen)
{
	EXTRA_ASSERT(beanstalkd != NULL);

	GError *err = NULL;
	gchar buf[256];

	if (!msg || !msglen)
		return err;

	if ((err = beanstalkd_reconnect(beanstalkd))) {
		g_prefix_error(&err, "Reconnect error: ");
		return err;
	}

	/* send the request */
	gsize len = g_snprintf(buf, sizeof(buf),
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
	err = _send_and_read_reply(beanstalkd->fd, iov, 3, buf, sizeof(buf));
	if (err) {
		goto exit;
	}

	/* No need to retry, the event has been saved ... or explicitely
	 * dropped. */
	const gchar * const replies_ok[] = { "INSERTED", "BURIED", "DRAINING",
			NULL };
	for (const gchar * const *pmsg = replies_ok; *pmsg ;++pmsg) {
		if (g_str_has_prefix(buf, *pmsg))
			return NULL;
	}

	err = _match_common_error(buf);
exit:
	if (err) {
		sock_set_linger(beanstalkd->fd, 1, 1);
		metautils_pclose(&(beanstalkd->fd));
	}
	return err;
}

GError *
beanstalkd_get_stats(struct beanstalkd_s *beanstalkd, gchar ***out)
{
	EXTRA_ASSERT(beanstalkd != NULL);
	EXTRA_ASSERT(out != NULL);

	GError *err = NULL;
	gchar buf[2048];

	if ((err = beanstalkd_reconnect(beanstalkd))) {
		g_prefix_error(&err, "Reconnect error: ");
		return err;
	}

	/* send the request */
	g_strlcpy(buf, "stats\r\n", sizeof(buf));
	struct iovec iov[1] = {};
	iov[0].iov_base = buf;
	iov[0].iov_len = strlen(buf);
	err = _send_and_read_reply(beanstalkd->fd, iov, 1, buf, sizeof(buf));
	if (err) {
		goto exit;
	}

	/* parse the reply */
	if (g_str_has_prefix(buf, "OK"))
		*out = g_strsplit(buf, "\n", -1);
	else
		err = _match_common_error(buf);
exit:
	if (err) {
		sock_set_linger(beanstalkd->fd, 1, 1);
		metautils_pclose(&(beanstalkd->fd));
	}
	return err;
}

void
beanstalkd_destroy(struct beanstalkd_s *beanstalkd)
{
	if (!beanstalkd)
		return;

	oio_str_clean(&(beanstalkd->endpoint));
	oio_str_clean(&(beanstalkd->tube));
	if (beanstalkd->fd >= 0) {
		sock_set_linger(beanstalkd->fd, 1, 1);
		metautils_pclose(&(beanstalkd->fd));
	}
	beanstalkd->fd = -1;
	g_free(beanstalkd);
}
