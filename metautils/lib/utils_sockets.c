/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2022 OVH SAS

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
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#include "metautils.h"
#include "metautils_syscall.h"

#include <metautils/lib/common_variables.h>

static gint
errno_to_errcode(int e)
{
	switch (e) {
		case 0:
			return 0;

		case EINVAL:
			return ERRCODE_PARAM;

		case ECONNRESET:
			return ERRCODE_CONN_RESET;
		case ECONNREFUSED:
		case EHOSTDOWN:
			return ERRCODE_CONN_REFUSED;
		case EHOSTUNREACH:
			return ERRCODE_CONN_NOROUTE;

		default:
			/* generic network error */
			return CODE_NETWORK_ERROR;
	}
}

static struct metautils_sockets_vtable_s VTABLE = {
	NULL, NULL, NULL,
	NULL, NULL,
	NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

int
socket_nonblock(int domain, int type, int protocol)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.socket_nonblock)
		return VTABLE.socket_nonblock(domain, type, protocol);
#endif
#ifdef HAVE_SOCKET3
	return metautils_syscall_socket(domain, type|SOCK_NONBLOCK, protocol);
#else
	int fd = metautils_syscall_socket(domain, type, protocol);
	if (fd < 0)
		return fd;
	if (sock_set_non_blocking(fd, TRUE))
		return fd;
	metautils_pclose(&fd);
	return -1;
#endif
}

int
accept_nonblock(int srv, struct sockaddr *sa, socklen_t *sa_len)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.accept_nonblock)
		return VTABLE.accept_nonblock(srv, sa, sa_len);
#endif
#ifdef HAVE_ACCEPT4
	return metautils_syscall_accept4(srv, sa, sa_len, SOCK_NONBLOCK);
#else
	int fd = metautils_syscall_accept(srv, sa, sa_len);
	if (fd >= 0)
		sock_set_non_blocking(fd, TRUE);
	return fd;
#endif
}

gint
sock_to_read(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.to_read)
		return VTABLE.to_read(fd, ms, buf, bufSize, err);
#endif

#define READ() do { \
		rc = metautils_syscall_read(fd, buf, bufSize); \
		if (rc > 0) \
			return rc; \
		if (rc == 0) { \
			GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d closed", fd); \
			return 0; \
		} \
		if (errno != EAGAIN && errno != EINTR) { \
			GSETCODE(err, errno_to_errcode(errno), "Read error (%s)", strerror(errno)); \
			return -1; \
		} \
	} while (0)

	gint rc;

	if (fd < 0 || !buf || bufSize <= 0) {
		GSETERROR(err, "invalid parameter");
		return -1;
	}

	/* on tente un premier READ, qui s'il reussit, nous epargne un appel a POLL */
	READ();

	/* pas de data en attente, donc attente protegee par le poll */
	for (;;) {
		struct pollfd p;

		p.fd = fd;
		p.events = POLLIN;
		p.revents = 0;

		/*wait for something to happen */
		rc = metautils_syscall_poll(&p, 1, ms);
		if (rc == 0) {	/*timeout */
			GSETCODE(err, ERRCODE_CONN_TIMEOUT, "Socket timeout");
			return -1;
		}

		if (rc < 0 && errno != EINTR) {	/*error */
			GSETCODE(err, errno_to_errcode(errno), "Socket error (%s)", strerror(errno));
			return -1;
		}
		if (rc == 1) {
			if (p.revents & POLLHUP && !(p.revents & POLLIN)) {
				GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d closed", fd);
				return 0;
			}
			if (p.revents & POLLERR) {
				int sock_err = socket_get_errcode(fd);
				GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d error : (%d) %s", fd, sock_err, strerror(sock_err));
				return 0;
			}
			READ();
		}
	}
}

/* ------------------------------------------------------------------------- */

gint
socket_get_errcode(int fd)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.get_error)
		return VTABLE.get_error(fd);
#endif

	int rc, sock_err = 0;
	socklen_t sock_err_size = sizeof(sock_err);

	if (fd < 0)
		return EINVAL;

	rc = metautils_syscall_getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sock_err_size);
	return (0 != rc) ? -1 : sock_err;
}

GError *
socket_get_error(int fd)
{
	int sock_err = socket_get_errcode(fd);
	return NEWERROR(errno_to_errcode(sock_err), "[errno=%d] %s",
			sock_err, strerror(sock_err));
}

gboolean
sock_set_tcpquickack(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_tcpquickack)
		return VTABLE.set_tcpquickack(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, IPPROTO_TCP, TCP_QUICKACK, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(TCP_QUICKACK,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_non_blocking(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_non_blocking)
		return VTABLE.set_non_blocking(fd, enabled);
#endif

	if (fd < 0) {
		errno = EAGAIN;
		return FALSE;
	}

	int flags = fcntl(fd, F_GETFL);
	flags = enabled ? flags|O_NONBLOCK : flags&(~O_NONBLOCK);

	if (!fcntl(fd, F_SETFL, flags))
		return TRUE;

	GRID_DEBUG("fd=%i set(O_NONBLOCK,%d): (%d) %s",
			fd, enabled, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_reuseaddr(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_reuseaddr)
		return VTABLE.set_reuseaddr(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(SO_REUSEADDR,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_reuseport(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_reuseport)
		return VTABLE.set_reuseport(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_REUSEPORT,
			(void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(SO_REUSEPORT,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_nodelay(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_nodelay)
		return VTABLE.set_nodelay(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(TCP_NODELAY,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_cloexec(int fd, gboolean enabled)
{
	int res = fcntl(fd, F_SETFD, enabled? FD_CLOEXEC : 0);

	GRID_DEBUG("fd=%i set(FD_CLOEXEC,%d): (%d) %s",
			fd, enabled, errno, strerror(errno));
	return res == 0;
}

gboolean
sock_set_cork(int fd, gboolean enabled)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_cork)
		return VTABLE.set_cork(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, IPPROTO_TCP, TCP_CORK, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(TCP_CORK,%d): (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_fastopen(int fd)
{
	int syndata_backlog = 16;
	int rc = metautils_syscall_setsockopt(fd, SOL_TCP, TCP_FASTOPEN,
			&syndata_backlog, sizeof(syndata_backlog));
	if (!rc)
		return TRUE;

	GRID_DEBUG("fd=%i set(TCP_FASTOPEN,%d): (%d) %s",
			fd, syndata_backlog, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_linger(int fd, int onoff, int linger)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.set_linger)
		return VTABLE.set_linger(fd, onoff, linger);
#endif

	struct linger ls;
	ls.l_onoff = BOOL(onoff);
	ls.l_linger = linger;

	if (!metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_LINGER, (void*)&ls, sizeof(ls)))
		return TRUE;
	GRID_WARN("fd=%i set(SO_LINGER,%d,%d): (%d) %s",
			fd, onoff, linger, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_linger_default(int fd)
{
	return sock_set_linger(fd,
			oio_socket_linger_onoff, oio_socket_linger_delay);
}

void
sock_set_client_default(int fd)
{
	sock_set_reuseaddr(fd, TRUE);
	sock_set_linger_default(fd);
	sock_set_nodelay(fd, oio_socket_quickack);
	sock_set_tcpquickack(fd, oio_socket_nodelay);
	sock_set_cloexec(fd, TRUE);
}

int
metautils_pclose(int *pfd)
{
	if (unlikely(pfd == NULL)) {
		errno = EAGAIN;
		return -1;
	}
	if (*pfd < 0) {
		errno = EINVAL;
		return -1;
	}

	errno = 0;
	int rc = metautils_syscall_close(*pfd);
	*pfd = -1;
	return rc;
}

int
sock_build_for_url(const char *url, GError **err,
		struct sockaddr_storage *sas, size_t *sas_len)
{
	*sas_len = sizeof(*sas);

	if (!grid_string_to_sockaddr (url, (struct sockaddr*) sas, sas_len)) {
		g_error_transmit(err, NEWERROR(EINVAL, "invalid URL"));
		return -1;
	}

	int fd = socket_nonblock(sas->ss_family, SOCK_STREAM, 0);
	if (0 > fd) {
		g_error_transmit(err, NEWERROR(EINVAL, "socket error: (%d) %s", errno, strerror(errno)));
		return -1;
	}

	sock_set_client_default(fd);
	*err = NULL;
	return fd;
}

int
sock_connect (const char *url, GError **err)
{
	gsize sas_len = 0;
	struct sockaddr_storage sas;
	int fd = sock_build_for_url(url, err, &sas, &sas_len);
	if (fd < 0)
		return -1;

	if (0 != metautils_syscall_connect (fd, (struct sockaddr*)&sas, sas_len)) {
		if (errno != EINPROGRESS && errno != 0) {
			g_error_transmit(err, NEWERROR(EINVAL, "connect error: (%d) %s", errno, strerror(errno)));
			metautils_pclose (&fd);
			return -1;
		}
	}

	sock_set_client_default(fd);
	*err = NULL;
	return fd;
}

/* Set buffer sizes for small RPC */
static void
sock_setopt_buflen(int fd)
{
	int rc, opt;

	if (oio_socket_gridd_sndbuf > 0) {
		opt = oio_socket_gridd_sndbuf;
		rc = metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &opt, sizeof(opt));
		(void) rc;
	}

	if (oio_socket_gridd_rcvbuf > 0) {
		opt = oio_socket_gridd_rcvbuf;
		rc = metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt));
		(void) rc;
	}
}

static volatile gint64 _fastopen_last_error = 0;

gboolean oio_allow_tcp_fastopen = FALSE;

int
sock_connect_and_send (const char *url, GError **err,
		const uint8_t *buf, gsize *len)
{
	gsize sas_len = 0;
	struct sockaddr_storage sas;
	int fd = sock_build_for_url(url, err, &sas, &sas_len);
	if (fd < 0)
		return -1;

	sock_setopt_buflen(fd);

#if defined(MSG_FASTOPEN) && defined(TCP_FASTOPEN)

	const gint64 now = oio_ext_monotonic_time();

	if (!oio_allow_tcp_fastopen || !buf || !len ||
			(_fastopen_last_error != 0 &&
			 _fastopen_last_error > OLDEST(now,G_TIME_SPAN_MINUTE)))
		goto label_simple_connect;

#ifdef HAVE_ENBUG
	if (*len > 1)
		*len = *len / 2;
#endif

	ssize_t rc;
retry:
	rc = sendto(fd, buf, *len,
			MSG_FASTOPEN|MSG_NOSIGNAL, (struct sockaddr*) &sas, sas_len);
	if (rc < 0) {
		if (errno == EINTR)
			goto retry;
		if (errno == ENOTSUP || errno == EOPNOTSUPP) {
			/* the TCP_FASTOPEN is not accepted, let's continue with a
			 * regular connect/send sequence */
			_fastopen_last_error = now;
label_simple_connect:
#endif
			*len = 0;
			if (0 != metautils_syscall_connect (fd, (struct sockaddr*)&sas, sas_len)) {
				if (errno != EINPROGRESS && errno != 0) {
					g_error_transmit(err,
							SYSERR("connect error: (%d) %s", errno, strerror(errno)));
					metautils_pclose (&fd);
					return -1;
				}
			}
			*err = NULL;
			return fd;
#if defined(MSG_FASTOPEN) && defined(TCP_FASTOPEN)
		} else if (errno == EINPROGRESS) {
			/* syn-cookie not ready, so the kernel will proceed internally with
			 * traditional connect() SYN-SYN/ACK-ACK sequence */
			*len = 0;
			*err = NULL;
			return fd;
		} else {
			g_error_transmit(err, NEWERROR(CODE_NETWORK_ERROR,
						"connect error: (%d) %s", errno, strerror(errno)));
			metautils_pclose (&fd);
			return -1;
		}
	} else {
		/* syn-cookie ready, the number of bytes packed in the SYN-cookie is
		 * returned. */
		*len = rc;
		*err = NULL;
		return fd;
	}
#endif
}
