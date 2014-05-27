#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils"
#endif

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <netdb.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/tcp.h>

#include "metautils.h"
#include "metautils_syscall.h"
#include "metautils_internals.h"

#ifndef SOCK_DEFAULT_LINGER_ONOFF
# define SOCK_DEFAULT_LINGER_ONOFF 1
#endif

#ifndef SOCK_DEFAULT_LINGER_DELAY
# define SOCK_DEFAULT_LINGER_DELAY 0
#endif

static struct metautils_sockets_vtable_s VTABLE = {
	NULL, NULL, NULL,
	NULL, NULL,
	NULL,
	NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

void
metautils_set_vtable_sockets(struct metautils_sockets_vtable_s *vtable)
{
#ifdef HAVE_MOCKS
	memcpy(&VTABLE, vtable, sizeof(VTABLE));
#else
	(void) vtable;
#endif
}

struct metautils_sockets_vtable_s*
metautils_get_vtable_sockets(void)
{
	return &VTABLE;
}

int
socket_nonblock(int domain, int type, int protocol)
{
#ifdef HAVE_MOCKS
	if (VTABLE.socket_nonblock)
		return VTABLE.socket_nonblock(domain, type, protocol);
#endif
#ifdef HAVE_SOCKET3
	return metautils_syscall_socket(domain, type|SOCK_NONBLOCK, protocol);
#else
	int fd = metautils_syscall_socket(domain, type, protocol);
	if (fd < 0)
		return fd;
	if (0 == sock_set_non_blocking(fd, TRUE))
		return fd;
	metautils_pclose(&fd);
	return -1;
#endif
}

int
accept_nonblock(int srv, struct sockaddr *sa, socklen_t *sa_len)
{
#ifdef HAVE_MOCKS
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
sock_to_write(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#ifdef HAVE_MOCKS
	if (VTABLE.to_write)
		return VTABLE.to_write(fd, ms, buf, bufSize, err);
#endif

#define WRITE() do { \
		written = metautils_syscall_write(fd, ((guint8 *)buf) + nbSent, bufSize - nbSent); \
		if (written > 0) { \
			ui_written = written; \
			nbSent += ui_written; \
		} \
		if (written < 0) { \
			if (errno != EAGAIN && errno != EINTR) { \
				GSETERROR(err, "Write error (%s)", strerror(errno)); \
				return -1; \
			} \
		} \
} while (0)

	gsize ui_written;
	ssize_t written;
	gsize nbSent = 0;

	if (fd < 0 || !buf || bufSize <= 0) {
		GSETERROR(err, "invalid parameter");
		return -1;
	}

	WRITE();

	while (nbSent < bufSize) {
		int rc_poll;
		struct pollfd p;

		p.fd = fd;
		p.events = POLLOUT | POLLERR | POLLHUP | POLLNVAL;
		p.revents = 0;

		errno = 0;
		rc_poll = metautils_syscall_poll(&p, 1, ms);

		if (rc_poll == 0) {	/*timeout */
			GSETCODE(err, ERRCODE_CONN_TIMEOUT, "Socket timeout");
			return (-1);
		}

		if (rc_poll == -1) {	/*poll error */
			if (errno != EINTR) {
				GSETERROR(err, "Socket error (%s) after %i bytes written", strerror(errno), nbSent);
				return (-1);
			}
			else {
				TRACE("poll interrupted (%s)", strerror(errno));
				continue;
			}
		}

		/*poll success */
		if (p.revents & POLLNVAL) {
			GSETERROR(err, "Socket (%d) is invalid after %i bytes sent", fd, nbSent);
			return -1;
		}
		if (p.revents & POLLERR) {
			int sock_err = sock_get_error(fd);
			GSETERROR(err, "Socket (%d) error after %i bytes written : (%d) %s", fd, nbSent, sock_err, strerror(sock_err));
			return -1;
		}
		if ((p.revents & POLLHUP)) {
			GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket (%d) closed after %i bytes written", fd, nbSent);
			return -1;
		}

		WRITE();
	}

	return nbSent;
}

gint
sock_to_read(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#ifdef HAVE_MOCKS
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
				int sock_err = sock_get_error(fd);
				GSETCODE(err, ERRCODE_CONN_CLOSED, "Socket %d error : (%d) %s", fd, sock_err, strerror(sock_err));
				return 0;
			}
			READ();
		}
	}
}

gint
sock_to_read_size(int fd, gint ms, void *buf, gsize bufSize, GError ** err)
{
#ifdef HAVE_MOCKS
	if (VTABLE.to_read_size)
		return VTABLE.to_read_size(fd, ms, buf, bufSize, err);
#endif

	gsize nbRead = 0;

	while (nbRead < bufSize) {
		int n = sock_to_read(fd, ms, ((guint8 *) buf) + nbRead, bufSize - nbRead, err);
		if (n < 0) {
			GSETERROR(err, "Read failed after %i bytes", nbRead);
			return n;
		}
		else if (n == 0) {
			GSETERROR(err, "Socket closed after %i bytes read", nbRead);
			return n;
		}
		else
			nbRead += n;
	}
	return nbRead;
}

/* ------------------------------------------------------------------------- */

gint
sock_get_error(int fd)
{
#ifdef HAVE_MOCKS
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

gboolean
sock_set_tcpquickack(int fd, gboolean enabled)
{
#ifdef HAVE_MOCKS
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
#ifdef HAVE_MOCKS
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
#ifdef HAVE_MOCKS
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
sock_set_keepalive(int fd, gboolean enabled)
{
#ifdef HAVE_MOCKS
	if (VTABLE.set_keepalive)
		return VTABLE.set_keepalive(fd, enabled);
#endif

	int opt = BOOL(enabled);
	if (!metautils_syscall_setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void*)&opt, sizeof(opt)))
		return TRUE;
	GRID_DEBUG("fd=%i set(SO_KEEPALIVE,%d) : (%d) %s",
			fd, opt, errno, strerror(errno));
	return FALSE;
}

gboolean
sock_set_nodelay(int fd, gboolean enabled)
{
#ifdef HAVE_MOCKS
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
sock_set_cork(int fd, gboolean enabled)
{
#ifdef HAVE_MOCKS
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
sock_set_linger(int fd, int onoff, int linger)
{
#ifdef HAVE_MOCKS
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
	return sock_set_linger(fd, SOCK_DEFAULT_LINGER_ONOFF,
			SOCK_DEFAULT_LINGER_DELAY);
}

void
sock_set_client_default(int fd)
{
	sock_set_linger_default(fd);
	sock_set_nodelay(fd, TRUE);
	sock_set_tcpquickack(fd, TRUE);
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

