# include <unistd.h>
# include <string.h>
# include <fcntl.h>
# include <poll.h>
# include <sys/socket.h>

#include "metautils_syscall.h"

static struct metautils_syscalls_vtable_s VTABLE = {
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL,
	NULL, NULL,
};

void
metautils_set_vtable_syscall(struct metautils_syscalls_vtable_s *vtable)
{
#ifdef HAVE_MOCKS
	memcpy(&VTABLE, vtable, sizeof(VTABLE));
#else
	(void) vtable;
#endif
}

struct metautils_syscalls_vtable_s*
metautils_get_vtable_syscall(void)
{
	return &VTABLE;
}

int
metautils_syscall_open (const char *p, int flag, int mode)
{
#ifdef HAVE_MOCKS
	if (VTABLE.open)
		return VTABLE.open(p, flag, mode);
#endif
	return open(p, flag, mode);
}

int
metautils_syscall_unlink (const char *p)
{
#ifdef HAVE_MOCKS
	if (VTABLE.unlink)
		return VTABLE.unlink(p);
#endif
	return unlink(p);
}

int
metautils_syscall_socket (int domain, int type, int protocol)
{
#ifdef HAVE_MOCKS
	if (VTABLE.socket)
		return VTABLE.socket(domain, type, protocol);
#endif
	return socket(domain, type, protocol);
}

int
metautils_syscall_connect (int fd, const struct sockaddr *addr, socklen_t alen)
{
#ifdef HAVE_MOCKS
	if (VTABLE.connect)
		return VTABLE.connect(fd, addr, alen);
#endif
	return connect(fd, addr, alen);
}

int
metautils_syscall_accept (int fd, struct sockaddr *addr, socklen_t *alen)
{
#ifdef HAVE_MOCKS
	if (VTABLE.accept)
		return VTABLE.accept(fd, addr, alen);
#endif
	return accept(fd, addr, alen);
}

#ifdef HAVE_ACCEPT4
int
metautils_syscall_accept4 (int fd, struct sockaddr *addr, socklen_t *alen, int flags)
{
#ifdef HAVE_MOCKS
	if (VTABLE.accept4)
		return VTABLE.accept4(fd, addr, alen, flags);
#endif
	return accept4(fd, addr, alen, flags);
}
#endif

ssize_t
metautils_syscall_write (int fd, const void *buf, size_t count)
{
#ifdef HAVE_MOCKS
	if (VTABLE.write)
		return VTABLE.write(fd, buf, count);
#endif
	return write(fd, buf, count);
}

ssize_t
metautils_syscall_read (int fd, void *buf, size_t count)
{
#ifdef HAVE_MOCKS
	if (VTABLE.read)
		return VTABLE.read(fd, buf, count);
#endif
	return read(fd, buf, count);
}

int
metautils_syscall_poll (struct pollfd *fds, int nfds, int timeout)
{
#ifdef HAVE_MOCKS
	if (VTABLE.poll)
		return VTABLE.poll(fds, nfds, timeout);
#endif
	return poll(fds, nfds, timeout);
}

int
metautils_syscall_close (int fd)
{
#ifdef HAVE_MOCKS
	if (VTABLE.close)
		return VTABLE.close(fd);
#endif
	return close(fd);
}

int
metautils_syscall_shutdown (int fd, int how)
{
#ifdef HAVE_MOCKS
	if (VTABLE.shutdown)
		return VTABLE.shutdown(fd, how);
#endif
	return shutdown(fd, how);
}


int
metautils_syscall_getsockopt (int fd, int lvl, int opt, void *v, socklen_t *vl)
{
#ifdef HAVE_MOCKS
	if (VTABLE.getsockopt)
		return VTABLE.getsockopt(fd, lvl, opt, v, vl);
#endif
	return getsockopt(fd, lvl, opt, v, vl);
}

int
metautils_syscall_setsockopt (int fd, int lvl, int opt, const void *v, socklen_t vl)
{
#ifdef HAVE_MOCKS
	if (VTABLE.setsockopt)
		return VTABLE.setsockopt(fd, lvl, opt, v, vl);
#endif
	return setsockopt(fd, lvl, opt, v, vl);
}

