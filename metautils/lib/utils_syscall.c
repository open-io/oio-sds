/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
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
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <poll.h>
#include <linux/fs.h>
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/sendfile.h>

#include <core/internals.h>
#include <core/oiolog.h>

#include "metautils_syscall.h"

static struct metautils_syscalls_vtable_s VTABLE = {
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL, NULL,
	NULL, NULL, NULL,
	NULL, NULL,
};

int
metautils_syscall_unlink (const char *p)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.unlink)
		return VTABLE.unlink(p);
#endif
	return unlink(p);
}

int
metautils_syscall_socket (int domain, int type, int protocol)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.socket)
		return VTABLE.socket(domain, type, protocol);
#endif
	return socket(domain, type, protocol);
}

int
metautils_syscall_connect (int fd, const struct sockaddr *addr, socklen_t alen)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.connect)
		return VTABLE.connect(fd, addr, alen);
#endif
	return connect(fd, addr, alen);
}

int
metautils_syscall_accept (int fd, struct sockaddr *addr, socklen_t *alen)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.accept)
		return VTABLE.accept(fd, addr, alen);
#endif
	return accept(fd, addr, alen);
}

#ifdef HAVE_ACCEPT4
int
metautils_syscall_accept4 (int fd, struct sockaddr *addr, socklen_t *alen, int flags)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.accept4)
		return VTABLE.accept4(fd, addr, alen, flags);
#endif
	return accept4(fd, addr, alen, flags);
}
#endif

ssize_t
metautils_syscall_write (int fd, const void *buf, size_t count)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.write)
		return VTABLE.write(fd, buf, count);
#endif
	return write(fd, buf, count);
}

ssize_t
metautils_syscall_send (int fd, const void *buf, size_t count, int flags)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.send)
		return VTABLE.send(fd, buf, count, flags);
#endif
	return send(fd, buf, count, flags);
}

ssize_t
metautils_syscall_read (int fd, void *buf, size_t count)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.read)
		return VTABLE.read(fd, buf, count);
#endif
	return read(fd, buf, count);
}

int
metautils_syscall_poll (struct pollfd *fds, int nfds, int timeout)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.poll)
		return VTABLE.poll(fds, nfds, timeout);
#endif
	return poll(fds, nfds, timeout);
}

int
metautils_syscall_close (int fd)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.close)
		return VTABLE.close(fd);
#endif
	return close(fd);
}

int
metautils_syscall_getsockopt (int fd, int lvl, int opt, void *v, socklen_t *vl)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.getsockopt)
		return VTABLE.getsockopt(fd, lvl, opt, v, vl);
#endif
	return getsockopt(fd, lvl, opt, v, vl);
}

int
metautils_syscall_setsockopt (int fd, int lvl, int opt, const void *v, socklen_t vl)
{
#ifdef HAVE_EXTRA_DEBUG
	if (VTABLE.setsockopt)
		return VTABLE.setsockopt(fd, lvl, opt, v, vl);
#endif
	return setsockopt(fd, lvl, opt, v, vl);
}

guint
metautils_syscall_count_maxfd (void)
{
	struct rlimit limit = {0, 0};
	if (0 == getrlimit(RLIMIT_NOFILE, &limit))
		return MAX(1024,limit.rlim_cur);
	return 1024;
}

GError*
metautils_syscall_copy_file(gchar *src, gchar *dst)
{
	EXTRA_ASSERT(src != NULL);
	EXTRA_ASSERT(dst != NULL);

	GError *err = NULL;
	int src_fd = 0, dest_fd = 0;
	struct stat stat_buf = {0};

	src_fd = open(src, O_RDONLY);
	if (src_fd < 0) {
		err = NEWERROR(errno, "Failed to open source: %s", strerror(errno));
		goto end;
	}
	if (fstat(src_fd, &stat_buf) < 0) {
		err = NEWERROR(errno, "Failed to fetch source stats: %s",
				strerror(errno));
		goto end;
	}
	dest_fd = open(dst, O_WRONLY|O_CREAT|O_EXCL, stat_buf.st_mode);
	if (dest_fd < 0) {
		err = NEWERROR(errno, "Failed to open destination: %s",
				strerror(errno));
		goto end;
	}

	GRID_DEBUG("Copying base %s to %s with reflink", src, dst);
	gint rc = ioctl(dest_fd, FICLONE, src_fd);
	if (rc != 0) {
		if (errno == EOPNOTSUPP) {
			GRID_WARN("Reflink is not enabled, "
					"copying base %s to %s without reflink", src, dst);

			off_t offset = 0;
			while (offset < stat_buf.st_size) {
				if (sendfile(dest_fd, src_fd, &offset,
						stat_buf.st_size - offset) >= 0) {
					continue;
				}
				if (errno == EAGAIN || errno == EINTR) {
					continue;
				}
				err = NEWERROR(errno, "Failed to send file: %s",
						strerror(errno));
				goto end;
			}
		} else {
			err = NEWERROR(errno, "Failed to share data: %s",
					strerror(errno));
			goto end;
		}
	}
end:
	if (src_fd)
		close(src_fd);
	if (dest_fd)
		close(dest_fd);
	return err;
}
