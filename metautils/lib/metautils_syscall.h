/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__metautils__lib__metautils_syscall_h
# define OIO_SDS__metautils__lib__metautils_syscall_h 1

# include <sys/types.h>

struct pollfd;
struct sockaddr;

struct metautils_syscalls_vtable_s {
	int (*open) (const char *, int, int);
	int (*shutdown) (int, int);
	int (*close) (int);
	int (*unlink) (const char *);

	int (*socket) (int, int, int);
	int (*connect) (int, const struct sockaddr *, socklen_t);
	int (*accept) (int, struct sockaddr *, socklen_t *);
	int (*accept4) (int, struct sockaddr *, socklen_t *, int);

	int (*poll) (struct pollfd *, int, int);
	ssize_t (*write) (int, const void *, size_t);
	ssize_t (*read) (int , void *, size_t);

	int (*getsockopt) (int, int, int, void *, socklen_t *);
	int (*setsockopt) (int, int, int, const void *, socklen_t);
};

void metautils_set_vtable_syscall(struct metautils_syscalls_vtable_s *vtable);
struct metautils_syscalls_vtable_s* metautils_get_vtable_syscall(void);

// Wrappers

int metautils_syscall_open (const char *, int, int);
int metautils_syscall_close (int);
int metautils_syscall_shutdown (int, int);
int metautils_syscall_unlink (const char *);
int metautils_syscall_socket (int, int, int);
int metautils_syscall_connect (int, const struct sockaddr *, socklen_t);
int metautils_syscall_accept (int, struct sockaddr *, socklen_t *);
#ifdef HAVE_ACCEPT4
int metautils_syscall_accept4 (int, struct sockaddr *, socklen_t *, int);
#endif
ssize_t metautils_syscall_write (int, const void *, size_t);
ssize_t metautils_syscall_read (int , void *, size_t);
int metautils_syscall_poll (struct pollfd *, int, int);
int metautils_syscall_getsockopt (int, int, int, void *, socklen_t *);
int metautils_syscall_setsockopt (int, int, int, const void *, socklen_t);

#endif /*OIO_SDS__metautils__lib__metautils_syscall_h*/