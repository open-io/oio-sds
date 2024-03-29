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

#ifndef OIO_SDS__metautils__lib__metautils_sockets_h
# define OIO_SDS__metautils__lib__metautils_sockets_h 1

# include <glib.h>

struct metautils_sockets_vtable_s
{
	gint (*to_write) (int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	gint (*to_read) (int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	gint (*to_read_size)(int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	int (*socket_nonblock) (int domain, int type, int protocol);
	int (*accept_nonblock) (int srv, struct sockaddr *sa, socklen_t *sa_len);
	gint (*get_error) (int fd);
	gboolean (*set_non_blocking) (int fd, gboolean enabled);
	gboolean (*set_tcpquickack) (int fd, gboolean enabled);
	gboolean (*set_reuseaddr) (int fd, gboolean enabled);
	gboolean (*set_reuseport) (int fd, gboolean enabled);
	gboolean (*set_keepalive) (int fd, gboolean enabled);
	gboolean (*set_nodelay) (int fd, gboolean enabled);
	gboolean (*set_cork) (int fd, gboolean enabled);
	gboolean (*set_linger) (int fd, int onoff, int linger);
};

extern gboolean oio_allow_tcp_fastopen;

/**
 * Read bytes from the socket file descriptor, spending at most a given
 * number of milli seconds.
 *
 * This function manages the case if the socket is blocking or not. If
 * fd is a blocking socket, there is n quranty that the sending will
 * be time-bounded.
 *
 * &@param fd an opened and connected socket file descriptor
 * @param ms the maximum latency
 * @param buf a pointer to the buffer to be filled withread data.
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 *
 * @return the positive number of bytes read, or 0 in case of time-out,
 *         or -1 in case of error (an err is set).
 */
gint sock_to_read(int fd, gint ms, void *buf, gsize bufSize, GError ** err);

/* Use this instead of socket() + sock_set_non_blocking() because it attempts to
 * optimize the syscalls made, depending on your kernel/sysc/compile options. */
int socket_nonblock(int domain, int type, int protocol);

/* Use this instead of accept() + sock_set_non_blocking() because it attempts to
 * optimize the syscalls made, depending on your kernel/sysc/compile options. */
int accept_nonblock(int srv, struct sockaddr *sa, socklen_t *sa_len);

/* Performs the getsockopt() call to retrieve error associated with 'fd' */
gint socket_get_errcode(int fd);

/* @see socket_get_errcode() */
GError* socket_get_error(int fd);

gboolean sock_set_non_blocking(int fd, gboolean enabled);

gboolean sock_set_tcpquickack(int fd, gboolean enabled);

gboolean sock_set_reuseaddr(int fd, gboolean enabled);

/* Enable (or disable) the SO_REUSEPORT option on the specified socket */
gboolean sock_set_reuseport(int fd, gboolean enabled);

gboolean sock_set_nodelay(int fd, gboolean enabled);

/* Enable (or disable) the close-on-exec flag on the specified socket */
gboolean sock_set_cloexec(int fd, gboolean enabled);

gboolean sock_set_cork(int fd, gboolean enabled);

gboolean sock_set_fastopen(int fd);

gboolean sock_set_linger(int fd, int onoff, int linger);

gboolean sock_set_linger_default(int fd);

/* Set the default socket options for low latencies client operations. */
void sock_set_client_default(int fd);

/* Closes the file descriptor pointed by 'pfd' then sets it to -1.
 * @return the result of close() or -1 in case of error. */
int metautils_pclose(int *pfd);

int sock_build_for_url(const char *url, GError **err,
		struct sockaddr_storage *sas, size_t *sas_len);

/* Opens a non-blocking TCP socket then connect it to 'url' before returning
 * it. 'err' is optional. */
int sock_connect (const char *url, GError **err);

/* Opens a non-blocking TCP socket and attempts to benefit the TCP_FASTOPEN
 * mechanism. The regular sock_connect() is used if that fast-open option is
 * not supported or if there is no data to be sen. */
int sock_connect_and_send (const char *url, GError **err,
		const uint8_t *buf, gsize *len);

#endif /*OIO_SDS__metautils__lib__metautils_sockets_h*/
