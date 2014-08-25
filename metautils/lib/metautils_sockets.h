#ifndef __REDCURRANT__metautils_sockets__h
# define __REDCURRANT__metautils_sockets__h 1
# include <glib.h>

/**
 * @defgroup metautils_sockets Sockets utilities
 * @ingroup metautils_utils
 * @{
 */

struct metautils_sockets_vtable_s {
	gint (*to_write) (int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	gint (*to_read) (int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	gint (*to_read_size)(int fd, gint ms, void *buf, gsize bufSize, GError ** err);
	int (*socket_nonblock) (int domain, int type, int protocol);
	int (*accept_nonblock) (int srv, struct sockaddr *sa, socklen_t *sa_len);
	gint (*get_error) (int fd);
	gboolean (*set_non_blocking) (int fd, gboolean enabled);
	gboolean (*set_tcpquickack) (int fd, gboolean enabled);
	gboolean (*set_reuseaddr) (int fd, gboolean enabled);
	gboolean (*set_keepalive) (int fd, gboolean enabled);
	gboolean (*set_nodelay) (int fd, gboolean enabled);
	gboolean (*set_cork) (int fd, gboolean enabled);
	gboolean (*set_linger) (int fd, int onoff, int linger);
};

void metautils_set_vtable_sockets(struct metautils_sockets_vtable_s *vtable);
struct metautils_sockets_vtable_s* metautils_get_vtable_sockets(void);

/**
 * Writes data in a file descriptor with a given maximum amount of time
 * spent in network latencies.
 *
 * This function manages the case if the socket is blocking or not. If
 * fd is a blocking socket, there is n quranty that the sending will
 * be time-bounded.
 *
 * @param fd an opened and connected socket file descriptor
 * @param ms the maximum latency
 * @param buf a pointer to the buffer to be sent
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 *
 * @return the number of bytes spent in case of success, -1 if an
 *         error occured.
 */
gint sock_to_write(int fd, gint ms, void *buf, gsize bufSize, GError ** err);


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


/**
 * Reads exactly 'bufSize' bytes during at most 'ms' milliseconds
 * and fills the given buffer with the data.
 *
 * @param fd an opened and connected socket 
 * @param ms the maximum latency of the operation
 * @param buf a pointer to the buffer to be filled withread data.
 * @param bufSize the size of the buffer
 * @param err an error structure set in case of error
 * @return
 */
gint sock_to_read_size(int fd, gint ms, void *buf, gsize bufSize, GError ** err);

// Use this instead of socket() + sock_set_non_blocking() because it attempts to
// optimize the syscalls made, depending on your kernel/sysc/compile options.
int socket_nonblock(int domain, int type, int protocol);

// Use this instead of accept() + sock_set_non_blocking() because it attempts to
// optimize the syscalls made, depending on your kernel/sysc/compile options.
int accept_nonblock(int srv, struct sockaddr *sa, socklen_t *sa_len);

/**
 * Performs the getsockopt() call to retrieve error associated with the socket 'fd'.
 *
 * @param fd a valid socket
 * @return a errno code
 */
gint socket_get_errcode(int fd);

GError* socket_get_error(int fd);

/**
 * Set non blocking 
 *
 * @param fd the socket file desciptor to be altered 
 * @param err an error structure set in case of error
 * @return 1 in case of success, 0 in case of error.
 */
gboolean sock_set_non_blocking(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 */
gboolean sock_set_tcpquickack(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_reuseaddr(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_keepalive(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_nodelay(int fd, gboolean enabled);

/**
 * @param fd
 * @param enabled
 * @return
 */
gboolean sock_set_cork(int fd, gboolean enabled);

/**
 * @param fd
 * @param onoff
 * @param linger
 * @return
 */
gboolean sock_set_linger(int fd, int onoff, int linger);

gboolean sock_set_linger_default(int fd);

/**
 * Set the default socket options for low latencies client operations.
 */
void sock_set_client_default(int fd);

/** Closes the file descriptor pointed by 'pfd' then sets it to -1.
 * @return the result of close() or -1 in case of error. */
int metautils_pclose(int *pfd);

/** @} */

#endif // __REDCURRANT__metautils_sockets__h
