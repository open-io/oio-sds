/**
 * @file grid_daemon.h
 */

#ifndef GRID__GRID_DAEMON_H
# define GRID__GRID_DAEMON_H 1

/**
 * @defgroup server_grid Grid Daemon utilities V2
 * @ingroup server
 * @brief
 * @details
 * @{
 */

/* Some forward declarations to avoid useless includes */
struct message_s;
struct network_server_s;
struct gridd_request_dispatcher_s;

/**
 * @param server
 * @param url
 * @param dispatcher
 */
void grid_daemon_bind_host(struct network_server_s *server, const gchar *url,
		struct gridd_request_dispatcher_s *dispatcher);

/** @} */

#endif /* GRID__GRID_DAEMON_H */
