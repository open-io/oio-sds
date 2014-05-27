#ifndef _SERVER_H
#define _SERVER_H

#include <glib.h>

/**
 * Default value of the listen backlog for both TCP and Unix socket
 */
#define MAX_ACCEPT 256

extern int backlog_tcp;
extern int backlog_unix;
extern int unix_socket_mode;
extern int unix_socket_uid;
extern int unix_socket_gid;


/**
  *	Start the connection server
  *
*/
int start_server(long sock_timeout, GError **error);

/**
  *	Stop the connection server
  *
*/
void stop_server(void);

/**
 *
 */
void set_inet_server_port(int port);

#endif		/* _SERVER_H */
