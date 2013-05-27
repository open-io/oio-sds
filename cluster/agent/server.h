/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
