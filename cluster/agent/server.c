/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./server.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./accept_worker.h"

/* Static variables */
static int sock_unix = -1;
static worker_t worker_unix;

static int sock_inet = -1;
static worker_t worker_inet;

static gboolean
set_unix_permissions(const gchar *path, GError **error)
{
	if (unix_socket_mode != 0) {
		INFO("Setting UNIX socket mode to %o", unix_socket_mode);
		if (0 != chmod(path, unix_socket_mode)) {
			GSETERROR(error, "chmod(%s,%o) error : errno=%d (%s)",
				path, unix_socket_mode, errno, strerror(errno));
			return FALSE;
		}
	}

	if (unix_socket_uid > 0 && unix_socket_gid > 0) {
		INFO("Setting UNIX socket ids to %d:%d", unix_socket_uid, unix_socket_gid);
		if (0 != chown(path, unix_socket_uid, unix_socket_gid)) {
			GSETERROR(error, "chown(%s,%d,%d) error : errno=%d (%s)",
				path, unix_socket_uid, unix_socket_gid, errno, strerror(errno));
			return FALSE;
		}
	}

	return TRUE;
}

static int
start_unix_server(GError **error)
{
	struct sockaddr_un local;
	worker_data_t wdata;

	memset(&wdata, 0x00, sizeof(wdata));
	memset(&local, 0x00, sizeof(local));
	memset(&worker_unix, 0, sizeof(worker_t));

	/* Create ressources to monitor */
	sock_unix = socket_nonblock(PF_UNIX, SOCK_STREAM, 0);
	if (sock_unix < 0) {
		GSETERROR(error, "Failed to create socket : %s", strerror(errno));
		return(0);
	}

	/* Bind to file */
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, unix_socket_path, sizeof(local.sun_path)-1);

	if (-1 == bind(sock_unix, (struct sockaddr *)&local, sizeof(local))) {
		GSETERROR(error, "Failed to bind socket %d to file %s : %s",
				sock_unix, unix_socket_path, strerror(errno));
		metautils_pclose(&sock_unix);
		return(0);
	}

	/* Listen on that socket */
	if (-1 == listen(sock_unix, unix_socket_backlog)) {
		GSETERROR(error, "Failed to listen on socket %d : %s", sock_unix, strerror(errno));
		metautils_pclose(&sock_unix);
		return(0);
	}

	if (!set_unix_permissions(unix_socket_path, error)) {
		GSETERROR(error, "Failed to set proper permissions on socket %d", sock_unix);
		metautils_pclose(&sock_unix);
		return(0);
	}

	/* Create worker */
	wdata.fd = sock_unix;
	wdata.sock_timeout = unix_socket_timeout;

	worker_unix.func = accept_worker;
	worker_unix.timeout.startup = 0;
	worker_unix.timeout.activity = 0;
	memcpy(&(worker_unix.data), &wdata, sizeof(worker_data_t));

	/* Accept new connection */
	if (!add_fd_to_io_scheduler(&worker_unix, EPOLLIN, error)) {
		GSETERROR(error,"Failed to add server sock to io_scheduler");
		metautils_pclose(&sock_unix);
		return 0;
	}

	INFO("UNIX server started on socket %s", unix_socket_path);
	return(1);
}

static int
start_inet_server(GError **error)
{
	struct sockaddr_in sin;
	worker_data_t wdata;

	DEBUG("Starting an INET server bond on 127.0.0.1:%d", inet_socket_port);
	memset(&wdata, 0x00, sizeof(wdata));
	memset(&worker_inet, 0, sizeof(worker_t));

	/* Create ressources to monitor */
	sock_inet = socket_nonblock(PF_INET, SOCK_STREAM, 0);
	if (sock_inet < 0) {
		GSETERROR(error, "Failed to create socket : %s", strerror(errno));
		return(0);
	}

	sock_set_reuseaddr(sock_inet, TRUE);

	/* Bind to file */
	memset(&sin, 0x00, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(inet_socket_port);
	if (!inet_aton("127.0.0.1", &(sin.sin_addr))) {
		GSETERROR(error,"Invalid address : 127.0.0.1 !!!");
		return 0;
	}

	if (-1 == bind(sock_inet, (struct sockaddr *)&sin, sizeof(sin))) {
		GSETERROR(error, "Failed to bind socket [%d] to address 127.0.0.1 : %s", sock_inet, strerror(errno));
		return(0);
	}

	/* Listen on that socket */
	if (-1 == listen(sock_inet, inet_socket_backlog)) {
		GSETERROR(error, "Failed to listen on socket [%d] : %s", sock_inet, strerror(errno));
		return(0);
	}

	/* Create worker */
	wdata.fd = sock_inet;
	wdata.sock_timeout = inet_socket_timeout;

	worker_inet.func = accept_worker;
	worker_inet.timeout.startup = 0;
	worker_inet.timeout.activity = 0;
	memcpy(&(worker_inet.data), &wdata, sizeof(worker_data_t));

	/* Accept new connection */
	if (!add_fd_to_io_scheduler(&worker_inet, EPOLLIN, error)) {
		GSETERROR(error,"Failed to add server sock to io_scheduler");
		return 0;
	}

	INFO("INET server started on socket fd=%d 127.0.0.1:%d",
			sock_inet, inet_socket_port);
	return(1);
}

int
start_server(GError **error)
{
	if (!*unix_socket_path && inet_socket_port <= 0) {
		GSETERROR(error, "No server configured");
		return 0;
	}
	if (unix_socket_path[0]) {
		if (!start_unix_server(error)) {
			GSETERROR(error,"Failed to start the UNIX server");
			stop_server();
			return 0;
		}
	}
	
	if (inet_socket_port > 0) {
		if (!start_inet_server(error)) {
			GSETERROR(error,"Failed to start the INET server");
			stop_server();
			return 0;
		}
	}

	return 1;
}

void
stop_server(void)
{
	DEBUG("Stopping the server...");

	if (sock_unix >= 0) {
		remove_fd_from_io_scheduler(&worker_unix, NULL);
		metautils_pclose(&sock_unix);
		unlink(unix_socket_path);
	}

	if (sock_inet >= 0) {
		remove_fd_from_io_scheduler(&worker_inet, NULL);
		metautils_pclose(&sock_inet);
	}

	DEBUG("The server is stopped.");
}
