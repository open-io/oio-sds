#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.server"
#endif

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <metautils/lib/metautils.h>

#include "./server.h"
#include "./config.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./accept_worker.h"

/* Global variables */
int backlog_unix = MAX_ACCEPT;
int backlog_tcp = MAX_ACCEPT;
int unix_socket_mode = UNIX_SOCK_DEFAULT_MODE;
int unix_socket_uid = UNIX_SOCK_DEFAULT_UID;
int unix_socket_gid = UNIX_SOCK_DEFAULT_GID;


/* Static variables */
static int usock = -1;
static worker_t worker_unix;

static int port_inet = -1;
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

void
set_inet_server_port(int port)
{
	if (port<1 || port>=65536) {
		ERROR("Invalid port (%d outside 1,65535)", port);
		return;
	}
	if (port_inet>=1) {
		ERROR("The INET port has already been set to %d", port_inet);
		return;
	}
	port_inet = port;
	INFO("INET server port set to %d", port_inet);
}

static int
start_unix_server(long sock_timeout, GError **error)
{
	struct sockaddr_un local;
	worker_data_t wdata;

	memset(&wdata, 0x00, sizeof(wdata));
	memset(&local, 0x00, sizeof(local));
	memset(&worker_unix, 0, sizeof(worker_t));

	/* Create ressources to monitor */
	usock = socket_nonblock(PF_UNIX, SOCK_STREAM, 0);
	if (usock < 0) {
		GSETERROR(error, "Failed to create socket : %s", strerror(errno));
		return(0);
	}

	/* Bind to file */
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, AGENT_SOCK_PATH, sizeof(local.sun_path)-1);

	if (-1 == bind(usock, (struct sockaddr *)&local, sizeof(local))) {
		GSETERROR(error, "Failed to bind socket %d to file %s : %s", usock, AGENT_SOCK_PATH, strerror(errno));
		metautils_pclose(&usock);
		return(0);
	}

	/* Listen on that socket */
	if (-1 == listen(usock, backlog_unix)) {
		GSETERROR(error, "Failed to listen on socket %d : %s", usock, strerror(errno));
		metautils_pclose(&usock);
		return(0);
	}

	if (!set_unix_permissions(AGENT_SOCK_PATH, error)) {
		GSETERROR(error, "Failed to set proper permissions on socket %d", usock);
		metautils_pclose(&usock);
		return(0);
	}

	/* Create worker */
	wdata.fd = usock;
	wdata.sock_timeout = sock_timeout;

	worker_unix.func = accept_worker;
	worker_unix.timeout = 0;
	memcpy(&(worker_unix.data), &wdata, sizeof(worker_data_t));

	/* Accept new connection */
	if (!add_fd_to_io_scheduler(&worker_unix, EPOLLIN, error)) {
		GSETERROR(error,"Failed to add server sock to io_scheduler");
		metautils_pclose(&usock);
		return 0;
	}

	INFO("UNIX server started on socket %s", AGENT_SOCK_PATH);
	return(1);
}

static int
start_inet_server(long sock_timeout, GError **error)
{
	struct sockaddr_in sin;
	worker_data_t wdata;

	DEBUG("Starting an INET server bond on 127.0.0.1:%d", port_inet);
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
	sin.sin_port = htons(port_inet);
	if (!inet_aton("127.0.0.1", &(sin.sin_addr))) {
		GSETERROR(error,"Invalid address : 127.0.0.1 !!!");
		return 0;
	}

	if (-1 == bind(sock_inet, (struct sockaddr *)&sin, sizeof(sin))) {
		GSETERROR(error, "Failed to bind socket [%d] to address 127.0.0.1 : %s", sock_inet, strerror(errno));
		return(0);
	}

	/* Listen on that socket */
	if (-1 == listen(sock_inet, backlog_tcp)) {
		GSETERROR(error, "Failed to listen on socket [%d] : %s", sock_inet, strerror(errno));
		return(0);
	}

	/* Create worker */
	wdata.fd = sock_inet;
	wdata.sock_timeout = sock_timeout;

	worker_inet.func = accept_worker;
	worker_inet.timeout = 0;
	memcpy(&(worker_inet.data), &wdata, sizeof(worker_data_t));

	/* Accept new connection */
	if (!add_fd_to_io_scheduler(&worker_inet, EPOLLIN, error)) {
		GSETERROR(error,"Failed to add server sock to io_scheduler");
		return 0;
	}

	INFO("INET server started on socket fd=%d 127.0.0.1:%d", sock_inet, port_inet);
	return(1);
}

int
start_server(long sock_timeout, GError **error)
{
	if (!start_unix_server(sock_timeout,error)) {
		GSETERROR(error,"Failed to start the UNIX server");
		stop_server();
		return 0;
	}
	
	if (port_inet<0)
		NOTICE("No INET port provided, no INET server started");
	else {
		if (!start_inet_server(sock_timeout,error)) {
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

	if (usock>=0) {
		remove_fd_from_io_scheduler(&worker_unix, NULL);
		metautils_pclose(&usock);
	}

	if (sock_inet>=0) {
		remove_fd_from_io_scheduler(&worker_inet, NULL);
		metautils_pclose(&sock_inet);
	}

	unlink(AGENT_SOCK_PATH);
	DEBUG("The server is stopped.");
}
