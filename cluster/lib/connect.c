#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.lib"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include <metautils/lib/metautils.h>

#include "agent/gridagent.h"
#include "connect.h"

int
connect_socket(int *fd, GError ** error)
{
	int usock;
	struct sockaddr_un local;

	/* Create socket */
	usock = socket_nonblock(PF_UNIX, SOCK_STREAM, 0);
	if (usock < 0) {
		GSETERROR(error, "Failed to create socket: (%d) %s",
				errno, strerror(errno));
		return (0);
	}

	/* Connect to file */
	memset(&local, 0x00, sizeof(local));
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, AGENT_SOCK_PATH, sizeof(local.sun_path));

	if (-1 == connect(usock, (struct sockaddr *) &local, sizeof(local))) {
		GSETERROR(error, "Failed to connect through file %s : %s", AGENT_SOCK_PATH, strerror(errno));
		metautils_pclose(&usock);
		return (0);
	}

	*fd = usock;
	return (1);
}

