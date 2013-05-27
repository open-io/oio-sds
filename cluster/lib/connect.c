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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.lib"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
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

#include <metautils.h>
#include <gridagent.h>
#include "./connect.h"

int
connect_socket(int *fd, GError ** error)
{
	int usock;
	struct sockaddr_un local;

	/* Create socket */
	usock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (usock < 0) {
		GSETERROR(error, "Failed to create socket: (%d) %s",
				errno, strerror(errno));
		return (0);
	}

	/* Got to non-blocking mode */
	if (!sock_set_non_blocking(usock, TRUE)) {
		GSETERROR(error, "Failed to set non-blocking mode on fd=%d: (%d) %s",
				usock, errno, strerror(errno));
		close(usock);
		return 0;
	}

	/* Connect to file */
	memset(&local, 0x00, sizeof(local));
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, AGENT_SOCK_PATH, sizeof(local.sun_path));

	if (-1 == connect(usock, (struct sockaddr *) &local, sizeof(local))) {
		GSETERROR(error, "Failed to connect through file %s : %s", AGENT_SOCK_PATH, strerror(errno));
		close(usock);
		return (0);
	}

	*fd = usock;
	return (1);
}

