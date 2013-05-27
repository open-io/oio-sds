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
#define LOG_DOMAIN "gridcluster.agent.connect"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <errno.h>
#include <string.h>
#include <fcntl.h>

#include <metautils.h>

#include "connect.h"

int
connect_addr_info(int *fd, addr_info_t *addr, GError **error)
{
	int _fd;
	struct sockaddr_storage sas;
	gsize sas_size;

	*fd = _fd = -1;
	if (addr == NULL) {
		GSETERROR(error, "Argument <addr> can't be NULL");
		return(0);
	}

	bzero(&sas, sizeof(sas));
	sas_size = sizeof(struct sockaddr_storage);
	if (!addrinfo_to_sockaddr(addr, (struct sockaddr*)&sas, &sas_size)) {
		GSETERROR(error, "Failed to convert the addr_info structure into a proper sockaddr structure");
		return(0);
	}

	_fd = socket(sas.ss_family, SOCK_STREAM, 0);
	if (_fd < 0) {
		GSETERROR(error, "Failed to create socket : %s", strerror(errno));
		return(0);
	}

	/* Go to non-blocking mode */
	sock_set_reuseaddr(_fd, TRUE);
	sock_set_nodelay(_fd, TRUE);
	sock_set_linger(_fd, 1, 0);
	if (!sock_set_non_blocking(_fd, TRUE)) {
		GSETERROR(error, "Failed to put fd=%d in non-blocking mode", _fd);
		close(_fd);
		return(0);
	}

	if (-1 == connect(_fd, (struct sockaddr*)&sas, sas_size) && errno != EINPROGRESS) {
		GSETERROR(error, "Failed to connect socket : errno=%d %s", errno, strerror(errno));
		close(_fd);
		return(0);
	}

	*fd = _fd;
	return(1);
}

