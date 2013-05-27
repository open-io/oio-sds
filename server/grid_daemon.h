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
