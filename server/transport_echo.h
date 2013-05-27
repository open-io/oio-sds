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
 * @file transport_echo.h
 */

#ifndef GRID__TRANSPORT_ECHO__H
# define GRID__TRANSPORT_ECHO__H 1

/**
 * @defgroup server_transecho ECHO transport
 * @ingroup server
 * @brief
 * @details
 * 
 * @{
 */

struct network_client_s;

/**
 * @param u
 * @param clt
 */
void transport_echo_factory(gpointer u, struct network_client_s *clt);

/** @} */

#endif
