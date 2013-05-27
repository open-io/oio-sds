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
 * @file resolv.h
 */

#ifndef GRID__RESOLV__H
# define GRID__RESOLV__H 1
# include <glib.h>

struct sockaddr;
struct addr_info_s;

/**
 * @defgroup metautils_resolv Address resolution features
 * @ingroup metautils_utils
 * @{
 */

/**
 * @param s
 * @param dst
 * @param dst_size
 */
void grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst, gsize dst_size);

/**
 * @param a
 * @param dst
 * @param dst_size
 */
void grid_addrinfo_to_string(const struct addr_info_s *a, gchar *dst, gsize dst_size);

/**
 * @param src
 * @param end
 * @param a
 * @return
 */
gboolean grid_string_to_addrinfo(const gchar *src, const gchar *end,
		struct addr_info_s *a);

/**
 * @param src
 * @param end
 * @param s
 * @param slen
 * @return
 */
gboolean grid_string_to_sockaddr(const gchar *src, const gchar *end,
		struct sockaddr *s, gsize *slen);

/** @} */

#endif /* GRID__RESOLV__H */
