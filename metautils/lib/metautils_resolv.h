/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__metautils_resolv_h
# define OIO_SDS__metautils__lib__metautils_resolv_h 1

# include <glib.h>

struct sockaddr;
struct addr_info_s;

gssize grid_sockaddr_to_string(const struct sockaddr *s, gchar *dst,
		gsize dst_size);

gsize grid_addrinfo_to_string(const struct addr_info_s *a, gchar *dst,
		gsize dst_size);

gboolean grid_string_to_addrinfo(const gchar *src, struct addr_info_s *a);

gboolean grid_string_to_sockaddr(const gchar *src, struct sockaddr *s, gsize *slen);

gint addrinfo_to_sockaddr(const struct addr_info_s * ai, struct sockaddr *sa,
		gsize * saSize);

gint addrinfo_from_sockaddr(struct addr_info_s * ai, struct sockaddr *sa,
		gsize saSize);

gboolean metautils_addr_valid_for_connect(const struct addr_info_s *a);

gboolean metautils_addr_valid_for_bind(const struct addr_info_s *a);

gboolean metautils_url_valid_for_connect(const gchar *url);

gboolean metautils_url_valid_for_bind(const gchar *url);

#endif /*OIO_SDS__metautils__lib__metautils_resolv_h*/
