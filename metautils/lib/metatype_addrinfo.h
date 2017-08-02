/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__metatype_addrinfo_h
# define OIO_SDS__metautils__lib__metatype_addrinfo_h 1

#include <glib/gtypes.h>

gboolean addr_info_equal(gconstpointer a, gconstpointer b);
gint addr_info_compare(gconstpointer a, gconstpointer b);
guint addr_info_hash(gconstpointer k);

#define addr_info_clean  g_free0
#define addr_info_gclean g_free1

/** Generate a location from the byte representation of the address */
oio_location_t location_from_addr_info(const struct addr_info_s *addr);

#endif /*OIO_SDS__metautils__lib__metatype_addrinfo_h*/
