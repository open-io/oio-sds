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

#ifndef OIO_SDS__metautils__lib__metatype_m1url_h
# define OIO_SDS__metautils__lib__metatype_m1url_h 1

#include <glib/gtypes.h>

struct meta1_service_url_s
{
	gint64 seq;
	gchar srvtype[LIMIT_LENGTH_SRVTYPE];
	gchar host[256];
	gchar args[1];
};

struct meta1_service_url_s* meta1_unpack_url(const gchar *url);

void meta1_service_url_clean(struct meta1_service_url_s *u);

void meta1_service_url_cleanv(struct meta1_service_url_s **uv);

gchar* meta1_pack_url(struct meta1_service_url_s *u);

gboolean meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst);

GError* meta1_service_url_load_json_object(struct json_object *obj,
		struct meta1_service_url_s **out);

void meta1_service_url_encode_json (GString *gstr,
		struct meta1_service_url_s *m1u);

#endif /*OIO_SDS__metautils__lib__metatype_m1url_h*/
