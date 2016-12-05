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

GError* meta1_service_url_load_json_object(struct json_object *obj,
		struct meta1_service_url_s **out);

void meta1_service_url_encode_json (GString *gstr,
		struct meta1_service_url_s *m1u);

gchar * meta1_strurl_get_address(const char *str);

/* In place shifts the characters unti the <host> part reaches the first
   position. In other words, "type|seq|ip:port|xyz" become "ip:port". */
void meta1_url_shift_addr(char *str);

/* with in place shifts, make an array of urls from an array of m1url. */
void meta1_urlv_shift_addr (char **v);

gboolean meta1_url_has_type(const char *str, const char *srvtype);

gchar ** meta1_url_filter_typed(const char * const *src, const char*srvtype);

#endif /*OIO_SDS__metautils__lib__metatype_m1url_h*/
