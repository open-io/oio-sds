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

/**
 */
struct meta1_service_url_s
{
	gint64 seq;        /**<  */
	gchar srvtype[LIMIT_LENGTH_SRVTYPE]; /**<  */
	gchar host[256];   /**<  */
	gchar args[1];     /**<  */
};

/**
 * @param url
 * @return
 */
struct meta1_service_url_s* meta1_unpack_url(const gchar *url);

/**
 * @param u
 */
void meta1_service_url_clean(struct meta1_service_url_s *u);

/**
 * @param uv
 */
void meta1_service_url_cleanv(struct meta1_service_url_s **uv);

/**
 * @param u
 * @return
 */
gchar* meta1_pack_url(struct meta1_service_url_s *u);

/**
 * @param u
 * @param dst
 * @return
 */
gboolean meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst);

GError* meta1_service_url_load_json_object(struct json_object *obj,
		struct meta1_service_url_s **out);

void meta1_service_url_encode_json (GString *gstr,
		struct meta1_service_url_s *m1u);

gchar * meta1_strurl_get_address(const char *str);

/** @} */

#endif /*OIO_SDS__metautils__lib__metatype_m1url_h*/
