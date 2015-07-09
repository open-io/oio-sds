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

#ifndef OIO_SDS__metautils__lib__hc_url_ext_h
# define OIO_SDS__metautils__lib__hc_url_ext_h 1

/**
 * This file provides and API dependent from the GLib, with non essential features.
 * Typically, this file is not destined to be included in external apps using the
 * C SDK.
 */
#include <glib.h>

struct hc_url_s;

/** Return the names of all the options registered. Free the result
 * with g_strfreev(). 'u' cannot be NULL. */
gchar ** hc_url_get_option_names(struct hc_url_s *u);

void hc_url_to_json (GString *out, struct hc_url_s *u);

#endif /*OIO_SDS__metautils__lib__hc_url_ext_h*/
