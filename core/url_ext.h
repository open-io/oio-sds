/*
OpenIO SDS core library
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

#ifndef OIO_SDS__metautils__lib__oio_url_ext_h
# define OIO_SDS__metautils__lib__oio_url_ext_h 1

/**
 * This file provides and API dependent from the GLib, with non essential features.
 * Typically, this file is not destined to be included in external apps using the
 * C SDK.
 */
#include <glib.h>

#define oio_url_get_option_names oio_url_get_option_names
#define oio_url_to_json          oio_url_to_json

struct oio_url_s;

/** Return the names of all the options registered. Free the result
 * with g_strfreev(). 'u' cannot be NULL. */
gchar ** oio_url_get_option_names(struct oio_url_s *u);

void oio_url_to_json (GString *out, struct oio_url_s *u);

struct oio_requri_s
{
	gchar *path;
	gchar *query;
	gchar *fragment;

	gchar **query_tokens;
};

gboolean oio_requri_parse (const char *packed, struct oio_requri_s *ruri);

void oio_requri_clear (struct oio_requri_s *ruri);

#endif /*OIO_SDS__metautils__lib__oio_url_ext_h*/
