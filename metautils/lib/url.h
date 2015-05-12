/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant (metacd)
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

#ifndef OIO_SDS__metautils__lib__url_h
# define OIO_SDS__metautils__lib__url_h 1
# include <glib.h>

struct req_uri_s
{
	gchar *path;
	gchar *query;
	gchar *fragment;

	gchar **query_tokens;
};

gboolean metautils_requri_parse (const char *packed, struct req_uri_s *ruri);

void metautils_requri_clear (struct req_uri_s *ruri);

#endif /*OIO_SDS__metautils__lib__hc_url_h*/
