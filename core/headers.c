/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <glib.h>
#include <curl/curl.h>

#include "oio_core.h"
#include "http_internals.h"

void
oio_headers_common (struct oio_headers_s *h)
{
	oio_headers_add (h, "Expect", "");
	oio_headers_add (h, PROXYD_HEADER_REQID, oio_ext_get_reqid());
}

void
oio_headers_clear (struct oio_headers_s *h)
{
	if (h->headers) {
		curl_slist_free_all (h->headers);
		h->headers = NULL;
	}
	if (h->gheaders) {
		g_slist_free_full (h->gheaders, g_free);
		h->gheaders = NULL;
	}
}

void
oio_headers_add (struct oio_headers_s *h, const char *k, const char *v)
{
	gchar *s = g_strdup_printf("%s: %s", k, v);
	h->gheaders = g_slist_prepend (h->gheaders, s);
	h->headers = curl_slist_append (h->headers, h->gheaders->data);
}

void
oio_headers_add_int64 (struct oio_headers_s *h, const char *k, gint64 i64)
{
	gchar v[24];
	g_snprintf (v, sizeof(v), "%"G_GINT64_FORMAT, i64);
	oio_headers_add (h, k, v);
}

