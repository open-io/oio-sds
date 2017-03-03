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
#include "internals.h"
#include "http_internals.h"

volatile enum oio_header_case_e oio_header_case = OIO_HDRCASE_NONE;

void
oio_headers_common (struct oio_headers_s *h)
{
	oio_headers_add (h, "Expect", "");
	oio_headers_add (h, PROXYD_HEADER_REQID, oio_ext_get_reqid());
	if (oio_ext_is_admin())
		oio_headers_add (h, PROXYD_HEADER_ADMIN, "1");
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

static void
_purify_case (gchar *s)
{
	GRand *r = NULL;

	switch (oio_header_case) {
		case OIO_HDRCASE_NONE:
			return;
		case OIO_HDRCASE_LOW:
			for (gchar *p=s; *p && *p != ':' ;++p)
				*p = g_ascii_tolower (*p);
			return;
		case OIO_HDRCASE_1CAP:
			for (gchar *p=s; *p && *p != ':' ;++p) {
				if (p==s) continue;
				if (*(p-1) == '-')
					*p = g_ascii_toupper (*p);
			}
			return;
		case OIO_HDRCASE_RANDOM:
			r = oio_ext_local_prng ();
			for (gchar *p=s; *p && *p != ':' ;++p) {
				*p = g_rand_boolean(r) ? g_ascii_tolower (*p) : g_ascii_toupper(*p);
			}
			return;
		default:
			g_assert_not_reached();
			return;
	}
}

void
oio_headers_add (struct oio_headers_s *h, const char *k, const char *v)
{
	gchar *s = g_strdup_printf("%s: %s", k, v);
	_purify_case (s);
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

