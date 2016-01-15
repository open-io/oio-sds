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

#ifndef OIO_SDS__sdk__http_internals_h
# define OIO_SDS__sdk__http_internals_h 1
#ifdef __cplusplus
extern "C" {
#endif

# ifndef  OIOSDS_http_agent
#  define OIOSDS_http_agent "OpenIO-SDS/SDK-2.0"
# endif

CURL * _curl_get_handle (void);

/* --------------------------------------------------------------------------
 * Headers helpers
 * -------------------------------------------------------------------------- */

struct oio_headers_s
{
	GSList *gheaders;
	struct curl_slist *headers;
};

void oio_headers_common (struct oio_headers_s *h);

void oio_headers_clear (struct oio_headers_s *h);

void oio_headers_add (struct oio_headers_s *h,
		const char *k, const char *v);

void oio_headers_add_int64 (struct oio_headers_s *h,
		const char *k, gint64 i64);

/* --------------------------------------------------------------------------
 * PROXY
 * Wrappers for CURL operations toward the proxy.
 * -------------------------------------------------------------------------- */

/* conscience */

GError * oio_proxy_call_conscience_register (CURL *h, const char *ns,
		GString *in);

GError * oio_proxy_call_conscience_deregister (CURL *h, const char *ns,
		GString *in);

GError * oio_proxy_call_conscience_flush (CURL *h, const char *ns,
		const char *srvtype);

GError * oio_proxy_call_conscience_unlock (CURL *h, const char *ns,
		GString *in);

GError * oio_proxy_call_conscience_list (CURL *h, const char *ns,
		const char *srvtype, GString *out);

GError * oio_proxy_call_conscience_list_types (CURL *h, const char *ns,
		GString *out);

struct oio_url_s;

/* directory */

GError * oio_proxy_call_reference_show (CURL *h, struct oio_url_s *u,
		const char *t, GString *out);

GError * oio_proxy_call_reference_create (CURL *h, struct oio_url_s *u);

GError * oio_proxy_call_reference_link (CURL *h, struct oio_url_s *u,
		const char *srvtype, gboolean autocreate, GString *out);

/* container */

GError * oio_proxy_call_content_show (CURL *h, struct oio_url_s *u,
		GString *out);

GError * oio_proxy_call_content_delete (CURL *h, struct oio_url_s *u);

GError * oio_proxy_call_content_link (CURL *h, struct oio_url_s *u,
		const char *id);

struct oio_proxy_content_prepare_out_s
{
	GString *body;
	gchar *header_chunk_size;
	gchar *header_version;
	gchar *header_content;
	gchar *header_stgpol;
	gchar *header_chunk_method;
	gchar *header_mime_type;
};

GError * oio_proxy_call_content_prepare (CURL *h, struct oio_url_s *u,
		gsize size, gboolean autocreate,
		struct oio_proxy_content_prepare_out_s *out);

struct oio_proxy_content_create_in_s
{
	gsize size;
	gint64 version;
	const char *content;
	GString *chunks;
	const char *hash;
};

GError * oio_proxy_call_content_create (CURL *h, struct oio_url_s *u,
		struct oio_proxy_content_create_in_s *in, GString *out);

GError * oio_proxy_call_content_list (CURL *h, struct oio_url_s *u,
		GString *out,
		const char *prefix, const char *marker, const char *end,
		guint max, char delim);

#ifdef __cplusplus
}
#endif
#endif /*OIO_SDS__sdk__http_internals_h*/
