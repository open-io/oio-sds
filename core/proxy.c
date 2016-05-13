
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

#include <string.h>

#include <glib.h>
#include <json.h>
#include <curl/curl.h>

#include "oio_core.h"
#include "oio_sds.h"
#include "http_internals.h"
#include "http_put.h"
#include "internals.h"

/* -------------------------------------------------------------------------- */


static GString * _build_json(const char* const *src)
{
	GString *json = g_string_new("{");
	for (int i = 0; src [i] && src [i+1] ; i +=2 ) {
		if(i != 0)
			g_string_append(json,",");
		oio_str_gstring_append_json_pair(json, src [i],
						 src [i+1]);

	}
	g_string_append(json, "}");
	return json;
}


static void
_ptrv_free_content (gchar **tab)
{
	while (*tab) { g_free (*(tab++)); }
}

/* @private */
enum _prefix_e { PREFIX_CONSCIENCE, PREFIX_REFERENCE, PREFIX_CONTAINER };

static GString *
_curl_url_prefix (const char *ns, enum _prefix_e which)
{
	GString *hu = g_string_new("http://");

	if (!ns) {
		GRID_WARN ("BUG No namespace configured!");
		g_string_append (hu, "proxy");
	} else {
		gchar *s = NULL;

		if (which == PREFIX_CONSCIENCE)
			s = oio_cfg_get_proxy_conscience (ns);
		else if (which == PREFIX_CONTAINER)
			s = oio_cfg_get_proxy_containers (ns);
		else if (which == PREFIX_REFERENCE)
			s = oio_cfg_get_proxy_directory (ns);

		if (!s)
			s = oio_cfg_get_proxy (ns);

		if (!s) {
			GRID_WARN ("No proxy configured!");
			g_string_append (hu, "proxy");
		} else {
			g_string_append (hu, s);
			g_free (s);
		}
	}

	return hu;
}

static GString *
_curl_url_prefix_containers (struct oio_url_s *u)
{
	return _curl_url_prefix (oio_url_get (u, OIOURL_NS), PREFIX_CONTAINER);
}

static GString *
_curl_url_prefix_reference (struct oio_url_s *u)
{
	return _curl_url_prefix (oio_url_get (u, OIOURL_NS), PREFIX_REFERENCE);
}

static void
_append (GString *gs, char sep, const char *k, const char *v)
{
	if (k != NULL && v != NULL) {
		g_string_append_printf (gs, "%c%s=", sep, k);
		g_string_append_uri_escaped (gs, v, NULL, TRUE);
	}
}

static GString *
_curl_reference_url (struct oio_url_s *u, const char *action)
{
	GString *hu = _curl_url_prefix_reference (u);
	g_string_append_printf (hu, "/%s/%s/reference/%s", PROXYD_PREFIX,
			oio_url_get(u, OIOURL_NS), action);
	_append (hu, '?', "acct", oio_url_get (u, OIOURL_ACCOUNT));
	_append (hu, '&', "ref",  oio_url_get (u, OIOURL_USER));
	return hu;
}

static GString *
_curl_conscience_url (const char *ns, const char *action)
{
	GString *hu = _curl_url_prefix (ns, PREFIX_CONSCIENCE);
	g_string_append_printf (hu, "/%s/%s/conscience/%s", PROXYD_PREFIX,
			ns, action);
	return hu;
}

static GString *
_append_type (struct oio_url_s *u, GString *hu)
{
	const char *type = oio_url_get (u, OIOURL_TYPE);
	if (type && *type)
		_append (hu, '&', "type", type);
	return hu;
}

static GString *
_curl_container_url (struct oio_url_s *u, const char *action)
{
	GString *hu = _curl_url_prefix_containers (u);
	g_string_append_printf (hu, "/%s/%s/container/%s", PROXYD_PREFIX,
			oio_url_get(u, OIOURL_NS), action);
	_append (hu, '?', "acct", oio_url_get (u, OIOURL_ACCOUNT));
	_append (hu, '&', "ref",  oio_url_get (u, OIOURL_USER));
	_append_type (u, hu);
	return hu;
}

static GString *
_curl_content_url (struct oio_url_s *u, const char *action)
{
	GString *hu = _curl_url_prefix_containers (u);
	g_string_append_printf (hu, "/%s/%s/content/%s", PROXYD_PREFIX,
			oio_url_get(u, OIOURL_NS), action);
	_append (hu, '?', "acct", oio_url_get (u, OIOURL_ACCOUNT));
	_append (hu, '&', "ref",  oio_url_get (u, OIOURL_USER));
	_append_type (u, hu);
	_append (hu, '&', "path", oio_url_get (u, OIOURL_PATH));
	return hu;
}

/* -------------------------------------------------------------------------- */

static GError *
_body_parse_error (GString *b)
{
	g_assert (b != NULL);
	struct json_tokener *tok = json_tokener_new ();
	struct json_object *jbody = json_tokener_parse_ex (tok, b->str, b->len);
	json_tokener_free (tok);
	tok = NULL;

	if (!jbody)
		return NEWERROR(0, "No error explained");

	struct json_object *jcode, *jmsg;
	struct oio_ext_json_mapping_s map[] = {
		{"status", &jcode, json_type_int,    0},
		{"message",  &jmsg,  json_type_string, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err =  oio_ext_extract_json(jbody, map);
	if (!err) {
		int code = 0;
		const char *msg = "Unknown error";
		if (jcode) code = json_object_get_int64 (jcode);
		if (jmsg) msg = json_object_get_string (jmsg);
		err = NEWERROR(code, "(code=%d) %s", code, msg);
	}
	json_object_put (jbody);
	return err;
}

static size_t
_write_NOOP (void *data, size_t s, size_t n, void *ignored)
{
	(void) data, (void) ignored;
	return s*n;
}

static size_t
_write_GString (void *b, size_t s, size_t n, GString *out)
{
	g_string_append_len (out, (gchar*)b, s*n);
	return s*n;
}

struct view_GString_s
{
	GString *data;
	size_t done;
};

static size_t
_read_GString (void *b, size_t s, size_t n, struct view_GString_s *in)
{
	size_t remaining = in->data->len - in->done;
	size_t available = s * n;
	size_t len = MIN(remaining,available);
	if (len) {
		memcpy(b, in->data->str + in->done, len);
		in->done += len;
	}
	return len;
}

static GString *
_gs_vprintf (const char *fmt, ...)
{
	GString *gs = g_string_new ("");
	va_list args;
	va_start (args, fmt);
	g_string_vprintf (gs, fmt, args);
	va_end (args);
	return gs;
}

/* -------------------------------------------------------------------------- */

struct http_ctx_s
{
	gchar **headers;
	GString *body;
};

static int
_has_prefix_len (char **pb, size_t *plen, const char *prefix)
{
	char *b = *pb;
	size_t blen = *plen;
	if (!b || !blen)
		return FALSE;

	while (*prefix) {
		if (!(blen--) || g_ascii_tolower(*(b++)) != *(prefix++))
			return FALSE;
	}

	*pb = b;
	*plen = blen;
	return TRUE;
}

static size_t
_header_callback(char *b, size_t s, size_t n, void *u)
{
	struct http_ctx_s *o = u;
	size_t total = n*s;
	if (!o || !o->headers || !_has_prefix_len (&b, &total, "x-oio-"))
		return total;

	gchar tmp[total+1];
	memcpy (tmp, b, total);
	tmp[total] = '\0';

	char *colon = strchr(tmp, ':');
	if (colon) {
		*(colon++) = 0;

		const gsize l = g_strv_length (o->headers);
		o->headers = g_realloc (o->headers, (l+3) * sizeof(void*));
		o->headers[l+0] = g_strdup (g_strstrip(tmp));
		o->headers[l+1] = g_strdup (g_strstrip(colon));
		o->headers[l+2] = NULL;
	}

	return n*s;
}

static GError *
_proxy_call_notime (CURL *h, const char *method, const char *url,
		struct http_ctx_s *in, struct http_ctx_s *out)
{
	g_assert (h != NULL);
	g_assert (method != NULL);
	g_assert (url != NULL);
	struct view_GString_s view_input = {.data=NULL, .done=0};

	GError *err = NULL;
	curl_easy_setopt (h, CURLOPT_URL, url);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, method);

	/* Populate the request headers */
	struct oio_headers_s headers = {NULL,NULL};
	oio_headers_common (&headers);
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
	if (in && in->headers) {
		for (gchar **p=in->headers; *p && *(p+1) ;p+=2)
			oio_headers_add (&headers, *p, *(p+1));
	}

	/* Intercept the headers from the response */
	if (out) {
		curl_easy_setopt (h, CURLOPT_HEADERDATA, out);
		curl_easy_setopt (h, CURLOPT_HEADERFUNCTION, _header_callback);
	} else {
		curl_easy_setopt (h, CURLOPT_HEADERDATA, NULL);
		curl_easy_setopt (h, CURLOPT_HEADERFUNCTION, NULL);
	}

	if (in && in->body) {
		view_input.data = in->body;
		gint64 len = in->body->len;
		curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
		curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
		curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, len);
	} else {
		curl_easy_setopt (h, CURLOPT_READFUNCTION, NULL);
		curl_easy_setopt (h, CURLOPT_READDATA, NULL);
		curl_easy_setopt (h, CURLOPT_UPLOAD, 0L);
		curl_easy_setopt (h, CURLOPT_INFILESIZE, 0L);
	}

	if (out && out->body) {
		curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GString);
		curl_easy_setopt (h, CURLOPT_WRITEDATA, out->body);
	} else {
		curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_NOOP);
	}

	CURLcode rc = curl_easy_perform (h);
	if (CURLE_OK != rc)
		err = NEWERROR(0, "Proxy error: (%d) %s", rc, curl_easy_strerror(rc));
	else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100)) {
			if (out && out->body) {
				err = _body_parse_error (out->body);
				g_prefix_error (&err, "Request error (%ld): ", code);
			} else {
				err = NEWERROR(code, "Request error (%ld)", code);
			}
		}
	}
	oio_headers_clear (&headers);
	return err;
}

static GError *
_proxy_call (CURL *h, const char *method, const char *url,
		struct http_ctx_s *in, struct http_ctx_s *out)
{
	if (!oio_ext_get_reqid ())
		oio_ext_set_random_reqid();

	gint64 t = g_get_monotonic_time ();
	GError *err = _proxy_call_notime (h, method, url, in, out);
	t = g_get_monotonic_time () - t;
	GRID_TRACE("proxy: %s %s took %"G_GINT64_FORMAT"us", method, url, t);
	return err;
}

/* -------------------------------------------------------------------------- */

GError *
oio_proxy_call_container_create (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_container_url (u, "create");
	gchar *hdrin[] = {PROXYD_HEADER_MODE, "autocreate", NULL};
	struct http_ctx_s i = { .headers = hdrin, .body = NULL };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_container_delete (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_container_url (u, "destroy");
	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_container_get_properties (CURL *h, struct oio_url_s *u,
		GString **props_str)
{
	GString *http_url = _curl_container_url (u, "get_properties");
	struct http_ctx_s out_ctx = {0};
	if (props_str && *props_str)
		out_ctx.body = *props_str;
	else
		out_ctx.body = g_string_sized_new(512);

	GError *err = _proxy_call (h, "POST", http_url->str, NULL, &out_ctx);

	g_string_free(http_url, TRUE);
	if (props_str && !*props_str && !err)
		*props_str = out_ctx.body;
	else
		g_string_free(out_ctx.body, TRUE);
	return err;
}

GError *
oio_proxy_call_content_get_properties (CURL *h, struct oio_url_s *u,
					 GString **props_str)
{
	GString *http_url = _curl_content_url (u, "get_properties");
	struct http_ctx_s out_ctx = {0};
	if (props_str && *props_str)
		out_ctx.body = *props_str;
	else
		out_ctx.body = g_string_sized_new(512);

	GError *err = _proxy_call (h, "POST", http_url->str, NULL, &out_ctx);

	g_string_free(http_url, TRUE);
	if (props_str && !*props_str && !err)
		*props_str = out_ctx.body;
	else
		g_string_free(out_ctx.body, TRUE);
	return err;
}

static GError *
_set_properties(CURL *h, GString *http_url, const char* const *values)
{
	GError *err = NULL;
	GString *json = _build_json(values);
	struct http_ctx_s i = {
		.body = json
	};
	err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(i.body, TRUE);
	return err;
	
}

GError *
oio_proxy_call_container_set_properties (CURL *h, struct oio_url_s *u,
				       const char* const *values)
{
	GString *http_url = _curl_container_url (u, "set_properties");
	GError *err = _set_properties(h, http_url, values);
	g_string_free (http_url, TRUE);
	return err;
}


GError *
oio_proxy_call_content_set_properties (CURL *h, struct oio_url_s *u,
				       const char* const *values)
{
        GString *http_url = _curl_content_url (u, "set_properties");
	GError *err = _set_properties(h, http_url, values);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_show (CURL *h, struct oio_url_s *u, GString *out)
{
	GString *http_url = _curl_content_url (u, "show");
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_delete (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_content_url (u, "delete");
	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_link (CURL *h, struct oio_url_s *u, const char *id)
{
	struct http_ctx_s i = { .headers = NULL, .body = _gs_vprintf("{\"id\":\"%s\"}", id) };
	GString *http_url = _curl_content_url (u, "link");
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free (http_url, TRUE);
	g_string_free (i.body, TRUE);
	return err;
}

GError *
oio_proxy_call_content_prepare (CURL *h, struct oio_url_s *u,
		gsize size, gboolean autocreate,
		struct oio_proxy_content_prepare_out_s *out)
{
	gchar *hdrin[] = {
		PROXYD_HEADER_MODE, autocreate ? "autocreate" : NULL,
		NULL
	};
	struct http_ctx_s i = {
		.headers = hdrin,
		.body = _gs_vprintf ("{\"size\":%"G_GSIZE_FORMAT",\"autocreate\":%s}",
			size, autocreate ? "true" : "false")
	};
	struct http_ctx_s o = {
		.headers = g_malloc0(sizeof(void*)),
		.body = out ? out->body : NULL
	};
	GString *http_url = _curl_content_url (u, "prepare");
	GError *err = _proxy_call (h, "POST", http_url->str, &i, &o);
	if (!err && out && o.headers) {
		for (gchar **p=o.headers; *p && *(p+1) ;p+=2) {
			if (!g_ascii_strcasecmp(*p, "ns-chunk-size"))
				oio_str_replace (&out->header_chunk_size, *(p+1));
			else if (!g_ascii_strcasecmp(*p, "content-meta-version"))
				oio_str_replace (&out->header_version, *(p+1));
			else if (!g_ascii_strcasecmp(*p, "content-meta-id"))
				oio_str_replace (&out->header_content, *(p+1));
			else if (!g_ascii_strcasecmp(*p, "content-meta-policy"))
				oio_str_replace (&out->header_stgpol, *(p+1));
			else if (!g_ascii_strcasecmp(*p, "content-meta-mime-type"))
				oio_str_replace (&out->header_mime_type, *(p+1));
			else if (!g_ascii_strcasecmp(*p, "content-meta-chunk-method"))
				oio_str_replace (&out->header_chunk_method, *(p+1));
		}
	}
	g_string_free (http_url, TRUE);
	g_string_free(i.body, TRUE);
	if (o.headers)
		g_strfreev (o.headers);
	return err;
}

GError *
oio_proxy_call_content_create (CURL *h, struct oio_url_s *u,
		struct oio_proxy_content_create_in_s *in, GString *out)
{
	GString *http_url = _curl_content_url (u, "create");
	if (in->content) {
		g_string_append (http_url, "&id=");
		g_string_append_uri_escaped (http_url, in->content, NULL, TRUE);
	}
	gchar *hdrin[] = {
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-id"),
		g_strdup_printf("%s", in->content),
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-version"),
		g_strdup_printf("%"G_GINT64_FORMAT, in->version),
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-length"),
		g_strdup_printf("%"G_GSIZE_FORMAT, in->size),
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-hash"),
		g_strdup_printf("%s", in->hash),
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-policy"),
		g_strdup_printf("%s", in->stgpol?: "NONE"),
		NULL
	};
	struct http_ctx_s i = { .headers = hdrin, .body = in ? in->chunks : NULL };
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, &o);
	_ptrv_free_content (i.headers);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_list (CURL *h, struct oio_url_s *u, GString *out,
		const char *prefix, const char *marker, const char *end,
		guint max, char delim)
{
	GString *http_url = _curl_container_url (u, "list");
	if (prefix) _append (http_url, '&', "prefix", prefix);
	if (marker) _append (http_url, '&', "marker", marker);
	if (end) _append (http_url, '&', "end", end);
	if (max) g_string_append_printf (http_url, "&max=%u", max);
	if (delim) g_string_append_printf (http_url, "&delimiter=%c", delim);

	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_strfreev (o.headers);

	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_show (CURL *h, struct oio_url_s *u,
		const char *t, GString *out)
{
	GString *http_url = _curl_reference_url (u, "show");
	if (t) _append(http_url, '&', "type", t);

	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_strfreev (o.headers);

	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_create (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_reference_url (u, "create");
	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_link (CURL *h, struct oio_url_s *u,
		const char *srvtype, gboolean autocreate, GString *out)
{
	GString *http_url = _curl_reference_url (u, "link");
	_append (http_url, '&', "type", srvtype);
	gchar *hdrin[] = {
		g_strdup(PROXYD_HEADER_MODE),
		g_strdup(autocreate ? "autocreate" : ""),
		NULL,
	};

	struct http_ctx_s i = { .headers = hdrin, .body = NULL };
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, &o);

	_ptrv_free_content (i.headers);
	g_strfreev (o.headers);
	g_string_free(http_url, TRUE);
	return err;
}

/* -------------------------------------------------------------------------- */

GError *
oio_proxy_call_conscience_register (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "register");
	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_lock (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "lock");
	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_deregister (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "deregister");
	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_flush (CURL *h, const char *ns, const char *srvtype)
{
	GString *http_url = _curl_conscience_url (ns, "flush");
	_append (http_url, '?', "type", srvtype);
	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_unlock (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "unlock");
	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_list (CURL *h, const char *ns,
		const char *srvtype, gboolean full, GString *out)
{
	GString *http_url = _curl_conscience_url (ns, "list");
	_append (http_url, '?', "type", srvtype);
	gchar *hdrin[] = {
		g_strdup(PROXYD_HEADER_MODE),
		g_strdup(full ? "full" : NULL),
		NULL,
	};

	struct http_ctx_s i = { .headers = hdrin, .body = NULL };
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, &i, &o);

	_ptrv_free_content (i.headers);
	g_strfreev (o.headers);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_list_types (CURL *h, const char *ns,
		GString *out)
{
	GString *http_url = _curl_conscience_url (ns, "info");
	_append (http_url, '?', "what", "types");
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_strfreev (o.headers);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_info (CURL *h, const char *ns, GString *out)
{
	GString *http_url = _curl_conscience_url (ns, "info");
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_strfreev (o.headers);
	g_string_free(http_url, TRUE);
	return err;
}
