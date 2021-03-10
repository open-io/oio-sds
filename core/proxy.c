/*
OpenIO SDS core library
Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS

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

#include <core/http_internals.h>

#include <string.h>

#include <json-c/json.h>
#include <curl/curl.h>

#include <core/oio_sds.h>
#include <core/oiostr.h>
#include <core/oiocfg.h>
#include <core/oiolog.h>
#include <core/oioext.h>

#include "internals.h"
#include "core/http_put.h"


static GString *
_build_json (const char* const *src, GString *json)
{
	if (!json)
		json = g_string_new ("");
	g_string_append_c(json, '{');
	for (int i = 0; src [i] && src [i+1] ; i +=2 ) {
		if (i != 0)
			g_string_append_c (json, ',');
		oio_str_gstring_append_json_pair (json, src [i], src [i+1]);
	}
	g_string_append_c (json, '}');
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
	if (!ns) {
		GRID_WARN ("BUG No namespace configured!");
		return NULL;
	}

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
		return NULL;
	}

	GString *hu = g_string_sized_new(128);
	g_string_append_static(hu, "http://");
	g_string_append (hu, s);
	g_free (s);
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
	if (!hu) return NULL;

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
	if (!hu) return NULL;

	g_string_append_printf (hu, "/%s/%s/conscience/%s", PROXYD_PREFIX,
			ns, action);
	return hu;
}

static GString *
_curl_container_url (struct oio_url_s *u, const char *action)
{
	GString *hu = _curl_url_prefix_containers (u);
	if (!hu) return NULL;

	g_string_append_printf (hu, "/%s/%s/container/%s", PROXYD_PREFIX,
			oio_url_get(u, OIOURL_NS), action);
	_append (hu, '?', "acct", oio_url_get (u, OIOURL_ACCOUNT));
	_append (hu, '&', "ref",  oio_url_get (u, OIOURL_USER));
	return hu;
}

static GString *
_curl_content_url (struct oio_url_s *u, const char *action)
{
	GString *hu = _curl_url_prefix_containers (u);
	if (!hu) return NULL;

	g_string_append_printf (hu, "/%s/%s/content/%s", PROXYD_PREFIX,
			oio_url_get(u, OIOURL_NS), action);
	_append (hu, '?', "acct", oio_url_get (u, OIOURL_ACCOUNT));
	_append (hu, '&', "ref",  oio_url_get (u, OIOURL_USER));
	_append (hu, '&', "path", oio_url_get (u, OIOURL_PATH));
	if (oio_url_has(u, OIOURL_VERSION)) {
		_append(hu, '&', "version", oio_url_get(u, OIOURL_VERSION));
	}
	return hu;
}

/* -------------------------------------------------------------------------- */

static GError *
_body_parse_error (GString *b)
{
	EXTRA_ASSERT (b != NULL);
	struct json_tokener *tok = json_tokener_new ();
	struct json_object *jbody = json_tokener_parse_ex (tok, b->str, b->len);
	enum json_tokener_error parsing_error = json_tokener_get_error (tok);
	json_tokener_free (tok);
	tok = NULL;

	if (json_tokener_success != parsing_error) {
		if (jbody) json_object_put(jbody);
		return NEWERROR(0, "unknown error (invalid json: %s)",
				json_tokener_error_desc(parsing_error));
	}

	if (!jbody)
		return NEWERROR(0, "unknown error (empty body or null json)");

	struct json_object *jcode, *jmsg;
	struct oio_ext_json_mapping_s map[] = {
		{"status", &jcode, json_type_int, 0},
		{"message",  &jmsg,  json_type_string, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err =  oio_ext_extract_json(jbody, map);
	if (!err) {
		int code = 0;
		const char *msg = "Unknown error (unexpected json)";
		if (jcode) code = json_object_get_int64 (jcode);
		if (jmsg) msg = json_object_get_string (jmsg);
		err = NEWERROR(code, "(code=%d) %s", code, msg);
	}
	json_object_put (jbody);
	return err;
}

static size_t
_write_NOOP (char *d UNUSED, size_t s, size_t n, void *i UNUSED)
{
	return s*n;
}

static size_t
_write_GString (char *b, size_t s, size_t n, GString *out)
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
_read_GString (char *b, size_t s, size_t n, struct view_GString_s *in)
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

struct http_reply_ctx_s
{
	guint retry_after;
	struct http_ctx_s *out;
};

static int
_has_prefix_len (char **pb, size_t *plen, const char *prefix)
{
	char *b = *pb;
	size_t blen = *plen;
	if (!b || !blen)
		return FALSE;

	while (*prefix) {
		if (!(blen--) || g_ascii_tolower(*(b++)) != g_ascii_tolower(*(prefix++)))
			return FALSE;
	}

	*pb = b;
	*plen = blen;
	return TRUE;
}

static size_t
_header_callback(char *b, size_t s, size_t n, void *u)
{
	struct http_reply_ctx_s *ctx = u;
	const size_t total = n*s;

	EXTRA_ASSERT(ctx != NULL);

	if (total > 2048) /* header too big */
		return total;

	size_t remaining = total;

	/* One special header is considered, would the caller app be interested in
	 * headers or not */
	if (_has_prefix_len(&b, &remaining, "Retry-After: ")) {
		/* OSEF the value, let's do our own exponential back-off */
		ctx->retry_after = 1;
		return total;
	}

	/* Then only the OpenIO-related headers are considered if the caller app.
	 * has an interest in them. */
	if (ctx->out && ctx->out->headers
			&& _has_prefix_len (&b, &remaining, PROXYD_HEADER_PREFIX)) {
		gchar tmp[remaining+1];
		memcpy (tmp, b, remaining);
		tmp[remaining] = '\0';

		char *colon = strchr(tmp, ':');
		if (colon) {
			*colon = 0;

			const gsize l = g_strv_length (ctx->out->headers);
			ctx->out->headers = g_realloc (ctx->out->headers, (l+3) * sizeof(void*));
			ctx->out->headers[l+0] = g_strdup (g_strstrip(tmp));
			ctx->out->headers[l+1] = g_strdup (g_strstrip(colon+1));
			ctx->out->headers[l+2] = NULL;
		}
		return total;
	}

	return total;
}

static GError *
_proxy_call_notime (CURL *h, const char *method, const char *url,
		struct http_ctx_s *in, struct http_ctx_s *out,
		guint *p_retry_after)
{
	EXTRA_ASSERT (h != NULL);
	EXTRA_ASSERT (method != NULL);
	EXTRA_ASSERT (url != NULL);
	EXTRA_ASSERT (p_retry_after != NULL);
	struct view_GString_s view_input = {.data=NULL, .done=0};

	GError *err = NULL;
	curl_easy_setopt (h, CURLOPT_URL, url);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, method);

	struct http_reply_ctx_s ctx = {0};
	ctx.out = out;

	/* Populate the request headers */
	struct oio_headers_s headers = {NULL,NULL};
	oio_headers_common (&headers);
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);
	if (in && in->headers) {
		for (gchar **p=in->headers; *p && *(p+1) ;p+=2)
			oio_headers_add (&headers, *p, *(p+1));
	}

	/* Intercept the headers from the response */
	curl_easy_setopt (h, CURLOPT_HEADERDATA, &ctx);
	curl_easy_setopt (h, CURLOPT_HEADERFUNCTION, _header_callback);

	if (in && in->body) {
		view_input.data = in->body;
		gint64 len = in->body->len;
		curl_easy_setopt (h, CURLOPT_READFUNCTION,
				(curl_read_callback)_read_GString);
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
		curl_easy_setopt (h, CURLOPT_WRITEFUNCTION,
				(curl_write_callback)_write_GString);
		curl_easy_setopt (h, CURLOPT_WRITEDATA, out->body);
	} else {
		curl_easy_setopt (h, CURLOPT_WRITEFUNCTION,
				(curl_write_callback)_write_NOOP);
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
				g_prefix_error (&err, "Proxy error (%ld): ", code);
			} else {
				err = NEWERROR(code, "Request error (%ld)", code);
			}
		}
	}

	oio_headers_clear (&headers);

	*p_retry_after = ctx.retry_after;
	return err;
}

static GError *
_proxy_call_with_retry (CURL *h, const char *method, const char *url,
		struct http_ctx_s *in, struct http_ctx_s *out, guint request_attempts)
{
	if (!oio_ext_get_reqid())
		oio_ext_set_prefixed_random_reqid("C-API-");

	GError *err = NULL;
	guint retry_after = 0;

	const guint max = request_attempts;
	for (guint i=0; i<max ;++i) {
		const gint64 t = g_get_monotonic_time ();
		err = _proxy_call_notime (h, method, url, in, out, &retry_after);
		GRID_TRACE("proxy: %s %s took %"G_GINT64_FORMAT"us",
				method, url, g_get_monotonic_time() - t);
		(void) t;
		if (!err) /* success */
			break;
#ifdef HAVE_ENBUG
		if (err->code == 404 && i == 0) /* let's fake a retry */
			err->code = 503, retry_after = 1;
#endif
		if (err->code != HTTP_CODE_SRV_UNAVAILABLE) { /* not retryable */
			if (i > 0 && err->code == CODE_CONTENT_EXISTS
					&& g_strcmp0(method, "POST") == 0) {
				// We were retrying a POST operation, it's highly probable
				// that the original operation succeeded after we timed
				// out. So we consider this a success and don't return
				// the error.
				g_clear_error(&err);
			}
			break;
		}
		if (!retry_after)  /* not told to retry */
			break;
		/* Let's retry! */
		if (i+1 != max) {
			/* cleanup what has been allocated by the previous call */
			g_clear_error(&err);
			if (out) {
				if (out->headers) {
					g_strfreev(out->headers);
					out->headers = g_malloc0(sizeof(void*));
				}
				if (out->body) {
					g_string_set_size(out->body, 0);
				}
			}
			/* randomize the sleep-time to avoid resonance effects */
			const gulong sleep_base = (1 << i) * 200 * G_TIME_SPAN_MILLISECOND;
			const gulong sleep_jitter = oio_ext_rand_int_range(0, 100 * G_TIME_SPAN_MILLISECOND);
			g_usleep(sleep_base + sleep_jitter);
		}
	}
	return err;
}

static GError *
_proxy_call (CURL *h, const char *method, const char *url,
		struct http_ctx_s *in, struct http_ctx_s *out)
{
	return _proxy_call_with_retry(h, method, url, in, out, 1);
}

static GError *
_get_properties(CURL *h, GString *http_url,
		GString **props_str)
{
	struct http_ctx_s out_ctx = {0};
	if (props_str && *props_str)
		out_ctx.body = *props_str;
	else
		out_ctx.body = g_string_sized_new(512);

	GError *err = _proxy_call(h, "POST", http_url->str, NULL, &out_ctx);

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
	GString *json = g_string_new("{\"properties\":");
	json = _build_json(values, json);
	g_string_append_c(json, '}');
	struct http_ctx_s i = {
		.body = json
	};
	err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(i.body, TRUE);
	return err;
}

/* -------------------------------------------------------------------------- */

GError *
oio_proxy_call_container_create (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_container_url (u, "create");
	if (!http_url) return BADNS();

	gchar *hdrin[] = {PROXYD_HEADER_MODE, "autocreate", NULL};
	GString *body = g_string_new("{}");
	struct http_ctx_s i = { .headers = hdrin, .body = body };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(body, TRUE);
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
oio_proxy_call_container_get_properties(CURL *h, struct oio_url_s *u,
		GString **props_str)
{
	GString *http_url = _curl_container_url(u, "get_properties");
	if (!http_url)
		return BADNS();

	GError *err = _get_properties(h, http_url, props_str);

	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_container_set_properties (CURL *h, struct oio_url_s *u,
		const char* const *values)
{
	GString *http_url = _curl_container_url (u, "set_properties");
	if (!http_url) return BADNS();

	GError *err = _set_properties(h, http_url, values);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_get_properties(CURL *h, struct oio_url_s *u,
		GString **props_str)
{
	GString *http_url = _curl_content_url(u, "get_properties");
	if (!http_url)
		return BADNS();

	GError *err = _get_properties(h, http_url, props_str);

	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_set_properties (CURL *h, struct oio_url_s *u,
		const char* const *values)
{
	GString *http_url = _curl_content_url (u, "set_properties");
	if (!http_url) return BADNS();

	GError *err = _set_properties(h, http_url, values);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_show (CURL *h, struct oio_url_s *u, GString *out,
		gchar ***hout)
{
	GString *http_url = _curl_content_url (u, "show");
	if (!http_url) return BADNS();

	struct http_ctx_s o = {
			.headers = hout ? g_malloc0(sizeof(gchar*)) : NULL,
			.body = out
	};
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_string_free (http_url, TRUE);
	if (hout)
		*hout = o.headers;
	return err;
}

GError *
oio_proxy_call_content_drain(CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_content_url(u, "drain");
	if (!http_url) return BADNS();

	GError *err = _proxy_call(h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_delete (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_content_url (u, "delete");
	if (!http_url)
		return BADNS();

	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_truncate (CURL *h, struct oio_url_s *u, gint64 size)
{
	GString *http_url = _curl_content_url(u, "truncate");
	if (!http_url)
		return BADNS();

	gchar size_str[16] = {0};
	g_snprintf(size_str, sizeof(size_str), "%"G_GINT64_FORMAT, size);

	_append(http_url, '&', "content", oio_url_get(u, OIOURL_CONTENTID));
	_append(http_url, '&', "size", size_str);

	GError *err = _proxy_call(h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_prepare (CURL *h, struct oio_url_s *u,
		gsize size, const char *stgpol, guint start_pos, gboolean append,
		struct oio_proxy_content_prepare_out_s *out)
{
	gboolean use_legacy = FALSE;
	GString *http_url = NULL;
retry:
	if (use_legacy)
		http_url = _curl_content_url(u, "prepare");
	else
		http_url = _curl_content_url(u, "prepare2");

	if (!http_url)
		return BADNS();

	struct http_ctx_s i = {
		.headers = NULL,
		.body = NULL,
	};
	struct http_ctx_s o = {
		.headers = g_malloc0(sizeof(void*)),
		.body = out ? out->body : NULL
	};

	if (stgpol) {
		i.body = _gs_vprintf ("{\"size\":%"G_GSIZE_FORMAT",\"policy\":\"%s\","
				"\"position\",%u,\"append\":%s}",
				size, stgpol, start_pos, append? "true" : "false");
	} else {
		i.body =
			_gs_vprintf("{\"size\":%"G_GSIZE_FORMAT",\"policy\":null,"
					"\"position\":%u,\"append\": %s}",
					size, start_pos, append? "true" : "false");
	}

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

	g_string_free(http_url, TRUE);
	g_string_free(i.body, TRUE);
	g_strfreev(o.headers);
	if (err && err->code == HTTP_CODE_NOT_FOUND && !use_legacy) {
		GRID_DEBUG("configured proxy does not support content/prepare2, "
				"trying with legacy content/prepare (reqid=%s)",
				oio_ext_get_reqid());
		if (out->body)
			g_string_set_size(out->body, 0);
		use_legacy = TRUE;
		g_clear_error(&err);
		goto retry;
	}
	return err;
}

GError *
oio_proxy_call_content_create (CURL *h, struct oio_url_s *u,
		struct oio_proxy_content_create_in_s *in, GString *out)
{
	GString *http_url = NULL;
	if (in->update)
		http_url = _curl_content_url (u, "update");
	else
		http_url = _curl_content_url (u, "create");
	if (!http_url) return BADNS();

	if (in->content) {
		g_string_append_static (http_url, "&id=");
		g_string_append_uri_escaped (http_url, in->content, NULL, TRUE);
	}
	if (BOOL(in->autocreate)) {
		g_string_append_static (http_url, "&autocreate=yes");
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
		g_strdup(PROXYD_HEADER_PREFIX "content-meta-chunk-method"),
		g_strdup_printf("%s", in->chunk_method?: "plain"),
		NULL,
		NULL,
		NULL
	};

	if (in->append) {
		gsize len = oio_ptrv_length(hdrin);
		hdrin[len] = g_strdup(PROXYD_HEADER_MODE);
		hdrin[len+1] = g_strdup("append");
	}
	GString *body = in? in->chunks : NULL;
	if (in && !in->update && in->properties) {
		GString *val = g_string_sized_new(1024);
		g_string_append_static(val, "{\"properties\":");
		val = _build_json(in->properties, val);
		g_string_append_static(val, ",\"chunks\":");
		g_string_append(val, in->chunks->str);
		g_string_append_c(val, '}');
		body = val;
	}
	struct http_ctx_s i = { .headers = hdrin, .body = body };
	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, &o);
	_ptrv_free_content (i.headers);
	if (in && !in->update && in->properties)
		g_string_free (body, TRUE);
	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_content_list(CURL *h, struct oio_sds_list_param_s *params,
		GString *out)
{
	GString *http_url = _curl_container_url(params->url, "list");
	if (!http_url) return BADNS();

	if (params->prefix)
		_append(http_url, '&', "prefix", params->prefix);
	if (params->marker)
		_append(http_url, '&', "marker", params->marker);
	if (params->end)
		_append(http_url, '&', "end", params->end);
	if (params->max_items)
		g_string_append_printf(http_url, "&max=%zu", params->max_items);
	if (params->delimiter)
		g_string_append_printf(http_url, "&delimiter=%c", params->delimiter);
	if (params->flag_properties)
		g_string_append_printf(http_url, "&properties=1");

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
	if (!http_url) return BADNS();

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
	if (!http_url) return BADNS();

	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_delete (CURL *h, struct oio_url_s *u)
{
	GString *http_url = _curl_reference_url (u, "destroy");
	if (!http_url) return BADNS();

	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_link (CURL *h, struct oio_url_s *u,
		const char *srvtype, gboolean autocreate, GString *out)
{
	GString *http_url = _curl_reference_url (u, "link");
	if (!http_url) return BADNS();

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

GError *
oio_proxy_call_reference_get_properties(CURL *h, struct oio_url_s *u,
		GString **props_str)
{
	GString *http_url = _curl_reference_url(u, "get_properties");
	if (!http_url)
		return BADNS();

	GError *err = _get_properties(h, http_url, props_str);

	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_set_properties(CURL *h, struct oio_url_s *u,
		const char* const *values)
{
	GString *http_url = _curl_reference_url(u, "set_properties");
	if (!http_url)
		return BADNS();

	GError *err = _set_properties(h, http_url, values);

	g_string_free (http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_reference_force(CURL *h, struct oio_url_s *u,
		const char *t, const char* const *values, gint64 seq)
{
	GString *http_url = _curl_reference_url(u, "force");
	if (!http_url) {
		return BADNS();
	}

	if (t) {
		_append(http_url, '&', "type", t);
	}

	gchar *hdrin[] = { PROXYD_HEADER_MODE, "autocreate", NULL };

	GString *json = _build_json(values, NULL);
	g_string_overwrite(json, json->len - 1, ",");
	oio_str_gstring_append_json_pair_int(json, "seq", seq);
	g_string_append_printf(json, "}");

	struct http_ctx_s i = { .headers = hdrin, .body = json };
	GError *err = _proxy_call(h, "POST", http_url->str, &i, NULL);

	g_string_free(http_url, TRUE);
	g_string_free(json, TRUE);

	return err;
}

GError *
oio_proxy_call_reference_unlink(CURL *h, struct oio_url_s *u,
		const char *t)
{
	GString *http_url = _curl_reference_url(u, "unlink");
	if (!http_url) {
		return BADNS();
	}

	if (t) {
		_append(http_url, '&', "type", t);
	}

	GError *err = _proxy_call(h, "POST", http_url->str, NULL, NULL);

	g_string_free(http_url, TRUE);

	return err;
}

/* -------------------------------------------------------------------------- */

GError *
oio_proxy_call_conscience_register (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "register");
	if (!http_url) return BADNS();

	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_lock (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "lock");
	if (!http_url) return BADNS();

	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_deregister (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "deregister");
	if (!http_url) return BADNS();

	struct http_ctx_s i = { .headers = NULL, .body = in };
	GError *err = _proxy_call (h, "POST", http_url->str, &i, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_flush (CURL *h, const char *ns, const char *srvtype)
{
	GString *http_url = _curl_conscience_url (ns, "flush");
	if (!http_url) return BADNS();

	_append (http_url, '?', "type", srvtype);
	GError *err = _proxy_call (h, "POST", http_url->str, NULL, NULL);
	g_string_free(http_url, TRUE);
	return err;
}

GError *
oio_proxy_call_conscience_unlock (CURL *h, const char *ns, GString *in)
{
	GString *http_url = _curl_conscience_url (ns, "unlock");
	if (!http_url) return BADNS();

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
	if (!http_url) return BADNS();

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
	if (!http_url) return BADNS();

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
	if (!http_url) return BADNS();

	struct http_ctx_s o = { .headers = NULL, .body = out };
	GError *err = _proxy_call (h, "GET", http_url->str, NULL, &o);
	g_strfreev (o.headers);
	g_string_free(http_url, TRUE);
	return err;
}
