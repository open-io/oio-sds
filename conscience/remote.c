/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <glib.h>
#include <curl/curl.h>
#include <json-c/json.h>

#include <metautils/metautils.h>
#include <core/http_put.h>

#include "remote.h"

GError *
gcluster_get_namespace (const char *cs, namespace_info_t **out)
{
	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat (cs, 30.0,
			message_marshall_gba_and_clean(metautils_message_create_named(
					NAME_MSGNAME_CS_GET_NSINFO)), &gba);
	if (err) {
		g_prefix_error(&err, "request: ");
		return err;
	}

	*out = namespace_info_unmarshall(gba->data, gba->len, &err);
	if (*out) return NULL;
	GSETERROR(&err, "Decoding error");
	return err;
}

GError *
gcluster_get_services(const char *cs, const char *type, gboolean full,
		gboolean local, GSList **out)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_SRV);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	if (full)
		metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");
	if (local)
		metautils_message_add_field_str(req, NAME_MSGKEY_LOCAL, "1");
	return gridd_client_exec_and_decode (cs, 30.0,
			message_marshall_gba_and_clean(req), out, service_info_unmarshall);
}

GError *
gcluster_get_service_types(const char *cs, GSList **out)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_GET_SRVNAMES);
	return gridd_client_exec_and_decode (cs, 30.0,
			message_marshall_gba_and_clean(req), out, strings_unmarshall);
}

GError *
gcluster_push_services(const char *cs, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_PUSH_SRV);
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	return gridd_client_exec (cs, 30.0, message_marshall_gba_and_clean(req));
}

GError*
gcluster_remove_services(const char *cs, const char *type, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_RM_SRV);
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	if (type) metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	return gridd_client_exec (cs, 30.0, message_marshall_gba_and_clean(req));
}

/* ------------------------------------------------------------------------- */

static int
_trace(CURL *h, curl_infotype t, char *data, size_t size, void *u)
{
	(void) h, (void) u;
	switch (t) {
		case CURLINFO_TEXT:
			GRID_TRACE("CURL: %.*s", (int)size, data);
			return 0;
		case CURLINFO_HEADER_IN:
			GRID_TRACE("CURL< %.*s", (int)size, data);
			return 0;
		case CURLINFO_HEADER_OUT:
			GRID_TRACE("CURL> %.*s", (int)size, data);
			return 0;
		default:
			return 0;
	}
}

struct view_GBytes_s
{
	GBytes *data;
	size_t done;
};

static size_t
_write_GByteArray (void *b, size_t s, size_t n, GByteArray *out)
{
	g_byte_array_append (out, (guint8*)b, s*n);
	return s*n;
}

static size_t
_read_GBytes (void *dst, size_t s, size_t n, struct view_GBytes_s *in)
{
	gsize srclen = 0;
	const void *src = g_bytes_get_data (in->data, &srclen);

	size_t remaining = srclen - in->done;
	size_t available = s * n;
	size_t len = MIN(remaining, available);
	if (len) {
		memcpy(dst, src, len);
		in->done += len;
	}
	return len;
}

static GError *
_proxy_request (const char *method, const char *url, GBytes *in, GBytes **pout)
{
	GError *err = NULL;
	GByteArray *out = g_byte_array_new ();

	if (!oio_local_get_reqid ())
		oio_local_set_random_reqid ();

	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_USERAGENT, "OpenIO-SDS/conscience-remote-2.0");
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_PROXY, NULL);
	if (GRID_TRACE_ENABLED()) {
		curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
		curl_easy_setopt (h, CURLOPT_VERBOSE, 1L);
	}
	curl_easy_setopt (h, CURLOPT_URL, url);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, method);

	struct http_headers_s headers = {NULL,NULL};
	http_headers_add (&headers, "Expect", "");
	http_headers_add (&headers, PROXYD_HEADER_REQID, oio_local_get_reqid());
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers.headers);

	if (in && g_bytes_get_size(in)) {
		struct view_GBytes_s view = {.data=in, .done=0};
		curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, g_bytes_get_size (in));
		curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GBytes);
		curl_easy_setopt (h, CURLOPT_READDATA, &view);
	}

	curl_easy_setopt (h, CURLOPT_WRITEFUNCTION, _write_GByteArray);
	curl_easy_setopt (h, CURLOPT_WRITEDATA, out);

	int rc = curl_easy_perform (h);
	if (rc != CURLE_OK)
		err = NEWERROR(0, "Proxy error: (%d) %s", rc, curl_easy_strerror(rc));
	else {
		long code = 0;
		curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 == (code/100)) {
			if (pout) {
				g_byte_array_append (out, (guint8*)"", 1);
				g_byte_array_set_size (out, out->len-1);
				*pout = g_byte_array_free_to_bytes (out);
				out = NULL;
			}
		} else {
			err = http_body_parse_error ((char*)out->data, out->len);
			if (pout)
				*pout = NULL;
			g_prefix_error (&err, "Proxy error (%ld): ", code);
			err->code = code;
		}
	}

	http_headers_clean (&headers);
	curl_easy_cleanup (h);
	if (out)
		g_byte_array_unref (out);
	return err;
}

GError *
conscience_get_namespace (const char *ns, struct namespace_info_s **out)
{
	gchar *id = oio_cfg_get_proxy_conscience (ns);
	if (!id) return NEWERROR (CODE_NAMESPACE_NOTMANAGED, "NS not configured");
	STRING_STACKIFY (id);

	gchar *url = g_strconcat ("http://", id, "/v2.0/cs/", ns, NULL);
	STRING_STACKIFY (url);

	GBytes *body = NULL;
	GError *err = _proxy_request ("GET", url, NULL, &body);
	if (err) return err;

	gsize l = 0;
	const void *b = g_bytes_get_data (body, &l);
	
	struct namespace_info_s *ni = g_malloc0 (sizeof(*ni));
	namespace_info_init (ni);
	err = namespace_info_init_json ((char*)b, ni);
	g_bytes_unref (body);
	*out = ni;
	return err;
}

GError *
conscience_list_service_types (const char *ns, GSList **out)
{
	gchar *id = oio_cfg_get_proxy_conscience (ns);
	if (!id) return NEWERROR (CODE_NAMESPACE_NOTMANAGED, "NS not configured");
	STRING_STACKIFY (id);

	gchar *url = g_strconcat ("http://", id, "/v2.0/cs/", ns, "?what=types", NULL);
	STRING_STACKIFY (url);

	GBytes *body = NULL;
	GError *err = _proxy_request ("GET", url, NULL, &body);
	if (err) return err;

	GSList *list = NULL;
	gsize l = 0;
	const void *b = g_bytes_get_data (body, &l);
	struct json_tokener *parser = json_tokener_new ();
	struct json_object *jbody = json_tokener_parse_ex (parser, (char*)b, l);
	if (out) {
		if (!json_object_is_type (jbody, json_type_array))
			err = NEWERROR(CODE_BAD_REQUEST, "Invalid reply");
		else {
			for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
				json_object *item = json_object_array_get_idx (jbody, i-1);
				list = g_slist_prepend (list, g_strdup (json_object_get_string (item)));
			}
		}
	}
	json_object_put (jbody);
	json_tokener_free (parser);

	if (err)
		g_slist_free_full (list, g_free);
	else if (out)
		*out = list;
	list = NULL;

	g_bytes_unref (body);
	return err;
}

GError *
conscience_list_services (const char *ns, const char *type, gboolean full, gboolean local, GSList **out)
{
	(void) full, (void) local;

	gchar *id = oio_cfg_get_proxy_conscience (ns);
	if (!id) return NEWERROR (CODE_NAMESPACE_NOTMANAGED, "NS not configured");
	STRING_STACKIFY (id);

	gchar *url = g_strconcat ("http://", id, "/v2.0/cs/", ns, "/", type, NULL);
	STRING_STACKIFY (url);

	GBytes *body = NULL;
	GError *err = _proxy_request ("GET", url, NULL, &body);
	if (err) return err;

	GSList *list = NULL;
	gsize l = 0;
	const void *b = g_bytes_get_data (body, &l);
	if (out) {
		struct json_tokener *parser = json_tokener_new ();
		struct json_object *jbody = json_tokener_parse_ex (parser, (char*)b, l);
		if (!json_object_is_type (jbody, json_type_array))
			err = NEWERROR(CODE_BAD_REQUEST, "Invalid reply");
		else {
			for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
				json_object *item = json_object_array_get_idx (jbody, i-1);
				struct service_info_s *si = NULL;
				if (!(err = service_info_load_json_object (item, &si, TRUE)))
					list = g_slist_prepend (list, si);
			}
		}
		json_object_put (jbody);
		json_tokener_free (parser);
	}

	if (err)
		g_slist_free_full (list, (GDestroyNotify)service_info_clean);
	else if (out)
		*out = list;

	g_bytes_unref (body);
	return err;
}

GError *
conscience_clear_services (const char *ns, const char *type, GSList *ls)
{
	gchar *id = oio_cfg_get_proxy_conscience (ns);
	if (!id) return NEWERROR (CODE_NAMESPACE_NOTMANAGED, "NS not configured");
	STRING_STACKIFY (id);

	gchar *url = g_strconcat ("http://", id, "/v2.0/cs/", ns, "/", type, NULL);
	STRING_STACKIFY (url);

	GString *gs = g_string_new ("");
	if (ls) {
		for (GSList *l=ls; l ;l=l->next) {
			if (l != ls) g_string_append_c (gs, ',');
			service_info_encode_json (gs, l->data, TRUE);
		}
	}
	GBytes *in = g_string_free_to_bytes (gs);
	gs = NULL;

	GError *err = _proxy_request ("DELETE", url, in, NULL);
	g_bytes_unref (in);
	return err;
}

GError *
conscience_register_service (struct service_info_s *si)
{
	const char *ns = si->ns_name;
	const char *type = si->type;

	gchar *id = oio_cfg_get_proxy_conscience (ns);
	if (!id) return NEWERROR (CODE_NAMESPACE_NOTMANAGED, "NS not configured");
	STRING_STACKIFY (id);

	gchar *url = g_strconcat ("http://", id, "/v2.0/cs/", ns, "/", type, NULL);
	STRING_STACKIFY (url);

	GString *gs = g_string_new ("");
	service_info_encode_json (gs, si, TRUE);
	GBytes *in = g_string_free_to_bytes (gs);
	gs = NULL;

	GError *err = _proxy_request ("PUT", url, in, NULL);
	g_bytes_unref (in);
	return err;
}

