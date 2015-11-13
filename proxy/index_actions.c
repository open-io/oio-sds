/*
OpenIO SDS proxy
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

#include <curl/curl.h>

#include "common.h"
#include "actions.h"

static enum http_rc_e
_rest_rdir_fetch (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _reply_not_implemented (args);
}

enum http_rc_e
action_rdir_fetch (struct req_args_s *args)
{
	return rest_action (args, _rest_rdir_fetch);
}

struct view_GString_s
{
	GString *data;
	size_t done;
};

/* TODO FIXME duplicated from core/sds.c */
static size_t
_read_GString(void *b, size_t s, size_t n, struct view_GString_s *in)
{
	size_t remaining = in->data->len - in->done;
	size_t available = s * n;
	size_t len = MIN(remaining,available);
	if (len) {
		memcpy(b, in->data->str, len);
		in->done += len;
	}
	return len;
}

static GError *
_curl_send (const char *http_method, GString *url, GString *body)
{
	struct view_GString_s view_input = {.data=body, .done=0};
	GError *err = NULL;

	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_PROXY, NULL);
	curl_easy_setopt (h, CURLOPT_URL, url->str);
	curl_easy_setopt (h, CURLOPT_CUSTOMREQUEST, http_method);
	curl_easy_setopt (h, CURLOPT_READFUNCTION, _read_GString);
	curl_easy_setopt (h, CURLOPT_READDATA, &view_input);
	curl_easy_setopt (h, CURLOPT_INFILESIZE_LARGE, body->len);
	curl_easy_setopt (h, CURLOPT_UPLOAD, 1L);

	struct curl_slist *headers = NULL;
	headers = curl_slist_append (headers, "Content-type: application/json");
	headers = curl_slist_append (headers, "Expect:");
	curl_easy_setopt (h, CURLOPT_HTTPHEADER, headers);

	CURLcode rc = curl_easy_perform (h);
	if (rc != CURLE_OK) {
		err = NEWERROR(0, "http error: (%d) %s", rc, curl_easy_strerror(rc));
	} else {
		long code = 0;
		rc = curl_easy_getinfo (h, CURLINFO_RESPONSE_CODE, &code);
		if (2 != (code/100))
			err = NEWERROR(0, "service error: (%ld)", code);
	}

	curl_slist_free_all (headers);
	curl_easy_cleanup (h);
	return err;
}

static GError *
_remote_push (const char *to, const char *volname, GString *body)
{
	GError *err = NULL;

	GString *url = g_string_new("http://");
	g_string_append_printf (url, "%s/%s/rdir/push?vol=%s",
			to, nsname, volname);

	err = _curl_send ("POST", url, body);

	g_string_free(url, TRUE);
	return err;
}

static enum http_rc_e
_rest_rdir_push (struct req_args_s *args, struct json_object *jargs)
{
	if (!jargs || !json_object_is_type (jargs, json_type_object))
		return _reply_common_error (args, BADREQ("Expected: json object"));

	GError *err = NULL;

	const char *vol = OPT("vol");
	if (!vol)
		return _reply_format_error (args, BADREQ("Missing volume"));
	struct json_object *jchunk, *jcontent, *jcontainer;
	struct oio_ext_json_mapping_s m[] = {
		{"chunk", &jchunk, json_type_string, 1},
		{"content", &jcontent, json_type_string, 1},
		{"container", &jcontainer, json_type_string, 1},
		/* TODO also unpack additional fields, e.g. a payload */
		{NULL, NULL, 0, 0},
	};
	if (NULL != (err = oio_ext_extract_json (jargs, m)))
		return _reply_format_error (args, BADREQ("Invalid JSON body"));

	struct oio_url_s *volurl = oio_url_empty ();
	oio_url_set (volurl, OIOURL_NS, nsname);
	oio_url_set (volurl, OIOURL_ACCOUNT, NAME_ACCOUNT_RDIR);
	oio_url_set (volurl, OIOURL_USER, vol);

	gboolean autocreate = _request_has_flag (args, PROXYD_HEADER_MODE, "autocreate");

	GError *hook (struct meta1_service_url_s *idx, gboolean *next) {
		GString *gs = g_string_new (json_object_to_json_string(jargs));
		GError *e = _remote_push (idx->host, vol, gs);
		g_string_free (gs, TRUE);
		*next = (e!=NULL);
		return e;
	}

retry:
	err = _resolve_service_and_do (NAME_SRVTYPE_RDIR, 0, volurl, hook);
	if (err) {
		if (CODE_IS_NOTFOUND(err->code)) {
			if (autocreate) {
				autocreate = FALSE;
				g_clear_error (&err);

				GError *hook_dir (const char *m1) {
					gchar **urlv = NULL;
					GError *e = meta1v2_remote_link_service (m1, volurl,
							NAME_SRVTYPE_RDIR, FALSE, TRUE, &urlv);
					if (urlv) g_strfreev (urlv);
					return e;
				}
				if (!(err = _m1_locate_and_action (volurl, hook_dir)))
					goto retry;
			}
		}
	}

	oio_url_pclean (&volurl);
	if (err)
		return _reply_common_error (args, err);
	return _reply_nocontent (args);
}

enum http_rc_e
action_rdir_push (struct req_args_s *args)
{
	return rest_action (args, _rest_rdir_push);
}

static GError *
_remote_delete (const char *to, const char *volname, GString *body)
{
	GError *err = NULL;

	GString *url = g_string_new("http://");
	g_string_append_printf (url, "%s/%s/rdir/delete?vol=%s",
			to, nsname, volname);

	err = _curl_send ("DELETE", url, body);

	g_string_free(url, TRUE);
	return err;
}

static enum http_rc_e
_rest_rdir_delete (struct req_args_s *args, struct json_object *jargs)
{
	if (!jargs || !json_object_is_type (jargs, json_type_object))
		return _reply_common_error (args, BADREQ("Expected: json object"));

	GError *err = NULL;

	const char *vol = OPT("vol");
	if (!vol)
		return _reply_format_error (args, BADREQ("Missing volume"));
	struct json_object *jchunk, *jcontent, *jcontainer;
	struct oio_ext_json_mapping_s m[] = {
		{"chunk", &jchunk, json_type_string, 1},
		{"content", &jcontent, json_type_string, 1},
		{"container", &jcontainer, json_type_string, 1},
		/* TODO also unpack additional fields, e.g. a payload */
		{NULL, NULL, 0, 0},
	};
	if (NULL != (err = oio_ext_extract_json (jargs, m)))
		return _reply_format_error (args, BADREQ("Invalid JSON body"));

	struct oio_url_s *volurl = oio_url_empty ();
	oio_url_set (volurl, OIOURL_NS, nsname);
	oio_url_set (volurl, OIOURL_ACCOUNT, NAME_ACCOUNT_RDIR);
	oio_url_set (volurl, OIOURL_USER, vol);

	GError *hook (struct meta1_service_url_s *idx, gboolean *next) {
		GString *gs = g_string_new (json_object_to_json_string(jargs));
		GError *e = _remote_delete (idx->host, vol, gs);
		g_string_free (gs, TRUE);
		*next = (e!=NULL);
		return e;
	}

	err = _resolve_service_and_do (NAME_SRVTYPE_RDIR, 0, volurl, hook);

	oio_url_pclean (&volurl);
	if (err)
		return _reply_common_error (args, err);
	return _reply_nocontent (args);
}
enum http_rc_e
action_rdir_delete (struct req_args_s *args)
{
	return rest_action (args, _rest_rdir_delete);
}
