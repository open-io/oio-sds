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

#include "common.h"

void
_append_status (GString *out, gint code, const char * msg)
{
	EXTRA_ASSERT (out != NULL);
	oio_str_gstring_append_json_pair_int(out, "status", code);
	g_string_append_c (out, ',');
	oio_str_gstring_append_json_pair (out, "message", msg);
}

GString *
_create_status (gint code, const gchar * msg)
{
	GString *gstr = g_string_sized_new (256);
	g_string_append_c (gstr, '{');
	_append_status (gstr, code, msg);
	g_string_append_c (gstr, '}');
	return gstr;
}

GString *
_create_status_error (GError * e)
{
	GString *gstr;
	if (e) {
		gstr = _create_status (e->code, e->message);
		g_error_free (e);
	} else {
		gstr = _create_status (CODE_INTERNAL_ERROR, "unknown error");
	}
	return gstr;
}

enum http_rc_e
_reply_common_error (struct req_args_s *args, GError *err)
{
	if (CODE_IS_NOTFOUND(err->code))
		return _reply_notfound_error (args, err);
	if (err->code == CODE_BAD_REQUEST)
		return _reply_format_error (args, err);
	return _reply_system_error (args, err);
}

enum http_rc_e
_reply_bytes (struct req_args_s *args, int code, const gchar * msg,
		GBytes * bytes)
{
	args->rp->set_status (code, msg);
	if (bytes) {
		if (g_bytes_get_size (bytes) > 0) {
			args->rp->set_content_type ("application/json");
			args->rp->set_body_bytes (bytes);
		} else {
			g_bytes_unref (bytes);
			args->rp->set_body_bytes (NULL);
		}
	} else {
		args->rp->set_body_bytes (NULL);
	}
	args->rp->finalize ();
	return HTTPRC_DONE;
}

enum http_rc_e
_reply_json (struct req_args_s *args, int code, const gchar * msg,
	GString * gstr)
{
	return _reply_bytes (args, code, msg,
			gstr ? g_string_free_to_bytes (gstr) : NULL);
}

enum http_rc_e
_reply_format_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_BAD_REQUEST,
			"Bad request", _create_status_error (err));
}

enum http_rc_e
_reply_system_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_INTERNAL_ERROR,
			"Internal error", _create_status_error (err));
}

enum http_rc_e
_reply_bad_gateway (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_BAD_GATEWAY,
			"Bad Gateway", _create_status_error (err));
}

enum http_rc_e
_reply_srv_unavailable (struct req_args_s *args, GError *err)
{
	return _reply_json (args, HTTP_CODE_SRV_UNAVAILABLE,
			"Service unavailable", _create_status_error (err));
}

enum http_rc_e
_reply_gateway_timeout (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_GATEWAY_TIMEOUT,
			"Gateway timeout", _create_status_error (err));
}

enum http_rc_e
_reply_not_implemented (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_NOT_IMPLEMENTED,
			"Not implemented", _create_status_error (NYI()));
}

enum http_rc_e
_reply_notfound_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_NOT_FOUND,
			"Not found", _create_status_error (err));
}

enum http_rc_e
_reply_forbidden_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_FORBIDDEN,
			"Forbidden", _create_status_error (err));
}

enum http_rc_e
_reply_method_error (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_METHOD_NOT_ALLOWED,
			"Method not allowed", NULL);
}

enum http_rc_e
_reply_conflict_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_CONFLICT,
			"Conflict", _create_status_error (err));
}

enum http_rc_e
_reply_nocontent (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_NO_CONTENT, "No Content", NULL);
}

enum http_rc_e
_reply_accepted (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_ACCEPTED, "Already Accepted", NULL);
}

enum http_rc_e
_reply_created (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_CREATED, "Created", NULL);
}

enum http_rc_e
_reply_success_bytes (struct req_args_s *args, GBytes *bytes)
{
	gsize l = 0;
	gconstpointer b = bytes ? g_bytes_get_data (bytes, &l) : NULL;

	const int code = b && l ? HTTP_CODE_OK : HTTP_CODE_NO_CONTENT;
	const char *msg = b && l ? "OK" : "No Content";
	return _reply_bytes (args, code, msg, bytes);
}

enum http_rc_e
_reply_success_json (struct req_args_s *args, GString * gstr)
{
	int code = gstr && gstr->len > 0 ? HTTP_CODE_OK : HTTP_CODE_NO_CONTENT;
	const gchar *msg = gstr && gstr->len > 0 ? "OK" : "No Content";
	return _reply_json (args, code, msg, gstr);
}

