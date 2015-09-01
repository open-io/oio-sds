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

GString *
_create_status (gint code, const gchar * msg)
{
	GString *gstr = g_string_sized_new (256);
	g_string_append_c (gstr, '{');
	g_string_append_printf (gstr, "\"status\":%d,\"message\":\"%s\"", code, msg);
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
_reply_json (struct req_args_s *args, int code, const gchar * msg,
	GString * gstr)
{
	args->rp->set_status (code, msg);
	if (gstr) {
		if (gstr->len > 0)
			args->rp->set_content_type ("application/json");
		args->rp->set_body_gstr (gstr);
	} else {
		args->rp->set_body (NULL, 0);
	}
	args->rp->finalize ();
	return HTTPRC_DONE;
}

enum http_rc_e
_reply_format_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_BAD_REQUEST, "Bad request", _create_status_error (err));
}

enum http_rc_e
_reply_system_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_INTERNAL_ERROR, "Internal error", _create_status_error (err));
}

enum http_rc_e
_reply_bad_gateway (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_BAD_GATEWAY, "Bad Gateway", _create_status_error (err));
}

enum http_rc_e
_reply_not_implemented (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_NOT_IMPLEMENTED, "Not implemented",
			_create_status_error (NEWERROR(CODE_NOT_IMPLEMENTED, "NYI")));
}

enum http_rc_e
_reply_notfound_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_NOT_FOUND, "Not found", _create_status_error (err));
}

enum http_rc_e
_reply_forbidden_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_FORBIDDEN, "Forbidden", _create_status_error (err));
}

enum http_rc_e
_reply_method_error (struct req_args_s *args)
{
	return _reply_json (args, HTTP_CODE_METHOD_NOT_ALLOWED, "Method not allowed", NULL);
}

enum http_rc_e
_reply_conflict_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_CONFLICT, "Conflict", _create_status_error (err));
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
_reply_success_json (struct req_args_s *args, GString * gstr)
{
	int code = gstr && gstr->len > 0 ? HTTP_CODE_OK : HTTP_CODE_NO_CONTENT;
	const gchar *msg = gstr && gstr->len > 0 ? "OK" : "No Content";
	return _reply_json (args, code, msg, gstr);
}

