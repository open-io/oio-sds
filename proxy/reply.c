/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2024 OVH SAS

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

// For strcasestr
#include <string.h>

#include "common.h"

void
_append_status (GString *out, gint code, const char * msg)
{
	EXTRA_ASSERT(out != NULL);
	OIO_JSON_append_int(out, "status", code);
	g_string_append_c(out, ',');
	OIO_JSON_append_str(out, "message", msg);
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

static enum http_rc_e
_reply_bytes(struct req_args_s *args, int code, const gchar * msg,
		const gchar *content_type, GBytes * bytes)
{
	args->rp->set_status(code, msg);
	if (bytes) {
		if (g_bytes_get_size(bytes) > 0) {
			if (content_type) {
				args->rp->set_content_type(content_type);
			} else {
				args->rp->set_content_type(HTTP_CONTENT_TYPE_BINARY);
			}
		}
		args->rp->set_body_bytes(bytes);
	} else {
		args->rp->set_body_bytes(NULL);
	}
	args->rp->finalize ();
	return HTTPRC_DONE;
}

enum http_rc_e
_reply_json(struct req_args_s *args, int code, const gchar * msg,
	GString * gstr)
{
	return _reply_bytes(args, code, msg, HTTP_CONTENT_TYPE_JSON,
			gstr ? g_string_free_to_bytes (gstr) : NULL);
}

static enum http_rc_e
_reply_json_error(struct req_args_s *args, int code, const char *msg,
	GString * gstr)
{
	GString *service_id = g_string_sized_new(256);
	GPtrArray *urlerrorv = NULL;
	urlerrorv = oio_ext_get_urlerrorv();
	if (urlerrorv && urlerrorv->len > 0) {
		for (guint i=0; i < urlerrorv->len; i++) {
			gchar *u = g_ptr_array_index(urlerrorv, i);
			g_string_append_printf(service_id, "%s%s", (i>0?",":""), u);
		}
	}
	args->rp->add_header("x-backend-service-id", service_id->str);

	if (gstr && gstr->len) {
		if (args->url && oio_url_has(args->url, OIOURL_HEXID)) {
			args->rp->access_tail(
					"error:%.*s\thexid:%s\tversion_id:%s\tservice_id:%s",
					gstr->len, gstr->str,
					oio_url_get(args->url, OIOURL_HEXID),
					oio_url_get(args->url, OIOURL_VERSION),  // possibly empty
					service_id->str
			);
		} else {
			args->rp->access_tail(
				"error:%.*s\tservice_id:%s", gstr->len, gstr->str, service_id->str
			);
		}
	}
	g_string_free(service_id, FALSE);
	return _reply_json(args, code, msg, gstr);
}

enum http_rc_e
_reply_format_error (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_BAD_REQUEST,
			"Bad request", _create_status_error (err));
}

enum http_rc_e
_reply_bad_gateway (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_BAD_GATEWAY,
			"Bad Gateway", _create_status_error (err));
}

enum http_rc_e
_reply_srv_unavailable (struct req_args_s *args, GError *err)
{
	return _reply_json_error (args, HTTP_CODE_SRV_UNAVAILABLE,
			"Service unavailable", _create_status_error (err));
}

enum http_rc_e
_reply_retry (struct req_args_s *args, GError *err)
{
	args->rp->add_header("Retry-After", g_strdup("1"));
	return _reply_srv_unavailable (args, err);
}

static enum http_rc_e
_reply_system_error (struct req_args_s *args, GError * err)
{
	return _reply_json (args, HTTP_CODE_INTERNAL_ERROR,
			"Internal error", _create_status_error (err));
}

enum http_rc_e
_reply_common_error (struct req_args_s *args, GError *err)
{
	if (CODE_IS_NOTFOUND(err->code))
		return _reply_notfound_error (args, err);
	switch (err->code) {
		case CODE_BAD_REQUEST:
			return _reply_format_error (args, err);
		// Low level codes changed to 503
		case ERRCODE_CONN_REFUSED:
		case ERRCODE_CONN_RESET:
		case ERRCODE_CONN_CLOSED:
		case ERRCODE_CONN_TIMEOUT:
		case ERRCODE_CONN_NOROUTE:
		case ERRCODE_READ_TIMEOUT:
		case CODE_AVOIDED:
		case CODE_NETWORK_ERROR:
		// High level codes changed to 503
		case CODE_TOOMANY_REDIRECT:
		case CODE_UNAVAILABLE:
		case CODE_GATEWAY_TIMEOUT:  // returned by server
		case CODE_EXCESSIVE_LOAD:  // returned by sqliterepo
		case CODE_CORRUPT_DATABASE:
		case CODE_CONTAINER_FROZEN:
		// There are more chances that we temporarily lack available services
		// than there is a misconfiguration, hence the code 503.
		case CODE_POLICY_NOT_SATISFIABLE:
			return _reply_retry(args, err);
		case CODE_NAMESPACE_NOTMANAGED:
		case CODE_SRVTYPE_NOTMANAGED:
			return _reply_notfound_error(args, err);
		case CODE_CONTAINER_EXISTS:
		case CODE_CONTENT_EXISTS:
		case CODE_CONTENT_PRECONDITION:
			return _reply_conflict_error(args, err);
		case CODE_NOT_ALLOWED:
		case CODE_CONTAINER_DRAINING:
			return _reply_forbidden_error(args, err);
		case CODE_METHOD_NOTALLOWED:
			return _reply_method_error(args, err, NULL);
		case CODE_POLICY_NOT_SUPPORTED:
			return _reply_format_error(args, err);
	}

	return _reply_system_error (args, err);
}

enum http_rc_e
_reply_gateway_timeout (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_GATEWAY_TIMEOUT,
			"Gateway timeout", _create_status_error (err));
}

enum http_rc_e
_reply_notfound_error (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_NOT_FOUND,
			"Not found", _create_status_error (err));
}

enum http_rc_e
_reply_forbidden_error (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_FORBIDDEN,
			"Forbidden", _create_status_error (err));
}

enum http_rc_e
_reply_method_error (struct req_args_s *args, GError *err, char *allowed)
{
	if (!allowed && err && strcasestr(err->message, "worm")) {
		// Namespace in WORM mode, do not allow DELETE
		allowed = "GET, HEAD, PUT";
	}
	// RFC 7231 requires the Allow header, but say it can be empty
	EXTRA_ASSERT(allowed != NULL);
	args->rp->add_header("Allow", g_strdup(allowed));
	return _reply_json_error(args, HTTP_CODE_METHOD_NOT_ALLOWED,
			"Method not allowed", _create_status_error(err));
}

enum http_rc_e
_reply_conflict_error (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_CONFLICT,
			"Conflict", _create_status_error (err));
}

enum http_rc_e
_reply_gone_error(struct req_args_s *args, GError *err)
{
	return _reply_json_error(args, HTTP_CODE_GONE,
			"Gone", _create_status_error(err));
}

enum http_rc_e
_reply_too_large (struct req_args_s *args, GError * err)
{
	return _reply_json_error (args, HTTP_CODE_PAYLOAD_TO_LARGE,
			"Payload too large", _create_status_error (err));
}

enum http_rc_e
_reply_nocontent (struct req_args_s *args)
{
	return _reply_json_error (args, HTTP_CODE_NO_CONTENT, "No Content", NULL);
}

enum http_rc_e
_reply_accepted (struct req_args_s *args)
{
	return _reply_json_error (args, HTTP_CODE_ACCEPTED, "Already Accepted", NULL);
}

enum http_rc_e
_reply_created (struct req_args_s *args)
{
	return _reply_json_error (args, HTTP_CODE_CREATED, "Created", NULL);
}

enum http_rc_e
_reply_success_bytes(struct req_args_s *args, const gchar *content_type,
		GBytes *bytes)
{
	gsize l = 0;
	gconstpointer b = bytes ? g_bytes_get_data(bytes, &l) : NULL;

	const int code = b && l ? HTTP_CODE_OK : HTTP_CODE_NO_CONTENT;
	const char *msg = b && l ? "OK" : "No Content";
	return _reply_bytes(args, code, msg, content_type, bytes);
}

enum http_rc_e
_reply_success_json (struct req_args_s *args, GString * gstr)
{
	int code = gstr && gstr->len > 0 ? HTTP_CODE_OK : HTTP_CODE_NO_CONTENT;
	const gchar *msg = gstr && gstr->len > 0 ? "OK" : "No Content";
	return _reply_json (args, code, msg, gstr);
}
