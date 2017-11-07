/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <sqliterepo/sqlx_macros.h>

#include "common.h"
#include "actions.h"

enum http_rc_e
action_forward_stats (struct req_args_s *args)
{
	const char *id = OPT("id");
	if (!id)
		return _reply_format_error (args, BADREQ("Missing SRVID"));

	args->rp->no_access();

	MESSAGE req = metautils_message_create_named("REQ_STATS",
			oio_clamp_deadline(proxy_timeout_stat, oio_ext_get_deadline()));
	GByteArray *encoded = message_marshall_gba_and_clean (req);
	gchar *packed = NULL;
	GError *err = gridd_client_exec_and_concat_string(id,
			oio_clamp_timeout(proxy_timeout_stat, oio_ext_get_deadline()),
			encoded, &packed);
	if (err) {
		g_free0 (packed);
		if (CODE_IS_NETWORK_ERROR(err->code)) {
			if (err->code == ERRCODE_CONN_TIMEOUT || err->code == ERRCODE_READ_TIMEOUT)
				return _reply_gateway_timeout (args, err);
			return _reply_srv_unavailable (args, err);
		}
		return _reply_common_error (args, err);
	}

	for (gchar *s=packed; *s ;++s) { if (*s == '=') *s = ' '; }

	return _reply_success_bytes (
			args, g_bytes_new_take((guint8*)packed, strlen(packed)));
}

enum http_rc_e
action_cache_flush_local (struct req_args_s *args)
{
	oio_lb_world__flush(lb_world);
	hc_resolver_flush_csm0 (resolver);
	hc_resolver_flush_services (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_flush_low (struct req_args_s *args)
{
	hc_resolver_flush_services (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_flush_high (struct req_args_s *args)
{
	hc_resolver_flush_csm0 (resolver);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_cache_status (struct req_args_s *args)
{
	struct hc_resolver_stats_s s = {{0}};
	hc_resolver_info (resolver, &s);

	GString *gstr = g_string_sized_new (256);
	g_string_append_c (gstr, '{');
	g_string_append_printf (gstr, " \"csm0\":{"
		"\"count\":%" G_GINT64_FORMAT ",\"max\":%u,\"ttl\":%lu},",
		s.csm0.count, s.csm0.max, s.csm0.ttl);
	g_string_append_printf (gstr, " \"meta1\":{"
		"\"count\":%" G_GINT64_FORMAT ",\"max\":%u,\"ttl\":%lu}",
		s.services.count, s.services.max, s.services.ttl);
	g_string_append_c (gstr, '}');
	return _reply_success_json (args, gstr);
}

enum http_rc_e
action_get_config (struct req_args_s *args)
{
	args->rp->no_access();
	return _reply_success_json (args, oio_var_list_as_json());
}

static enum http_rc_e
_set_config (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_object))
		return _reply_format_error (args, BADREQ("Object argument expected"));
	if (json_object_object_length(jargs) <= 0)
		return _reply_format_error (args, BADREQ("Empty object argument"));
	json_object_object_foreach(jargs, k, jv) {
		oio_var_value_one(k, json_object_get_string(jv));
	}
	return _reply_success_json(args, NULL);
}

enum http_rc_e
action_set_config (struct req_args_s *args)
{
	args->rp->no_access();
	return rest_action(args, _set_config);
}

enum http_rc_e
action_forward_set_config (struct req_args_s *args)
{
	args->rp->no_access();

	const char *id = OPT("id");
	if (!id)
		return _reply_format_error (args, BADREQ("Missing SRVID"));
	if (!args->rq->body)
		return _reply_format_error (args, BADREQ("Missing body"));

	MESSAGE req = metautils_message_create_named("REQ_SETCFG",
			oio_clamp_deadline(proxy_timeout_config, oio_ext_get_deadline()));
	metautils_message_set_BODY(req, args->rq->body->data, args->rq->body->len);
	GByteArray *encoded = message_marshall_gba_and_clean (req);
	GError *err = gridd_client_exec(id,
			oio_clamp_timeout(proxy_timeout_config, oio_ext_get_deadline()),
			encoded);
	if (err) {
		if (CODE_IS_NETWORK_ERROR(err->code)) {
			if (err->code == ERRCODE_CONN_TIMEOUT || err->code == ERRCODE_READ_TIMEOUT)
				return _reply_gateway_timeout (args, err);
			return _reply_srv_unavailable (args, err);
		}
		return _reply_common_error (args, err);
	}

	return _reply_success_json(args, NULL);
}

static enum http_rc_e
_forward_XXX (struct req_args_s *args, const char *reqname, gdouble timeout)
{
	args->rp->no_access();

	const char *id = OPT("id");
	if (!id)
		return _reply_format_error (args, BADREQ("Missing SRVID"));

	MESSAGE req = metautils_message_create_named(reqname,
			oio_clamp_deadline(timeout, oio_ext_get_deadline()));
	GByteArray *encoded = message_marshall_gba_and_clean(req);
	gchar *packed = NULL;
	GError *err = gridd_client_exec_and_concat_string(id,
			oio_clamp_timeout(timeout, oio_ext_get_deadline()),
			encoded, &packed);
	if (err) {
		g_free0 (packed);
		if (CODE_IS_NETWORK_ERROR(err->code)) {
			if (err->code == ERRCODE_CONN_TIMEOUT || err->code == ERRCODE_READ_TIMEOUT)
				return _reply_gateway_timeout (args, err);
			return _reply_srv_unavailable (args, err);
		}
		return _reply_common_error (args, err);
	}

	return _reply_success_bytes (
			args, g_bytes_new_take((guint8*)packed, strlen(packed)));
}


enum http_rc_e
action_forward_get_config (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_GETCFG", proxy_timeout_config);
}

enum http_rc_e
action_forward_get_version (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_VERSION", proxy_timeout_info);
}

enum http_rc_e
action_forward_get_handlers (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_HANDLERS", proxy_timeout_common);
}

enum http_rc_e
action_forward_get_ping (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_PING", proxy_timeout_common);
}

enum http_rc_e
action_forward_get_info (struct req_args_s *args)
{
	return _forward_XXX(args, NAME_MSGNAME_SQLX_INFO, proxy_timeout_info);
}

enum http_rc_e
action_forward_kill (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_KILL", proxy_timeout_common);
}

enum http_rc_e
action_forward_flush (struct req_args_s *args)
{
	return _forward_XXX(args, NAME_MSGNAME_SQLX_FLUSH, proxy_timeout_common);
}

enum http_rc_e
action_forward_reload (struct req_args_s *args)
{
	return _forward_XXX(args, NAME_MSGNAME_SQLX_RELOAD, proxy_timeout_common);
}

enum http_rc_e
action_forward_lean_sqlx (struct req_args_s *args)
{
	return _forward_XXX(args, NAME_MSGNAME_SQLX_LEANIFY, proxy_timeout_common);
}

enum http_rc_e
action_forward_lean_glib (struct req_args_s *args)
{
	return _forward_XXX(args, "REQ_LEAN", proxy_timeout_common);
}

