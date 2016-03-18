/*
OpenIO SDS proxy
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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
#include "actions.h"

static void
_get_sqlx_dirtype (const char *t, gchar *d, gsize dlen)
{
	if (!strcmp(t, NAME_SRVTYPE_META0) || !strcmp(t, NAME_SRVTYPE_META1)) {
		*d = '#';
		g_strlcpy (d+1, t, dlen-1);
	} else {
		g_strlcpy (d, t, dlen);
	}
}

static enum http_rc_e
_sqlx_action_noreturn_TAIL (struct req_args_s *args, struct client_ctx_s *ctx,
		request_packer_f pack)
{
	GError *err = gridd_request_replicated (ctx, pack);

	if (err) {
		client_clean (ctx);
		return _reply_common_error (args, err);
	}

	GString *out = g_string_new ("{");

	/* Pack the output */
	if (ctx->which == CLIENT_RUN_ALL && ctx->count) {
		gboolean first = TRUE;
		for (guint i=0; i<ctx->count ;++i) {
			COMA(out,first);
			g_string_append_printf (out, "\"%s\":{", ctx->urlv[i]);
			if (ctx->errorv[i]) {
				GError *e = ctx->errorv[i];
				g_string_append (out, "\"status\":{");
				_append_status (out, e->code, e->message);
				g_string_append (out, "}");
			}
			if (ctx->bodyv[i]) {
				GByteArray *b = ctx->bodyv[i];
				g_string_append_printf (out, ",\"body\":");
				g_string_append_len (out, (const char*)(b->data), b->len);
			} else {
				g_string_append_printf (out, ",\"body\":null");
			}
			g_string_append_c (out, '}');
		}
	}
	g_string_append_c (out, '}');

	return _reply_success_json (args, out);
}

static enum http_rc_e
_sqlx_action_noreturn (struct req_args_s *args, enum preference_e how,
		request_packer_f pack)
{
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));

	gint64 seq = 1;

	CLIENT_CTX (ctx, args, dirtype, seq);
	ctx.which = how;
	return _sqlx_action_noreturn_TAIL (args, &ctx, pack);
}

/* ---------------------------------------------------------------------------*/

static gchar **
_load_stringv (struct json_object *jargs)
{
	if (!json_object_is_type (jargs, json_type_array))
		return NULL;
	int max = json_object_array_length (jargs);
	GPtrArray *tmp = g_ptr_array_sized_new(max);
	for (int i=max; i>0 ;i--) {
		struct json_object *item = json_object_array_get_idx (jargs, i-1);
		if (!json_object_is_type (item, json_type_string)) {
			g_ptr_array_set_free_func (tmp, g_free0);
			g_ptr_array_free (tmp, TRUE);
			return NULL;
		}
		g_ptr_array_add (tmp, g_strdup(json_object_get_string(item)));
	}
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

/* ---------------------------------------------------------------------------*/

enum http_rc_e
action_sqlx_copyto (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_string))
		return _reply_format_error (args, BADREQ("Action argument must be a string"));

	const gchar *to = json_object_get_string (jargs);
	if (!metautils_url_valid_for_connect(to))
		return _reply_format_error (args, BADREQ("Invalid target URL"));

	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));

	gint64 seq = 1;

	CLIENT_CTX (ctx, args, dirtype, seq);
	ctx.which = CLIENT_PREFER_MASTER;
	PACKER(_pack) { return sqlx_pack_PIPEFROM(n, to); }

	return _sqlx_action_noreturn_TAIL (args, &ctx, _pack);
}

enum http_rc_e
action_sqlx_propset (struct req_args_s *args, struct json_object *jargs)
{
	enum http_rc_e rc;
	GError *err = NULL;
	GSList *pairs = NULL;

	if (jargs) {
		if (!json_object_is_type (jargs, json_type_object))
			return _reply_format_error (args, BADREQ("Invalid pairs"));
		json_object_object_foreach(jargs,sk,jv) {
			if (json_object_is_type (jv, json_type_string)) {
				struct key_value_pair_s *kv = key_value_pair_create (sk,
						(guint8*) json_object_get_string(jv), json_object_get_string_len(jv));
				pairs = g_slist_prepend (pairs, kv);
			} else if (json_object_is_type (jv, json_type_null)) {
				struct key_value_pair_s *kv = key_value_pair_create (sk, NULL, 0);
				pairs = g_slist_prepend (pairs, kv);
			} else {
				err = BADREQ("Invalid value for [%s]", sk);
				break;
			}
		}
	}

	if (!err) {
		gboolean flush = NULL != OPT("flush");
		PACKER(_pack) { return sqlx_pack_PROPSET_pairs (n, flush, pairs); }
		rc = _sqlx_action_noreturn (args, CLIENT_PREFER_MASTER, _pack);
	} else {
		rc = _reply_common_error (args, err);
	}
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return rc;
}

enum http_rc_e
action_sqlx_propget (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	(void) jargs;

	// Query the services
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));

	gint64 seq = 1;
	CLIENT_CTX(ctx, args, dirtype, seq);

	PACKER(_pack) { return sqlx_pack_PROPGET (n); }
	err = gridd_request_replicated (&ctx, _pack);

	if (err) {
		client_clean (&ctx);
		return _reply_common_error (args, err);
	}

	// Decode the output of the services
	GSList *pairs = NULL;
	err = metautils_unpack_bodyv (ctx.bodyv, &pairs, key_value_pairs_unmarshall);
	if (err) {
		g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
		return _reply_system_error(args, err);
	}

	GString *out = g_string_new ("{");
	for (GSList *l=pairs; l ;l=l->next) {
		if (out->len > 1)
			g_string_append_c (out, ',');
		struct key_value_pair_s *kv = l->data;
		if (!kv)
			continue;
		if (!kv->value)
			g_string_append_printf (out, "\"%s\":null", kv->key);
		else {
			g_string_append_printf(out, "\"%s\":\"", kv->key);
			oio_str_gstring_append_json_blob(out,
					(const char*)kv->value->data, kv->value->len);
			g_string_append_c(out, '"');
		}
	}
	g_string_append_c (out, '}');

	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	client_clean (&ctx);
	return _reply_success_json (args, out);
}

enum http_rc_e
action_sqlx_propdel (struct req_args_s *args, struct json_object *jargs)
{
	gchar **namev = _load_stringv (jargs);
	if (!namev)
		return _reply_format_error (args, BADREQ("Bad names"));

	PACKER(packer) { return sqlx_pack_PROPDEL (n, (const gchar * const * )namev); }
	enum http_rc_e rc = _sqlx_action_noreturn (args, CLIENT_PREFER_MASTER, packer);
	g_strfreev (namev);
	return rc;
}

enum http_rc_e
action_admin_ping (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, sqlx_pack_USE);
}

enum http_rc_e
action_admin_status (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, sqlx_pack_STATUS);
}

enum http_rc_e
action_admin_info (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_INFO (); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_drop_cache (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_LEANIFY (); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_sync (struct req_args_s *args)
{
	PACKER(_pack) { return sqlx_pack_RESYNC (n); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_leave (struct req_args_s *args)
{
	PACKER(_pack) { return sqlx_pack_EXITELECTION (n); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_debug (struct req_args_s *args)
{
	PACKER(_pack) { return sqlx_pack_DESCR (n); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_copy (struct req_args_s *args)
{
	return rest_action (args, action_sqlx_copyto);
}

enum http_rc_e
action_admin_prop_get (struct req_args_s *args)
{
	return rest_action (args, action_sqlx_propget);
}

enum http_rc_e
action_admin_prop_set (struct req_args_s *args)
{
	return rest_action (args, action_sqlx_propset);
}

enum http_rc_e
action_admin_prop_del (struct req_args_s *args)
{
	return rest_action (args, action_sqlx_propdel);
}

enum http_rc_e
action_admin_freeze (struct req_args_s *args)
{
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, sqlx_pack_FREEZE);
}

enum http_rc_e
action_admin_enable (struct req_args_s *args)
{
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, sqlx_pack_ENABLE);
}

enum http_rc_e
action_admin_disable (struct req_args_s *args)
{
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, sqlx_pack_DISABLE);
}
