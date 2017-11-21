/*
OpenIO SDS proxy
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

	GString *out = g_string_sized_new (256);
	g_string_append_c(out, '{');

	/* Pack the output */
	if (ctx->which == CLIENT_RUN_ALL && ctx->count) {
		gboolean first = TRUE;
		for (guint i=0; i<ctx->count ;++i) {
			COMA(out,first);
			g_string_append_printf (out, "\"%s\":{", ctx->urlv[i]);
			if (ctx->errorv[i]) {
				GError *e = ctx->errorv[i];
				g_string_append_static (out, "\"status\":{");
				_append_status (out, e->code, e->message);
				g_string_append_c (out, '}');
			}
			if (ctx->bodyv[i]) {
				GByteArray *b = ctx->bodyv[i];
				g_string_append_static (out, ",\"body\":");
				if (b && b->data && b->len)
					g_string_append_len (out, (const char*)(b->data), b->len);
				else
					g_string_append_static (out, "\"\"");
			} else {
				g_string_append_static (out, ",\"body\":null");
			}
			g_string_append_c (out, '}');
		}
	}
	g_string_append_c (out, '}');

	return _reply_success_json (args, out);
}

static enum http_rc_e
_sqlx_action_noreturn (struct req_args_s *args, enum proxy_preference_e how,
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
	enum http_rc_e rc = _sqlx_action_noreturn_TAIL (args, &ctx, pack);
	client_clean(&ctx);
	return rc;
}

/* ---------------------------------------------------------------------------*/

static gchar **
_load_stringv (struct json_object *jargs)
{
	if (!json_object_is_type (jargs, json_type_array))
		return NULL;
	const guint max = json_object_array_length (jargs);
	GPtrArray *tmp = g_ptr_array_sized_new(max);
	for (guint i=max; i>0 ;i--) {
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
	if (!json_object_is_type(jargs, json_type_object))
		return _reply_format_error(args,
				BADREQ("Action argument must be an object"));

	struct json_object *jto = NULL, *jfrom = NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"to",   &jto,  json_type_string, 1},
		{"from", &jfrom, json_type_string, 0},
		{NULL, NULL, 0, 0},
	};

	GError *err = oio_ext_extract_json(jargs, mapping);
	if (err)
		return _reply_format_error(args, err);

	const gchar *to = json_object_get_string(jto);
	if (!metautils_url_valid_for_connect(to))
		return _reply_format_error(args, BADREQ("Invalid target URL"));
	const gchar *from = NULL;
	if (jfrom) {
		from = json_object_get_string(jfrom);
		if (!metautils_url_valid_for_connect(to))
			return _reply_format_error(args, BADREQ("Invalid source URL"));
	}

	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype(type, dirtype, sizeof(dirtype));

	gint64 seq = 1;
	enum http_rc_e rc;
	CLIENT_CTX(ctx, args, dirtype, seq);
	if (!from) {
		/* No source, locate services from directory and use DB_PIPETO. */
		ctx.which = CLIENT_PREFER_MASTER;
		GByteArray * _pack(const struct sqlx_name_s *n) {
			return sqlx_pack_PIPETO(n, to, DL());
		}
		rc = _sqlx_action_noreturn_TAIL(args, &ctx, _pack);
	} else {
		/* Source service provided, use DB_PIPEFROM. */
		NAME2CONST(n, ctx.name);
		GByteArray *encoded = sqlx_pack_PIPEFROM(&n, from, DL());
		err = gridd_client_exec(to,
				oio_clamp_timeout(proxy_timeout_common, oio_ext_get_deadline()),
				encoded);
		if (err) {
			rc = _reply_common_error(args, err);
		} else {
			rc = _reply_success_json(args, NULL);
		}
	}

	client_clean(&ctx);
	return rc;
}

enum http_rc_e
action_sqlx_propset (struct req_args_s *args, struct json_object *jargs)
{
	enum http_rc_e rc = HTTPRC_ABORT;

	gchar **kv = NULL;
	GError *err = KV_read_usersys_properties(jargs, &kv);
	if (!err && !*kv)
		err = BADREQ("No properties found in JSON object");
	if (!err) {
		gboolean flush = _request_get_flag(args, "flush");
		GByteArray * _pack (const struct sqlx_name_s *n) {
			return sqlx_pack_PROPSET_tab(n, flush, kv, DL());
		}
		rc = _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, _pack);
	} else {
		rc = _reply_common_error (args, err);
	}
	if (kv)
		g_strfreev(kv);
	return rc;
}

enum http_rc_e
action_sqlx_propget (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	(void) jargs;

	/* Query the services */
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));

	gint64 seq = 1;
	CLIENT_CTX(ctx, args, dirtype, seq);

	PACKER_VOID(_pack) { return sqlx_pack_PROPGET(_u, DL()); }
	err = gridd_request_replicated (&ctx, _pack);

	if (err) {
		client_clean (&ctx);
		return _reply_common_error (args, err);
	}

	/* Decode the output of the first service that replied */
	gchar **pairs = NULL;
	for (guint i=0; i<ctx.count && !err && !pairs ;++i) {
		GError *e = ctx.errorv[i];
		GByteArray *gba = ctx.bodyv[i];
		if (e && e->code != CODE_FINAL_OK)
			continue;
		if (gba && gba->data && gba->len)
			err = KV_decode_buffer(gba->data, gba->len, &pairs);
	}

	/* avoid a memleak and ensure a result, even if empty */
	if (err) {
		/* TODO(jfs): maybe a good place for an assert */
		if (pairs) g_strfreev(pairs);
		return _reply_common_error(args, err);
	}
	if (!pairs) {
		pairs = g_malloc0(sizeof(void*));
		GRID_WARN("BUG the request for properties failed without error");
	}

	gchar **user = KV_extract_prefixed(pairs, SQLX_ADMIN_PREFIX_USER);
	gchar **nonuser = KV_extract_not_prefixed(pairs, SQLX_ADMIN_PREFIX_USER);

	GString *out = g_string_sized_new(512);
	g_string_append_static(out, "{\"properties\":");
	KV_encode_gstr2(out, user);
	g_string_append_static(out, ",\"system\":");
	KV_encode_gstr2(out, nonuser);
	g_string_append_c(out, '}');

	g_free(user);
	g_free(nonuser);
	g_strfreev(pairs);

	client_clean (&ctx);
	return _reply_success_json (args, out);
}

enum http_rc_e
action_sqlx_propdel (struct req_args_s *args, struct json_object *jargs)
{
	gchar **namev = _load_stringv (jargs);
	if (!namev)
		return _reply_format_error (args, BADREQ("Bad names"));

	for (gchar **p = namev; namev && *p; p++)
		oio_str_reuse(p, g_strconcat("user.", *p, NULL));

	GByteArray * _pack(const struct sqlx_name_s *n) {
		return sqlx_pack_PROPDEL (n, (const gchar * const * )namev, DL());
	}
	enum http_rc_e rc = _sqlx_action_noreturn (args, CLIENT_PREFER_MASTER, _pack);
	g_strfreev (namev);
	return rc;
}

enum http_rc_e
action_admin_ping (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_USE (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_status (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_STATUS (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_info (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_INFO (DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_drop_cache (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_LEANIFY (DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_sync (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_RESYNC (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_leave (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_EXITELECTION (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_debug (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_DESCR (_u, DL()); }
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
	PACKER_VOID(_pack) { return sqlx_pack_FREEZE(_u, DL()); }
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, _pack);
}

enum http_rc_e
action_admin_enable (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_ENABLE(_u, DL()); }
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, _pack);
}

enum http_rc_e
action_admin_disable (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return sqlx_pack_DISABLE(_u, DL()); }
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, _pack);
}
