/*
OpenIO SDS proxy
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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
	GError *err = gridd_request_replicated_with_retry(args, ctx, pack);
	if (err) {
		client_clean (ctx);
		return _reply_common_error (args, err);
	}

	GString *out = g_string_sized_new (256);
	g_string_append_c(out, '{');

	/* Pack the output */
	if ((ctx->which == CLIENT_RUN_ALL || ctx->which == CLIENT_SPECIFIED)
			&& ctx->count) {
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

	CLIENT_CTX2(ctx, args, dirtype, seq, SUFFIX(), how, NULL, NULL);

	if (*dirtype == '#' && !strcmp(dirtype+1, NAME_SRVTYPE_META1)) {
		const guint nb_digits = MIN(oio_ns_meta1_digits, 4);
		for (guint i=nb_digits; i<4 ;i++)
			ctx.name.base[i] = '0';
	}

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

	struct json_object *jto = NULL, *jfrom = NULL, *jlocal=NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"to",   &jto,  json_type_string, 0},
		{"from", &jfrom, json_type_string, 0},
		{"local", &jlocal, json_type_int, 0},
		{NULL, NULL, 0, 0},
	};

	GError *err = oio_ext_extract_json(jargs, mapping);
	if (err)
		return _reply_format_error(args, err);

	gint32 local_copy = json_object_get_int(jlocal);

	const gchar *to = json_object_get_string(jto);
	if (!local_copy && !metautils_url_valid_for_connect(to))
		return _reply_format_error(args, BADREQ("Invalid target URL"));
	const gchar *from = NULL;

	const gchar *init_suffix = NULL;
	if (jfrom) {
		from = json_object_get_string(jfrom);
		if (!metautils_url_valid_for_connect(from))
			return _reply_format_error(args, BADREQ("Invalid source URL"));
	}

	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype(type, dirtype, sizeof(dirtype));

	gint64 seq = 1;
	enum http_rc_e rc;
	if (!local_copy) {
		init_suffix = SUFFIX();
	}

	CLIENT_CTX2(ctx, args, dirtype, seq, init_suffix, CLIENT_PREFER_NONE,
			NULL, NULL);
	if (!from) {
		/* No source, locate services from directory and use DB_PIPETO. */
		ctx.which = CLIENT_PREFER_MASTER;
		GByteArray * _pack(const struct sqlx_name_s *n,
				const gchar **headers UNUSED) {
			return sqlx_pack_PIPETO(n, to, DL());
		}
		rc = _sqlx_action_noreturn_TAIL(args, &ctx, _pack);
	} else {
		NAME2CONST(n, ctx.name);
		if (local_copy) {
			GByteArray *encoded = sqlx_pack_LOCAL_COPY(&n, from, SUFFIX(), DL());
			err = gridd_client_exec(from,
					oio_clamp_timeout(proxy_timeout_common, oio_ext_get_deadline()),
					encoded);
		} else {
			/* Source service provided, use DB_PIPEFROM. */
			GByteArray *encoded = sqlx_pack_PIPEFROM(&n, from, -1, DL());
			err = gridd_client_exec(to,
					oio_clamp_timeout(proxy_timeout_common, oio_ext_get_deadline()),
					encoded);
		}
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
action_sqlx_propset_with_decoder(struct req_args_s *args,
		struct json_object *jargs, client_on_reply decoder)
{
	GError *err = NULL;
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));
	gint64 seq = 1;
	CLIENT_CTX2(ctx, args, dirtype, seq, NULL, CLIENT_PREFER_MASTER,
			decoder, NULL);
	gchar **kv = NULL;

	err = KV_read_usersys_properties(jargs, &kv);
	if (!err && !*kv) {
		err = BADREQ("No properties found in JSON object");
	}
	if (err) {
		goto end;
	}

	gboolean flush = _request_get_flag(args, "flush");
	gboolean propagate_to_shards = _request_get_flag(args, "propagate_to_shards");
	GByteArray * _pack (const struct sqlx_name_s *n,
			const gchar **headers UNUSED) {
		return sqlx_pack_PROPSET_tab(args->url, n, flush, propagate_to_shards,
				kv, DL());
	}
	err = gridd_request_replicated_with_retry(args, &ctx, _pack);
	if (err) {
		goto end;
	}

end:
	g_strfreev(kv);
	client_clean(&ctx);
	if (err) {
		if (err->code != CODE_REDIRECT_SHARD) {
			return _reply_common_error(args, err);
		}
		g_clear_error(&err);
	}
	return _reply_success_json(args, NULL);
}

enum http_rc_e
action_sqlx_propset(struct req_args_s *args, struct json_object *jargs)
{
	return action_sqlx_propset_with_decoder(args, jargs, NULL);
}

enum http_rc_e
action_sqlx_propget (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	(void) jargs;
	gboolean local = _request_get_flag(args, "local");
	gboolean urgent = _request_get_flag(args, "urgent");
	gboolean extra_counters = _request_get_flag(args, "extra_counters");

	const gchar *suffix = _req_get_option(args, "suffix");

	/* Query the services */
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));

	gint64 seq = 1;
	enum proxy_preference_e how = CLIENT_PREFER_NONE;

	if (oio_str_is_set(suffix)) {
		how = CLIENT_SPECIFIED;
	}
	CLIENT_CTX2(ctx, args, dirtype, seq, suffix, how, NULL, NULL);

	PACKER_VOID(_pack) { return sqlx_pack_PROPGET(_u, suffix, local, urgent, extra_counters, DL()); }
	err = gridd_request_replicated_with_retry(args, &ctx, _pack);
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
action_sqlx_propdel_with_decoder(struct req_args_s *args,
		struct json_object *jargs, client_on_reply decoder)
{
	GError *err = NULL;
	const char *type = TYPE();
	if (!type)
		return _reply_format_error(args, BADREQ("No service type"));
	gchar dirtype[64] = "";
	_get_sqlx_dirtype (type, dirtype, sizeof(dirtype));
	gint64 seq = 1;
	CLIENT_CTX2(ctx, args, dirtype, seq, NULL, CLIENT_PREFER_MASTER,
			decoder, NULL);
	gchar **namev = NULL;

	namev = _load_stringv (jargs);
	if (!namev) {
		err = BADREQ("Bad names");
		goto end;
	}
	for (gchar **p = namev; namev && *p; p++) {
		oio_str_reuse(p, g_strconcat("user.", *p, NULL));
	}

	GByteArray * _pack (const struct sqlx_name_s *n,
			const gchar **headers UNUSED) {
		return sqlx_pack_PROPDEL(args->url, n, (const gchar * const * )namev,
				DL());
	}
	err = gridd_request_replicated_with_retry(args, &ctx, _pack);
	if (err) {
		goto end;
	}

end:
	g_strfreev(namev);
	client_clean(&ctx);
	if (err) {
		if (err->code != CODE_REDIRECT_SHARD) {
			return _reply_common_error(args, err);
		}
		g_clear_error(&err);
	}
	return _reply_success_json(args, NULL);
}

enum http_rc_e
action_sqlx_propdel(struct req_args_s *args, struct json_object *jargs)
{
	return action_sqlx_propdel_with_decoder(args, jargs, NULL);
}

enum http_rc_e
action_admin_ping (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	PACKER_VOID(_pack) { return sqlx_pack_USE(_u, NULL, FALSE, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_has (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	PACKER_VOID(_pack) { return sqlx_pack_HAS (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_status (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
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
	oio_ext_set_admin(TRUE);
	oio_ext_allow_long_timeout(TRUE);
	gint64 check_type = -1;
	const gchar *check_type_str = _req_get_option(args, "check_type");
	if (oio_str_is_set(check_type_str))
		check_type = g_ascii_strtoll(check_type_str, NULL, 10);
	PACKER_VOID(_pack) { return sqlx_pack_RESYNC(_u, (gint)check_type, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_vacuum(struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	oio_ext_allow_long_timeout(TRUE);
	gboolean local = _request_get_flag(args, "local");
	PACKER_VOID(_pack) { return sqlx_pack_VACUUM(_u, local, DL()); }
	return _sqlx_action_noreturn(args, CLIENT_PREFER_MASTER, _pack);
}

enum http_rc_e
action_admin_leave (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	PACKER_VOID(_pack) { return sqlx_pack_EXITELECTION (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_debug (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	PACKER_VOID(_pack) { return sqlx_pack_DESCR (_u, DL()); }
	return _sqlx_action_noreturn (args, CLIENT_RUN_ALL, _pack);
}

enum http_rc_e
action_admin_copy (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	return rest_action (args, action_sqlx_copyto);
}

enum http_rc_e
action_admin_remove (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
	PACKER_VOID(_pack) { return sqlx_pack_REMOVE(_u, DL()); }
	const char *service_id = SERVICE_ID();
	if (service_id == NULL)
		return _reply_format_error(args, BADREQ("No service ID"));

	return _sqlx_action_noreturn(args, CLIENT_SPECIFIED, _pack);
}

enum http_rc_e
action_admin_prop_get (struct req_args_s *args)
{
	oio_ext_set_admin(TRUE);
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
