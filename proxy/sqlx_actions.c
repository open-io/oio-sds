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

static GError *
_abstract_sqlx_action (struct req_args_s *args, gboolean next,
		GError* (*hook) (struct sqlx_name_s *n, struct meta1_service_url_s *m1u))
{
	/* @TODO Here is a factorisation spot, with sqlx_name_fill() */
	const gchar *type = TYPE();
	if (!type)
		return BADREQ("No service type");

	gint64 seq = 1;
	gchar *etype = NULL;
	gchar *bn = NULL;

	if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META0)) {
		bn = g_strdup (nsname);
		etype = g_strdup("#" NAME_SRVTYPE_META0);
	}
	else if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META1)) {
		bn = g_strndup (oio_url_get(args->url, OIOURL_HEXID), 4);
		etype = g_strdup("#" NAME_SRVTYPE_META1);
	}
	else if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META2)
			|| g_str_has_prefix(type, NAME_SRVTYPE_META2".")) {
		bn = g_strdup_printf("%s.%"G_GINT64_FORMAT,
				oio_url_get (args->url, OIOURL_HEXID), seq);
		etype = g_strdup(type);
	}
	else if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_SQLX)
			|| g_str_has_prefix(type, NAME_SRVTYPE_SQLX".")) {
		seq = atoi(SEQ());
		bn = g_strdup_printf("%s.%"G_GINT64_FORMAT,
				oio_url_get (args->url, OIOURL_HEXID), seq);
		etype = g_strdup(type);
	}
	else {
		return NEWERROR(HTTP_CODE_NOT_FOUND, "Type not managed");
	}

	struct sqlx_name_s n = {.ns=NS(),.base=bn,.type=type};
	GError *on_url (struct meta1_service_url_s *m1u, gboolean *pnext) {
		*pnext = next;
		return hook(&n, m1u);
	}
	GError *err = _resolve_service_and_do (etype, seq, args->url, on_url);
	g_free (etype);
	g_free (bn);

	return err;
}

#define SQLX_NEXT    0x01
#define SQLX_NOREDIR 0x02

static enum http_rc_e
_sqlx_action_noreturn (struct req_args_s *args, guint32 flags,
		GByteArray* (*reqbuilder) (const struct sqlx_name_s *))
{
	gboolean _on_status_reply (gpointer ctx, MESSAGE reply) {
		*((gchar**)ctx) = metautils_message_extract_string_copy(reply, "MSG");
		return TRUE;
	}
	GString *out = g_string_new("{");
	gboolean first = TRUE;

	GError *hook (struct sqlx_name_s *n, struct meta1_service_url_s *m1u) {
		gchar *msg = NULL;
		GByteArray *req = reqbuilder(n);
		struct gridd_client_s *c = gridd_client_create(m1u->host, req,
				&msg, _on_status_reply);
		if (flags & SQLX_NOREDIR)
			gridd_client_no_redirect (c);
		g_byte_array_unref (req);
		gridd_client_start (c);
		gridd_client_set_timeout (c, COMMON_CLIENT_TIMEOUT);
		GError *e = gridd_client_loop (c);
		if (!e)
			e = gridd_client_error (c);
		gridd_client_free (c);
		if (!first)
			g_string_append (out, ",\n");
		first = FALSE;
		if (!e)
			g_string_append_printf (out, "\"%s\":\"%s\"", m1u->host, "OK");
		else {
			g_string_append_printf (out,
					"\"%s\":{\"code\":\"%u\",\"msg\":\"%s\"}",
					m1u->host, e->code, e->message);
		}
		g_free0(msg);
		return e;
	}

	GError *err = _abstract_sqlx_action (args, flags & SQLX_NEXT, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, out);
}

static enum http_rc_e
_sqlx_action_flatbody (struct req_args_s *args, guint32 flags,
		GByteArray* (*reqbuilder) (const struct sqlx_name_s *))
{
	GString *out = g_string_new("{");
	gboolean first = TRUE;

	GError *hook (struct sqlx_name_s *n, struct meta1_service_url_s *m1u) {
		GByteArray * _builder () { return reqbuilder(n); }
		GByteArray * body = NULL;
		GError *e = _gba_request (m1u, _builder, &body);
		if (!first)
			g_string_append (out, ",\n");
		first = FALSE;
		if (!e)
			g_string_append_printf (out, "\"%s\":\"%.*s\"", m1u->host,
					body->len, (gchar*) body->data);
		else {
			g_string_append_printf (out,
					"\"%s\":{\"code\":\"%u\",\"msg\":\"%s\"}",
					m1u->host, e->code, e->message);
			g_clear_error (&e);
		}
		if (body)
			g_byte_array_unref (body);
		return NULL;
	}

	GError *err = _abstract_sqlx_action (args, flags & SQLX_NEXT, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		return _reply_common_error (args, err);
	}

	args->rp->set_body_gstr (out);
	args->rp->set_status (HTTP_CODE_OK, "OK");
	args->rp->finalize ();
	return HTTPRC_DONE;
}

static GError *
_sqlx_action_bodyv (struct req_args_s *args,
		GByteArray* (*reqbuilder) (struct sqlx_name_s *),
		GByteArray ***out)
{
	gboolean _on_reply (gpointer ctx, MESSAGE reply) {
		GByteArray **pgba = ctx;
		GError *e = metautils_message_extract_body_gba (reply, pgba);
		if (e) g_clear_error (&e);
		return TRUE;
	}

	GPtrArray *tmp = g_ptr_array_new ();

	GError *hook (struct sqlx_name_s *n, struct meta1_service_url_s *m1u) {
		GByteArray* _builder () { return reqbuilder(n); }
		GByteArray *body = NULL;
		GError *e = _gba_request (m1u, _builder, &body);
		if (!e && body)
			g_ptr_array_add (tmp, g_byte_array_ref (body));
		if (body)
			g_byte_array_unref (body);
		return e;
	}

	GError *err = _abstract_sqlx_action (args, FALSE, hook);

	if (err) {
		g_ptr_array_set_free_func (tmp, metautils_gba_unref);
		g_ptr_array_free (tmp, TRUE);
		return err;
	}

	*out = (GByteArray**) metautils_gpa_to_array (tmp, TRUE);
	return NULL;
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

	GString *out = g_string_new("{");
	gboolean first = TRUE;

	GError *hook (struct sqlx_name_s *n, struct meta1_service_url_s *m1u) {
		GByteArray *req = sqlx_pack_PIPEFROM(n, m1u->host);
		EXTRA_ASSERT(req != NULL);
		struct gridd_client_s *c = gridd_client_create(to, req, NULL, NULL);
		g_byte_array_unref (req);
		gridd_client_start (c);
		gridd_client_set_timeout (c, 30.0);
		GError *e = gridd_client_loop (c);
		gridd_client_free (c);
		if (!first)
			g_string_append_c (out, ',');
		first = FALSE;
		if (!e)
			g_string_append_printf (out, "\"%s\":\"%s\"", m1u->host, "OK");
		else {
			g_string_append_printf (out,
					"\"%s\":{\"code\":\"%u\",\"msg\":\"%s\"}",
					m1u->host, e->code, e->message);
			g_clear_error (&e);
		}
		return NULL;
	}

	GError *err = _abstract_sqlx_action (args, FALSE, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, out);
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
		GByteArray * packer (const struct sqlx_name_s *n) {
			return sqlx_pack_PROPSET_pairs (n, flush, pairs);
		}
		rc = _sqlx_action_noreturn (args, 0, packer);
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
	GByteArray* packer (struct sqlx_name_s *n) {
		return sqlx_pack_PROPGET (n);
	}
	GByteArray **bodies = NULL;
	err = _sqlx_action_bodyv (args, packer, &bodies);
	if (err)
		return _reply_common_error (args, err);

	// Decode the output of the services
	GSList *pairs = NULL;
	err = metautils_unpack_bodyv (bodies, &pairs, key_value_pairs_unmarshall);
	metautils_gba_cleanv (bodies);
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
		else
			g_string_append_printf (out, "\"%s\":\"%.*s\"",
					kv->key, kv->value->len, (gchar*) kv->value->data);
	}
	g_string_append_c (out, '}');

	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return _reply_success_json (args, out);
}

enum http_rc_e
action_sqlx_propdel (struct req_args_s *args, struct json_object *jargs)
{
	gchar **namev = _load_stringv (jargs);
	if (!namev)
		return _reply_format_error (args, BADREQ("Bad names"));

	GByteArray * packer (const struct sqlx_name_s *n) {
		return sqlx_pack_PROPDEL (n, (const gchar * const * )namev);
	}
	enum http_rc_e rc = _sqlx_action_noreturn (args, 0, packer);
	g_strfreev (namev);
	return rc;
}

enum http_rc_e
action_admin_ping (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, SQLX_NEXT|SQLX_NOREDIR, sqlx_pack_USE);
}

enum http_rc_e
action_admin_status (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, SQLX_NEXT|SQLX_NOREDIR, sqlx_pack_STATUS);
}

enum http_rc_e
action_admin_info (struct req_args_s *args)
{
	GByteArray* _pack (const struct sqlx_name_s *n) {
		(void) n; return sqlx_pack_INFO ();
	}
	return _sqlx_action_flatbody (args, SQLX_NEXT|SQLX_NOREDIR, _pack);
}

enum http_rc_e
action_admin_drop_cache (struct req_args_s *args)
{
	GByteArray* _pack (const struct sqlx_name_s *n) {
		(void) n; return sqlx_pack_LEANIFY ();
	}
	return _sqlx_action_noreturn (args, SQLX_NEXT|SQLX_NOREDIR, _pack);
}

enum http_rc_e
action_admin_sync (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, SQLX_NEXT|SQLX_NOREDIR, sqlx_pack_RESYNC);
}

enum http_rc_e
action_admin_leave (struct req_args_s *args)
{
	return _sqlx_action_noreturn (args, SQLX_NEXT|SQLX_NOREDIR, sqlx_pack_EXITELECTION);
}

enum http_rc_e
action_admin_debug (struct req_args_s *args)
{
	return _sqlx_action_flatbody (args, SQLX_NEXT, sqlx_pack_DESCR);
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
	return _sqlx_action_noreturn(args, 0, sqlx_pack_FREEZE);
}

enum http_rc_e
action_admin_enable (struct req_args_s *args)
{
	return _sqlx_action_noreturn(args, 0, sqlx_pack_ENABLE);
}

enum http_rc_e
action_admin_disable (struct req_args_s *args)
{
	return _sqlx_action_noreturn(args, 0, sqlx_pack_DISABLE);
}
