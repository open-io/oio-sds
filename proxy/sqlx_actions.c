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

#include <sqliterepo/sqlx_remote.h>

static GError *
_abstract_sqlx_action (struct req_args_s *args, gboolean next,
		GError* (*hook) (struct sqlx_name_s *n, struct meta1_service_url_s *m1u))
{
	gint64 seq = 1;

	// @TODO Here is a factorisation spot, with sqlx_name_fill()
	// Build the base name
	const gchar *type = TYPE();
	gchar *etype = NULL;
	gchar *bn = NULL;
	if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META0)) {
		bn = g_strdup (nsname);
		etype = g_strdup("#" NAME_SRVTYPE_META0);
	}
	else if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META1)) {
		bn = g_strndup (hc_url_get(args->url, HCURL_HEXID), 4);
		etype = g_strdup("#" NAME_SRVTYPE_META1);
	}
	else if (!g_ascii_strcasecmp(type, NAME_SRVTYPE_META2)) {
		seq = 1;
		bn = g_strdup_printf("%s.%"G_GINT64_FORMAT,
				hc_url_get (args->url, HCURL_HEXID), seq);
		etype = g_strdup(NAME_SRVTYPE_META2);
	}
	else if (!g_str_has_prefix(type, "sqlx.")) {
		seq = atoi(SEQ());
		bn = g_strdup_printf("%s.%"G_GINT64_FORMAT,
				hc_url_get (args->url, HCURL_HEXID), seq);
		etype = g_strdup(type);
	}
	else {
		return NEWERROR(HTTP_CODE_NOT_FOUND, "Type not managed");
	}

	struct sqlx_name_s n = {.ns=NS(),.base=bn,.type=etype};
	GError *on_url (struct meta1_service_url_s *m1u, gboolean *pnext) {
		*pnext = next;
		return hook(&n, m1u);
	}
	GError *err = _resolve_service_and_do (etype, seq, args->url, on_url);
	g_free (etype);
	g_free (bn);

	return err;
}

static enum http_rc_e
_sqlx_action_noreturn (struct req_args_s *args,
		GByteArray* (*reqbuilder) (struct sqlx_name_s *))
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
		g_byte_array_unref (req);
		gridd_client_start (c);
		gridd_client_set_timeout (c, 1.0, 1.0);
		GError *e = gridd_client_loop (c);
		if (!e)
			e = gridd_client_error (c);
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
		}
		g_free0(msg);
		return e;
	}

	GError *err = _abstract_sqlx_action (args, FALSE, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error (args, err);
		return _reply_system_error (args, err);
	}
	return _reply_success_json (args, out);
}

static enum http_rc_e
_sqlx_action_flatbody (struct req_args_s *args,
		GByteArray* (*reqbuilder) (struct sqlx_name_s *))
{
	GString *out = g_string_new("{");
	gboolean first = TRUE;

	GError *hook (struct sqlx_name_s *n, struct meta1_service_url_s *m1u) {
		GByteArray * _builder () { return reqbuilder(n); }
		GByteArray * body = NULL;
		GError *e = _gba_request (m1u, _builder, &body);
		if (!first)
			g_string_append_c (out, '\n');
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

	GError *err = _abstract_sqlx_action (args, FALSE, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error (args, err);
		return _reply_system_error (args, err);
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

//------------------------------------------------------------------------------

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

//------------------------------------------------------------------------------

static enum http_rc_e
action_sqlx_leave (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_EXITELECTION);
}

static enum http_rc_e
action_sqlx_ping (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_USE);
}

static enum http_rc_e
action_sqlx_status (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_STATUS);
}

static enum http_rc_e
action_sqlx_info (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_flatbody(args, sqlx_pack_INFO);
}

static enum http_rc_e
action_sqlx_leanify (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_LEANIFY);
}

static enum http_rc_e
action_sqlx_resync (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_RESYNC);
}

static enum http_rc_e
action_sqlx_debug (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_flatbody (args, sqlx_pack_DESCR);
}

static enum http_rc_e
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
		gridd_client_set_timeout (c, 20.0, 20.0);
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

	GError *err = _abstract_sqlx_action (args, TRUE, hook);
	g_string_append(out, "}");

	if (err) {
		g_string_free(out, TRUE);
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error (args, err);
		return _reply_system_error (args, err);
	}
	return _reply_success_json (args, out);
}

static enum http_rc_e
action_sqlx_propset (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type (jargs, json_type_object))
		return _reply_format_error (args, BADREQ("Missing pairs"));

	enum http_rc_e rc;
	GError *err = NULL;
	GSList *pairs = NULL;

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

	if (!err) {
		gboolean flush = NULL != OPT("flush");
		GByteArray * packer (struct sqlx_name_s *n) {
			return sqlx_pack_PROPSET_pairs (n, flush, pairs);
		}
		rc = _sqlx_action_noreturn (args, packer);
	} else {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			rc = _reply_notfound_error (args, err);
		else
			rc = _reply_format_error (args, err);
	}
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return rc;
}

static enum http_rc_e
action_sqlx_propget (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	gchar **namev = NULL;
	if (json_object_is_type (jargs, json_type_null))
		namev = g_malloc0 (sizeof(gchar*));
	else
		namev = _load_stringv (jargs);
	if (!namev)
		return _reply_format_error (args, BADREQ("Bad names"));

	// Query the services
	GByteArray* packer (struct sqlx_name_s *n) {
		return sqlx_pack_PROPGET (n, (const gchar * const * )namev);
	}
	GByteArray **bodies = NULL;
	err = _sqlx_action_bodyv (args, packer, &bodies);
	g_strfreev (namev);
	if (err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error(args, err);
		return _reply_system_error(args, err);
	}

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

static enum http_rc_e
action_sqlx_propdel (struct req_args_s *args, struct json_object *jargs)
{
	gchar **namev = _load_stringv (jargs);
	if (!namev)
		return _reply_format_error (args, BADREQ("Bad names"));

	GByteArray * packer (struct sqlx_name_s *n) {
		return sqlx_pack_PROPDEL (n, (const gchar * const * )namev);
	}
	enum http_rc_e rc = _sqlx_action_noreturn (args, packer);
	g_strfreev (namev);
	return rc;
}

static enum http_rc_e
action_sqlx_freeze (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_FREEZE);
}

static enum http_rc_e
action_sqlx_enable (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_ENABLE);
}

static enum http_rc_e
action_sqlx_disable (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_DISABLE);
}

static enum http_rc_e
action_sqlx_disable_disabled (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	return _sqlx_action_noreturn(args, sqlx_pack_DISABLE_DISABLED);
}

static enum http_rc_e
action_sqlx_action (struct req_args_s *args)
{
	struct sub_action_s actions[] = {
		{"Info", action_sqlx_info},
		{"Leanify", action_sqlx_leanify},

		{"Ping", action_sqlx_ping},
		{"Status", action_sqlx_status},
		{"Debug", action_sqlx_debug},
		{"Resync", action_sqlx_resync},
		{"Leave", action_sqlx_leave},
		{"CopyTo", action_sqlx_copyto},

		{"GetProperties", action_sqlx_propget},
		{"SetProperties", action_sqlx_propset},
		{"DelProperties", action_sqlx_propdel},

		{"Freeze", action_sqlx_freeze},
		{"Enable", action_sqlx_enable},
		{"Disable", action_sqlx_disable},
		{"DisableDisabled", action_sqlx_disable_disabled},

		{NULL,NULL},
	};
	return abstract_action ("sqlx actions", args, actions);
}

