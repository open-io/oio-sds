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
#include "actions.h"

#include <cluster/module/module.h>

GError *
conscience_remote_get_namespace (const char *cs, namespace_info_t **out)
{
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_NSINFO);
	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), &gba);
	if (err) {
		EXTRA_ASSERT (gba == NULL);
		g_prefix_error(&err, "request: ");
		return err;
	}

	*out = namespace_info_unmarshall(gba->data, gba->len, &err);
	g_byte_array_unref (gba);
	if (*out) return NULL;
	GSETERROR(&err, "Decoding error");
	return err;
}

GError *
conscience_remote_get_services(const char *cs, const char *type, gboolean full,
		GSList **out)
{
	EXTRA_ASSERT(type != NULL);
	MESSAGE req = metautils_message_create_named(NAME_MSGNAME_CS_GET_SRV);
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	if (full)
		metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");
	return gridd_client_exec_and_decode (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), out, service_info_unmarshall);
}

GError * conscience_remote_get_types(const char *cs, gchar ***out) {
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_GET_SRVNAMES);
	gchar *json = NULL;
	GError *err = gridd_client_exec_and_concat_string (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req), &json);
	EXTRA_ASSERT((err != NULL) ^ (json != NULL));
	if (!err) {
		err = STRV_decode_buffer((guint8*)json, strlen(json), out);
		if (out) {
			EXTRA_ASSERT((err != NULL) ^ (*out != NULL));
		}
		g_free(json);
	}
	return err;
}

GError *
conscience_remote_push_services(const char *cs, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_PUSH_SRV);
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	return gridd_client_exec (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req));
}

GError*
conscience_remote_remove_services(const char *cs, const char *type, GSList *ls)
{
	MESSAGE req = metautils_message_create_named (NAME_MSGNAME_CS_RM_SRV);
	if (ls)
		metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	if (type) metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	return gridd_client_exec (cs, CS_CLIENT_TIMEOUT,
			message_marshall_gba_and_clean(req));
}

/* -------------------------------------------------------------------------- */

static GError *
_cs_check_tokens (struct req_args_s *args)
{
	// XXX All the handler use the NS, this should have been checked earlier.
	if (!validate_namespace(NS()))
		return BADNS();

	const char *type = TYPE();
	if (type && !validate_srvtype(type))
		return BADSRVTYPE();
	return NULL;
}

static GString *
_cs_pack_and_free_srvinfo_list (GSList * svc)
{
	GString *gstr = g_string_new ("[");
	for (GSList * l = svc; l; l = l->next) {
		if (l != svc)
			g_string_append_c (gstr, ',');
		service_info_encode_json (gstr, l->data, FALSE);
	}
	g_string_append (gstr, "]");
	g_slist_free_full (svc, (GDestroyNotify) service_info_clean);
	return gstr;
}

enum reg_op_e {
	REGOP_PUSH,
	REGOP_LOCK,
	REGOP_UNLOCK,
};

#ifdef HAVE_EXTRA_DEBUG
static const char*
_regop_2str (const enum reg_op_e op)
{
	switch (op) {
		ON_ENUM(REGOP_,PUSH);
		ON_ENUM(REGOP_,LOCK);
		ON_ENUM(REGOP_,UNLOCK);
	}
	g_assert_not_reached ();
	return "?";
}
#endif

static enum http_rc_e
_registration (struct req_args_s *args, enum reg_op_e op, struct json_object *jsrv)
{
	GError *err;

	if (!jsrv || !json_object_is_type (jsrv, json_type_object))
		return _reply_common_error (args, BADREQ("Expected: json object"));

	if (!push_queue)
		return _reply_bad_gateway(args, SYSERR("Service upstream disabled"));

	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	struct service_info_s *si = NULL;
	err = service_info_load_json_object (jsrv, &si, TRUE);

	if (err) {
		g_prefix_error (&err, "JSON error: ");
		if (err->code == CODE_BAD_REQUEST)
			return _reply_format_error (args, err);
		else
			return _reply_system_error (args, err);
	}

	if (!si->type[0] && !service_info_get_tag(si->tags, "tag.id")) {
		service_info_clean (si);
		return _reply_format_error (args, BADREQ("Service type not specified"));
	}

	if (!si->ns_name[0]) {
		GRID_TRACE2("%s NS forced to %s", __FUNCTION__, si->ns_name);
		g_strlcpy (si->ns_name, ns_name, sizeof(si->ns_name));
	} else if (!validate_namespace (si->ns_name)) {
		service_info_clean (si);
		return _reply_format_error (args, BADNS());
	}

	gchar *k = service_info_key (si);
	STRING_STACKIFY(k);
	GRID_TRACE2("%s op=%s score=%d key=[%s]", __FUNCTION__,
			_regop_2str(op), si->score.value, k);

	switch (op) {
		case REGOP_PUSH:
			si->score.value = SCORE_UNSET;
			if (!service_is_known (k)) {
				service_learn (k);
				service_tag_set_value_boolean (service_info_ensure_tag (
							si->tags, NAME_TAGNAME_RAWX_FIRST), TRUE);
			}
			break;
		case REGOP_LOCK:
			si->score.value = CLAMP(si->score.value, SCORE_DOWN, SCORE_MAX);
			break;
		case REGOP_UNLOCK:
			si->score.value = SCORE_UNLOCK;
			break;
		default:
			g_assert_not_reached();
	}

	if (ttl_expire_local_services > 0 && op != REGOP_UNLOCK) {
		struct service_info_s *v = service_info_dup (si);
		v->score.timestamp = oio_ext_monotonic_seconds ();
		REG_WRITE(
			const struct service_info_s *si0 = lru_tree_get(srv_registered, k);
			if (si0) v->score.value = si0->score.value;
			lru_tree_insert (srv_registered, g_strdup(k), v);
		);
	}

	si->score.timestamp = oio_ext_real_seconds ();

	// TODO follow the DRY principle and factorize this!
	if (flag_cache_enabled) {
		GString *gstr = g_string_new ("");
		service_info_encode_json (gstr, si, TRUE);
		PUSH_WRITE(lru_tree_insert(push_queue, service_info_key(si), si));
		return _reply_success_json (args, gstr);
	} else {
		CSURL(cs);
		GSList l = {.data = si, .next = NULL};
		if (NULL != (err = conscience_remote_push_services (cs, &l))) {
			service_info_clean (si);
			return _reply_common_error (args, err);
		} else {
			GString *gstr = g_string_new ("");
			service_info_encode_json (gstr, si, TRUE);
			service_info_clean (si);
			return _reply_success_json (args, gstr);
		}
	}
}

/* -------------------------------------------------------------------------- */

enum http_rc_e
action_conscience_info (struct req_args_s *args)
{
	args->rp->no_access();
	GError *err;
	const char *v = OPT("what");

	if (v && !strcmp(v, "types")) {
		if (NULL != (err = _cs_check_tokens(args)))
			return _reply_notfound_error (args, err);

		GString *out = g_string_new("");
		g_string_append_c(out, '[');
		NSINFO_READ(if (srvtypes && *srvtypes) {
			g_string_append_c(out, '"');
			g_string_append(out, *srvtypes);
			g_string_append_c(out, '"');
			for (gchar **ps = srvtypes+1; *ps ;ps++) {
				g_string_append_c(out, ',');
				g_string_append_c(out, '"');
				g_string_append(out, *ps);
				g_string_append_c(out, '"');
			}
		});
		g_string_append_c(out, ']');
		return _reply_success_json (args, out);
	}

	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	struct namespace_info_s ni = {{0}};
	NSINFO_READ(namespace_info_copy (&nsinfo, &ni));

	GString *gstr = g_string_new ("");
	namespace_info_encode_json (gstr, &ni);
	namespace_info_clear (&ni);
	return _reply_success_json (args, gstr);
}

enum http_rc_e
action_local_list (struct req_args_s *args)
{
	args->rp->no_access();

	const char *type = TYPE();

	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error(args, err);

	GString *gs = g_string_new ("[");
	gboolean _on_service (gpointer k, gpointer v, gpointer u) {
		(void) k, (void) u;
		struct service_info_s *si = v;
		if (!type || !g_ascii_strcasecmp (si->type, type)) {
			if (gs->len > 1)
				g_string_append_c (gs, ',');
			service_info_encode_json (gs, si, type==NULL);
		}
		return FALSE;
	}

	REG_READ(lru_tree_foreach(srv_registered, _on_service, NULL));
	g_string_append_c (gs, ']');

	return _reply_success_json (args, gs);
}

enum http_rc_e
action_conscience_list (struct req_args_s *args)
{
	args->rp->no_access();

	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("Missing type"));

	gboolean full = _request_get_flag (args, "full");

	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error(args, err);

	if (flag_cache_enabled) {
		service_remember_wanted (type);
		if (!full) {
			GBytes *prepared = service_is_wanted (type);
			if (prepared) {
				gsize ltype = strlen (type) + 1;
				gsize lmax = g_bytes_get_size (prepared);
				GRID_TRACE("%s replied %"G_GSIZE_FORMAT" bytes from the cache",
						__FUNCTION__, lmax - ltype);
				GBytes *json = g_bytes_new_from_bytes (prepared, ltype, lmax-ltype);
				g_bytes_unref (prepared);
				return _reply_success_bytes (args, json);
			} else {
				GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "cache miss");
			}
		} else {
			GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "stats expected");
		}
	} else {
		GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "cache disabled");
	}

	CSURL(cs);
	GSList *sl = NULL;
	err = conscience_remote_get_services (cs, type, full, &sl);
	if (NULL != err) {
		g_slist_free_full (sl, (GDestroyNotify) service_info_clean);
		g_prefix_error (&err, "Conscience error: ");
		return _reply_system_error (args, err);
	}

	args->rp->access_tail ("%s=%u", type, g_slist_length(sl));
	return _reply_success_json (args, _cs_pack_and_free_srvinfo_list (sl));
}

enum http_rc_e
action_conscience_flush (struct req_args_s *args)
{
	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	const char *srvtype = TYPE();
	if (!srvtype)
		return _reply_format_error (args, BADREQ("Missing type"));

	CSURL(cs);
	err = conscience_remote_remove_services (cs, srvtype, NULL);

	if (err) {
		g_prefix_error (&err, "Conscience error: ");
		return _reply_system_error (args, err);
	}
	return _reply_success_json (args, _create_status (CODE_FINAL_OK, "OK"));
}

enum http_rc_e
action_conscience_deregister (struct req_args_s *args)
{
	/* TODO(jfs): this behavior should disappear, there is the explicit
	   flush() for this */
	if (!args->rq->body || !args->rq->body->len) {
		GRID_INFO("old-style flush");
		return action_conscience_flush (args);
	}

	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	/* TODO(jfs): the deregistration of a single service has not been implemented yet */
	return _reply_not_implemented (args);
}

static enum http_rc_e
_rest_conscience_register (struct req_args_s *args, struct json_object *jargs)
{
	return _registration (args, REGOP_PUSH, jargs);
}

enum http_rc_e
action_conscience_register (struct req_args_s *args)
{
	args->rp->no_access();
	return rest_action (args, _rest_conscience_register);
}

static enum http_rc_e
_rest_conscience_lock (struct req_args_s *args, struct json_object *jargs)
{
	return _registration (args, REGOP_LOCK, jargs);
}

enum http_rc_e
action_conscience_lock (struct req_args_s *args)
{
	return rest_action (args, _rest_conscience_lock);
}

static enum http_rc_e
_rest_conscience_unlock (struct req_args_s *args, struct json_object *jargs)
{
	return _registration (args, REGOP_UNLOCK, jargs);
}

enum http_rc_e
action_conscience_unlock (struct req_args_s *args)
{
	return rest_action (args, _rest_conscience_unlock);
}
