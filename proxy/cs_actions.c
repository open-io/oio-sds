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

static GError *
_cs_check_tokens (struct req_args_s *args)
{
	// XXX All the handler use the NS, this should have been checked earlier.
	if (!validate_namespace(NS()))
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");

	if (TYPE()) {
		if (!validate_srvtype(TYPE()))
			return NEWERROR(CODE_SRVTYPE_NOTMANAGED, "Invalid srvtype");
	}
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

static enum http_rc_e
_registration (struct req_args_s *args, enum reg_op_e op, struct json_object *jsrv)
{
	GError *err;

	if (!jsrv || !json_object_is_type (jsrv, json_type_object))
		return _reply_common_error (args, BADREQ("Expected: json object"));

	if (!push_queue)
		return _reply_bad_gateway(args, NEWERROR(CODE_INTERNAL_ERROR,
					"Service upstream disabled"));

	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	struct service_info_s *si = NULL;
	err = service_info_load_json_object (jsrv, &si, TRUE);

	if (err) {
		if (err->code == CODE_BAD_REQUEST)
			return _reply_format_error (args, err);
		else
			return _reply_system_error (args, err);
	}

	if (!si->type[0]) {
		service_info_clean (si);
		return _reply_format_error (args, BADREQ("Service type not specified"));
	}

	if (!si->ns_name[0]) {
		g_strlcpy (si->ns_name, nsname, sizeof(si->ns_name));
	} else if (!validate_namespace (si->ns_name)) {
		service_info_clean (si);
		return _reply_format_error (args, NEWERROR (CODE_NAMESPACE_NOTMANAGED,
					"Unexpected NS"));
	}

	si->score.timestamp = oio_ext_real_time () / G_TIME_SPAN_SECOND;

	if (op == REGOP_PUSH)
		si->score.value = SCORE_UNSET;
	else if (op == REGOP_UNLOCK)
		si->score.value = SCORE_UNLOCK;
	else /* if (op == REGOP_LOCK) */
		si->score.value = CLAMP(si->score.value, SCORE_DOWN, SCORE_MAX);

	if (cs_expire_local_services > 0) {
		gchar *k = service_info_key (si);
		struct service_info_s *v = service_info_dup (si);
		PUSH_DO(lru_tree_insert (srv_registered, k, v));
	}

	// TODO follow the DRY principle and factorize this!
	if (flag_cache_enabled) {
		GString *gstr = g_string_new ("");
		service_info_encode_json (gstr, si, TRUE);
		PUSH_DO(lru_tree_insert(push_queue, service_info_key(si), si));
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

//------------------------------------------------------------------------------

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
		NSINFO_DO(if (srvtypes && *srvtypes) {
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
	NSINFO_DO(namespace_info_copy (&nsinfo, &ni));

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

	PUSH_DO(do {
		lru_tree_foreach_DEQ (srv_registered, _on_service, NULL);
	} while (0));
	g_string_append_c (gs, ']');

	return _reply_success_json (args, gs);
}

enum http_rc_e
action_conscience_list (struct req_args_s *args)
{
	args->rp->no_access();

	const char *types = TYPE();
	if (!types)
		return _reply_format_error (args, BADREQ("Missing type"));

	gboolean full = _request_has_flag (args, PROXYD_HEADER_MODE, "full");

	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error(args, err);

	CSURL(cs);
	GSList *sl = NULL;
	err = conscience_remote_get_services (cs, types, full, &sl);

	if (NULL != err) {
		g_slist_free_full (sl, (GDestroyNotify) service_info_clean);
		g_prefix_error (&err, "Conscience error: ");
		return _reply_system_error (args, err);
	}

	args->rp->access_tail ("%s=%u", types, g_slist_length(sl));
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
