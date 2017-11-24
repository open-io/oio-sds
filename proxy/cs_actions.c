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

#include "common.h"
#include "actions.h"

GError *
conscience_remote_get_namespace (const char *cs, namespace_info_t **out)
{
	MESSAGE req = metautils_message_create_named("CS_CFG",
			oio_clamp_deadline(proxy_timeout_conscience, oio_ext_get_deadline()));
	GByteArray *gba = NULL;
	GError *err = gridd_client_exec_and_concat (cs,
			oio_clamp_timeout(proxy_timeout_conscience, oio_ext_get_deadline()),
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
	MESSAGE req = metautils_message_create_named("CS_SRV",
			oio_clamp_deadline(proxy_timeout_conscience, oio_ext_get_deadline()));
	metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	if (full)
		metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");
	return gridd_client_exec_and_decode (cs,
			oio_clamp_timeout(proxy_timeout_conscience, oio_ext_get_deadline()),
			message_marshall_gba_and_clean(req), out, service_info_unmarshall);
}

GError * conscience_remote_get_types(const char *cs, gchar ***out) {
	MESSAGE req = metautils_message_create_named ("CS_TYP",
			oio_clamp_deadline(proxy_timeout_conscience, oio_ext_get_deadline()));
	gchar *json = NULL;
	GError *err = gridd_client_exec_and_concat_string (cs,
			oio_clamp_timeout(proxy_timeout_conscience, oio_ext_get_deadline()),
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
	MESSAGE req = metautils_message_create_named ("CS_PSH",
			oio_clamp_deadline(proxy_timeout_conscience, oio_ext_get_deadline()));
	metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	return gridd_client_exec (cs,
			oio_clamp_timeout(proxy_timeout_conscience, oio_ext_get_deadline()),
			message_marshall_gba_and_clean(req));
}

GError*
conscience_remote_remove_services(const char *cs, const char *type, GSList *ls)
{
	MESSAGE req = metautils_message_create_named ("CS_DEL",
			oio_clamp_deadline(proxy_timeout_conscience, oio_ext_get_deadline()));
	if (ls)
		metautils_message_add_body_unref (req, service_info_marshall_gba (ls, NULL));
	if (type) metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
	return gridd_client_exec (cs,
			oio_clamp_timeout(proxy_timeout_conscience, oio_ext_get_deadline()),
			message_marshall_gba_and_clean(req));
}

/* -------------------------------------------------------------------------- */

static GError *
_cs_check_tokens (struct req_args_s *args)
{
	/* Any handler use the NS, this should have been checked earlier. */
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
	GString *gstr = g_string_sized_new (2048);
	g_string_append_c (gstr, '[');
	for (GSList * l = svc; l; l = l->next) {
		if (l != svc)
			g_string_append_c (gstr, ',');
		service_info_encode_json (gstr, l->data, FALSE);
	}
	g_string_append_c (gstr, ']');
	g_slist_free_full (svc, (GDestroyNotify) service_info_clean);
	return gstr;
}

enum reg_op_e {
	REGOP_PUSH,
	REGOP_LOCK,
	REGOP_UNLOCK,
};

static GError *
_registration_batch (enum reg_op_e op, GSList *services)
{
	const gint64 now = oio_ext_real_seconds();

	/* Sanity checks and patch of each score */
	for (GSList *l=services; l ;l=l->next) {
		struct service_info_s *si = l->data;

		if (!metautils_addr_valid_for_connect(&si->addr))
			return BADREQ("Invalid service address");
		if (!si->type[0] && !service_info_get_tag(si->tags, "tag.id"))
			return BADREQ("Service type not specified");
		if (!validate_srvtype(si->type))
			return BADREQ("Service type currently unknown");

		si->score.timestamp = now;
		switch (op) {
			case REGOP_PUSH:
				si->score.value = SCORE_UNSET;
				continue;
			case REGOP_LOCK:
				si->score.value = CLAMP(si->score.value, SCORE_DOWN, SCORE_MAX);
				continue;
			case REGOP_UNLOCK:
				si->score.value = SCORE_UNLOCK;
				continue;
		}
	}

	/* Patch the various caches where services are identified by the
	 * "service ID" key: the cache of known services, ad the cache of local
	 * services (if configured).  */
	for (GSList *l=services; l ;l=l->next) {
		struct service_info_s *si = l->data;
		gchar *k = service_info_key (si);

		if (!service_is_known (k)) {
			service_learn (k);
			service_tag_set_value_boolean (service_info_ensure_tag (
						si->tags, NAME_TAGNAME_RAWX_FIRST), TRUE);
		}

		if (ttl_expire_local_services > 0 && op != REGOP_UNLOCK) {
			struct service_info_s *v = service_info_dup (si);
			v->score.timestamp = oio_ext_monotonic_seconds ();
			REG_WRITE(
					const struct service_info_s *si0 = lru_tree_get(srv_registered, k);
					if (si0)
						v->score.value = si0->score.value;
					lru_tree_insert (srv_registered, g_strdup(k), v);
					);
		}

		g_free(k);
	}

/* if we receive a simple registration and if a special action
 * is already pending (lock or unlock), we should not lose the
 * special action, so merge the old score (i.e. the action code)
 * in the new services description */
#define ENQUEUE_SERVICE() { \
	if (op == REGOP_PUSH) { \
		struct service_info_s *si0 = lru_tree_get(push_queue, key); \
		if (si0 && si0->score.value != SCORE_UNSET) \
			si->score.value = si0->score.value; \
	} \
	lru_tree_insert(push_queue, key, si); \
}
	if (flag_cache_enabled) {
		for (GSList *l=services; l ;l=l->next) {
			struct service_info_s *si = l->data;
			gchar *key = service_info_key(si);
			PUSH_WRITE(ENQUEUE_SERVICE());
			/* Prevent future 'services' list free from freeing element data.
			 * It will be freed when leaving 'push_queue'. */
			l->data = NULL;
		}
		return NULL;
	} else {
		CSURL(cs);
		return conscience_remote_push_services (cs, services);
	}
}

static enum http_rc_e
_registration (struct req_args_s *args, enum reg_op_e op, struct json_object *jsrv)
{
	GError *err;

	if (!push_queue)
		return _reply_bad_gateway(args, SYSERR("Service upstream disabled"));

	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_notfound_error (args, err);

	/* Manage a single service as well as a list of services */
	GSList *services = NULL;
	if (json_object_is_type (jsrv, json_type_array)) {
		const gint max = json_object_array_length(jsrv);
		for (gint i = 0; i < max; ++i) {
			struct json_object *jitem = json_object_array_get_idx(jsrv, i);
			struct service_info_s *si = NULL;
			err = service_info_load_json_object (jitem, &si, TRUE);
			if (err)
				break;
			services = g_slist_prepend(services, si);
		}
	} else if (json_object_is_type (jsrv, json_type_object)) {
		struct service_info_s *si = NULL;
		if (!(err = service_info_load_json_object (jsrv, &si, TRUE)))
			services = g_slist_prepend(services, si);
	} else {
		err = BADREQ("Expected: json object");
	}

	/* Register the whole batch */
	if (!err)
		err = _registration_batch(op, services);
	g_slist_free_full(services, (GDestroyNotify)service_info_clean);

	if (!err)
		return _reply_success_json (args, NULL);
	return _reply_common_error (args, err);
}

/* -------------------------------------------------------------------------- */

enum http_rc_e
action_conscience_info (struct req_args_s *args)
{
	args->rp->no_access();
	GError *err;
	const char *v = OPT("what");

#ifdef HAVE_ENBUG
	if (10 >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	if (v && !strcmp(v, "types")) {
		if (NULL != (err = _cs_check_tokens(args)))
			return _reply_notfound_error (args, err);

		GString *out = g_string_sized_new(128);
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

	GString *gstr = g_string_sized_new (2048);
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

	GString *gs = g_string_sized_new (2048);
	g_string_append_c (gs, '[');
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

#ifdef HAVE_ENBUG
	if (10 >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

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
		return _reply_common_error (args, err);
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

#ifdef HAVE_ENBUG
	if (10 >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	const char *srvtype = TYPE();
	if (!srvtype)
		return _reply_format_error (args, BADREQ("Missing type"));

	CSURL(cs);
	err = conscience_remote_remove_services (cs, srvtype, NULL);

	if (err) {
		g_prefix_error (&err, "Conscience error: ");
		return _reply_common_error (args, err);
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

/*
CS{{
POST /v3.0/{NS}/conscience/register
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Register one service:

.. code-block:: json

   {
     "addr": "127.0.0.1:6000",
     "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 }
   }

Register several services at once:

.. code-block:: json

   [
     { "addr": "127.0.0.1:6000",
       "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 } },
     { "addr": "127.0.0.1:6000",
       "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 } }
   ]

}}CS
 */
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
