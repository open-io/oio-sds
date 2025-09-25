/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2025 OVH SAS

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
_loop_on_one_cs_while_neterror(const gchar *cs,
		GError* (action)(const char *cs))
{
	GError *err = NULL;
	int attempt = 0;
	gint64 retry_delay = 0;
	do {
		if (err) {
			retry_delay += proxy_request_retry_delay;
			GRID_WARN("Error toward [%s]: (%d) %s", cs, err->code, err->message);
			g_clear_error(&err);
			sleep_at_most(retry_delay);
		}
		err = action(cs);
		if (!err)
			break;
	} while (++attempt < proxy_request_attempts
			&& CODE_IS_NETWORK_ERROR(err->code));
	return err;
}

static GError *
_loop_on_allcs_while_neterror(struct req_args_s *args, gchar **allcs,
		GError* (action)(const char *cs))
{
	EXTRA_ASSERT(allcs != NULL);

	GError *err = NULL;
	if (args) {
		const gchar *cs = CONSCIENCE();
		if (oio_str_is_set(cs)) {
			return _loop_on_one_cs_while_neterror(cs, action);
		}
	}
	for (gchar **pcs = allcs; *pcs; ++pcs) {
		err = action(*pcs);
		if (!err)
			return NULL;
		if (CODE_IS_NETWORK_ERROR(err->code)) {
			GRID_DEBUG("Error toward [%s]: (%d) %s", *pcs, err->code, err->message);
			g_clear_error(&err);
			continue;
		}
		g_prefix_error(&err, "request to [%s]: ", *pcs);
		return err;
	}

	gchar *allcs_joined = g_strjoinv(",", allcs);
	err = BUSY("No conscience replied [%s]", allcs_joined);
	g_free(allcs_joined);
	return err;
}

GError *
conscience_remote_get_namespace(struct req_args_s *args, gchar **allcs,
		namespace_info_t **out, gint64 deadline)
{
	GError * action (const char *cs) {
		GByteArray *gba = NULL;
		MESSAGE req = metautils_message_create_named("CS_CFG",
				oio_clamp_deadline(proxy_timeout_conscience, deadline));
		GError *err = gridd_client_exec_and_concat(cs,
				oio_clamp_timeout(proxy_timeout_conscience, deadline),
				message_marshall_gba_and_clean(req), &gba);
		EXTRA_ASSERT ((gba != NULL) ^ (err != NULL));
		if (err)
			return err;
		*out = namespace_info_unmarshall(gba->data, gba->len, &err);
		g_byte_array_unref (gba);
		if (*out) return NULL;
		g_prefix_error(&err, "Decoding error: ");
		return err;
	}
	return _loop_on_allcs_while_neterror(args, allcs, action);
}

GError *
conscience_remote_get_services(struct req_args_s *args, gchar **allcs,
		const char *type, gboolean full, GSList **out, gint64 deadline)
{
	EXTRA_ASSERT(type != NULL);
	GError * action (const char *cs) {
		MESSAGE req = metautils_message_create_named("CS_SRV",
				oio_clamp_deadline(proxy_timeout_conscience, deadline));
		metautils_message_add_field_str (req, NAME_MSGKEY_TYPENAME, type);
		if (full)
			metautils_message_add_field_str(req, NAME_MSGKEY_FULL, "1");
		return gridd_client_exec_and_decode(cs,
				oio_clamp_timeout(proxy_timeout_conscience, deadline),
				message_marshall_gba_and_clean(req), out, service_info_unmarshall);
	}
	return _loop_on_allcs_while_neterror(args, allcs, action);
}

GError *
conscience_remote_get_types(struct req_args_s *args, gchar **allcs,
		gchar ***out, gint64 deadline)
{
	GError * action(const char *cs) {
		MESSAGE req = metautils_message_create_named("CS_TYP",
				oio_clamp_deadline(proxy_timeout_conscience, deadline));
		gchar *json = NULL;
		GError *err = gridd_client_exec_and_concat_string(cs,
				oio_clamp_timeout(proxy_timeout_conscience, deadline),
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
	return _loop_on_allcs_while_neterror(args, allcs, action);
}

GError *
conscience_remote_push_services(struct req_args_s *args, gchar **allcs,
		GSList *ls, gint64 deadline)
{
	if (!ls)  /* Avoid sending an empty request */
		return NULL;

	GError * action(const char *cs) {
		MESSAGE req = metautils_message_create_named("CS_PSH",
				oio_clamp_deadline(proxy_timeout_conscience, deadline));
		metautils_message_add_body_unref(req, service_info_marshall_gba(ls, NULL));
		return gridd_client_exec(cs,
				oio_clamp_timeout(proxy_timeout_conscience, deadline),
				message_marshall_gba_and_clean(req));
	}
	return _loop_on_allcs_while_neterror(args, allcs, action);
}

GError *
conscience_remote_remove_services(struct req_args_s *args, gchar **allcs,
		const char *type, GSList *ls, gint64 deadline)
{
	GError * action(const char *cs) {
		MESSAGE req = metautils_message_create_named("CS_DEL",
			oio_clamp_deadline(proxy_timeout_conscience, deadline));
		if (ls)
			metautils_message_add_body_unref(req, service_info_marshall_gba(ls, NULL));
		if (type)
			metautils_message_add_field_str(req, NAME_MSGKEY_TYPENAME, type);
		return gridd_client_exec(cs,
				oio_clamp_timeout(proxy_timeout_conscience, deadline),
				message_marshall_gba_and_clean(req));
	}
	return _loop_on_allcs_while_neterror(args, allcs, action);
}

GError *
conscience_resolve_service_id(gchar **cs UNUSED, const char *type UNUSED,
		const char *service_id, gchar **out, gchar **internal_addr)
{
	*out = oio_lb_resolve_service_id(service_id, FALSE);
	*internal_addr = oio_lb_resolve_internal_service_id(service_id);
	if (*out)
		return NULL;

	return NEWERROR(CODE_UNAVAILABLE, "Service ID [%s] not found", service_id);
}

static GError *
_cached_json_to_urlv(const char * srvtype, GBytes *json, gchar ***result)
{
	/* Extract the JSON portion of the cached information (there is
	 * a prefix, the whole buffer is not valid JSON) */
	do {
		const gsize ltype = strlen(srvtype) + 1;
		const gsize lmax = g_bytes_get_size(json);
		json = g_bytes_new_from_bytes(json, ltype, lmax-ltype);
	} while (0);

	GPtrArray *tmp = g_ptr_array_new();
	GError *err = NULL;

	/* We now have a JSON-encoded list of services, right out of
	 * the cache */
	gsize buflen = 0;
	gconstpointer bufptr = g_bytes_get_data(json, &buflen);
	struct json_tokener *tok = json_tokener_new();
	struct json_object *array = json_tokener_parse_ex(tok, bufptr, buflen);
	json_tokener_free(tok);
	if (!json_object_is_type(array, json_type_array)) {
		err = SYSERR("Unexpected cache entry");
		goto label_error;
	} else {
		const int max = json_object_array_length(array);
		if (max <= 0) {
			err = SYSERR("No %s service", srvtype);
			goto label_error;
		}
		for (int i = 0; i < max; ++i) {
			struct service_info_s *si = NULL;
			struct json_object *obj = json_object_array_get_idx(array, i);
			err = service_info_load_json_object(obj, &si, TRUE);
			if (err != NULL)
				goto label_error;
			if (!oio_str_is_set(si->type))
				g_strlcpy(si->type, srvtype, sizeof(si->type));
			g_ptr_array_add(tmp, metautils_service_to_m1url(si, 1));
			service_info_clean(si);
		}
	}
	json_object_put(array);
	g_ptr_array_add(tmp, NULL);
	*result = (gchar**) g_ptr_array_free(tmp, FALSE);
	g_bytes_unref(json);
	return NULL;

label_error:
	json_object_put(array);
	g_ptr_array_set_free_func(tmp, g_free);
	g_ptr_array_free(tmp, TRUE);
	*result = NULL;
	g_bytes_unref(json);
	return err;
}

GError *
proxy_locate_meta0(const char *ns UNUSED, gchar ***result, gint64 deadline)
{
	CSURL(cs);
	GSList *sl = NULL;
	GError *err = NULL;

	if (flag_cache_enabled) {
		service_remember_wanted (NAME_SRVTYPE_META0);
		GBytes *prepared = service_is_wanted (NAME_SRVTYPE_META0);
		if (prepared) {
			err = _cached_json_to_urlv(NAME_SRVTYPE_META0, prepared, result);
			g_bytes_unref(prepared);
			return err;
		}
	}

	err = conscience_remote_get_services(NULL, cs, NAME_SRVTYPE_META0,
			FALSE, &sl, deadline);
	if (NULL != err) {
		g_slist_free_full (sl, (GDestroyNotify) service_info_clean);
		return err;
	}
	*result = metautils_service_list_to_urlv(sl);
	g_slist_free_full(sl, (GDestroyNotify)service_info_clean);
	return NULL;
}

/* -------------------------------------------------------------------------- */

static GError *
_cs_check_tokens (struct req_args_s *args)
{
	/* Any handler use the NS, this should have been checked earlier. */
	if (!validate_namespace(NS()))
		return BADNS();

	const char *type = TYPE();
	if (type)
		return validate_srvtype(type);

	return NULL;
}

static GString*
_cs_json_pack_and_free_srvinfo_list(GSList * svc, gboolean full)
{
	GString *gstr = g_string_sized_new(2048);
	g_string_append_c (gstr, '[');
	for (GSList * l = svc; l; l = l->next) {
		if (l != svc)
			g_string_append_c(gstr, ',');
		service_info_encode_json(gstr, l->data, full);
	}
	g_string_append_c(gstr, ']');
	g_slist_free_full(svc, (GDestroyNotify) service_info_clean);
	return gstr;
}

static void
_service_info_build_stats_keys(const struct service_info_s *si,
		gchar *out_key_get, gchar *out_key_put, size_t key_size)
{
	gchar slots[128] = {0};
	gboolean up = FALSE, get_lock = FALSE, put_lock = FALSE;
	struct service_tag_s *tag = NULL;
	for (guint i = 0, max = si->tags->len; i < max; i++) {
		tag = si->tags->pdata[i];
		if (!g_strcmp0(tag->name, NAME_TAGNAME_SLOTS)) {
			service_tag_get_value_string(tag, slots, sizeof(slots), NULL);
		} else if (!g_strcmp0(tag->name, NAME_TAGNAME_UP)) {
			service_tag_get_value_boolean(tag, &up, NULL);
		} else if (!g_strcmp0(tag->name, NAME_TAGNAME_GET_LOCK)) {
			service_tag_get_value_boolean(tag, &get_lock, NULL);
		} else if (!g_strcmp0(tag->name, NAME_TAGNAME_PUT_LOCK)) {
			service_tag_get_value_boolean(tag, &put_lock, NULL);
		}
	}

	g_snprintf(out_key_get, key_size,
			"service_type=\"%s\",slots=\"%s\",up=\"%s\",lock=\"%s\",score_type=\"get\"",
			si->type, slots, BOOLSTR(up), BOOLSTR(get_lock));
	g_snprintf(out_key_put, key_size,
			"service_type=\"%s\",slots=\"%s\",up=\"%s\",lock=\"%s\",score_type=\"put\"",
			si->type, slots, BOOLSTR(up), BOOLSTR(put_lock));
}

static void
_service_info_incr_stats(GHashTable *stats, const gchar *mid_key, gint32 score)
{
	gint32 intervals[6] = {G_MAXINT32, 80, 60, 40, 20, 0};
	gchar *key = NULL;

	score = MAX(score, 0);

	key = g_strdup_printf("conscience_scores_count{%s}", mid_key);
	gint64 count = GPOINTER_TO_INT(g_hash_table_lookup(stats, key));
	g_hash_table_insert(stats, key, GINT_TO_POINTER(count + 1));

	key = g_strdup_printf("conscience_scores_sum{%s}", mid_key);
	gint64 sum = GPOINTER_TO_INT(g_hash_table_lookup(stats, key));
	g_hash_table_insert(stats, key, GINT_TO_POINTER(sum + score));

	for (size_t i = 0; i < sizeof(intervals)/sizeof(gint32); i++) {
		gint32 upper = intervals[i];
		if (i == 0) {
			key = g_strdup_printf(
					"conscience_scores_bucket{%s,le=\"+Inf\"}", mid_key);
		} else {
			key = g_strdup_printf(
					"conscience_scores_bucket{%s,le=\"%u\"}", mid_key, upper);
		}
		/* If the key does not exist, count will be zero. */
		count = GPOINTER_TO_INT(g_hash_table_lookup(stats, key));
		if (score <= upper)
			count += 1;
		/* Even if the count is zero, insert it, so all "le" exist. */
		g_hash_table_insert(stats, key, GINT_TO_POINTER(count));
	}
}

static void
service_info_incr_stats(GHashTable *stats, const struct service_info_s *si)
{
	if (!si)
		return;

	gchar mid_key_get[192] = {0}, mid_key_put[192] = {0};
	_service_info_build_stats_keys(
			si, mid_key_get, mid_key_put, sizeof(mid_key_get));
	_service_info_incr_stats(stats, mid_key_get, si->get_score.value);
	_service_info_incr_stats(stats, mid_key_put, si->put_score.value);
}

static GString*
_cs_prometheus_aggregate_and_free_srvinfo_stats(GSList *svc)
{
	GHashTable *stats = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);
	for (GSList * l = svc; l; l = l->next) {
		service_info_incr_stats(stats, l->data);
	}
	g_slist_free_full(svc, (GDestroyNotify)service_info_clean);

	GString *gstr = g_string_sized_new(4096);
	GHashTableIter iter;
	gpointer k, v;
	g_hash_table_iter_init(&iter, stats);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		g_string_append_printf(
				gstr, "%s %d\n", (gchar*)k, GPOINTER_TO_INT(v));
	}

	g_hash_table_unref(stats);
	return gstr;
}

static GString*
_cs_prometheus_pack_and_free_srvinfo_list(GSList * svc)
{
	GString *gstr = g_string_sized_new(4096);
	for (GSList * l = svc; l; l = l->next) {
		service_info_encode_prometheus(gstr, l->data);
	}
	g_slist_free_full(svc, (GDestroyNotify) service_info_clean);
	return gstr;
}

static GError *
_load_services_info(struct json_object *jsrv, GSList **services)
{
	GError *err = NULL;

	/* Manage a single service as well as a list of services */
	if (json_object_is_type(jsrv, json_type_array)) {
		const gint max = json_object_array_length(jsrv);
		for (gint i = 0; i < max; ++i) {
			struct json_object *jitem = json_object_array_get_idx(jsrv, i);
			struct service_info_s *si = NULL;
			err = service_info_load_json_object(jitem, &si, TRUE);
			if (err)
				break;
			if (!oio_str_is_set(si->ns_name)) {
				gchar srvaddr[STRLEN_ADDRINFO];
				grid_addrinfo_to_string(&si->addr, srvaddr, sizeof(srvaddr));
				/* We can't require this unless heavily patching the Python
				 * API, hence the debug message instead of an error. */
				GRID_DEBUG("Loading service without ns_name: %s (reqid=%s))",
					srvaddr, oio_ext_get_reqid());
			}
			*services = g_slist_prepend(*services, si);
		}
	} else if (json_object_is_type(jsrv, json_type_object)) {
		struct service_info_s *si = NULL;
		if (!(err = service_info_load_json_object(jsrv, &si, TRUE))) {
			*services = g_slist_prepend(*services, si);
		}
	} else {
		err = BADREQ("Expected: json object");
	}

	return err;
}

enum reg_op_e {
	REGOP_PUSH,
	REGOP_LOCK,
	REGOP_UNLOCK,
};

static GError *
_registration_batch(struct req_args_s *args, enum reg_op_e op, GSList *services)
{
	const gint64 now = oio_ext_real_seconds();

	/* Sanity checks and patch of each score */
	for (GSList *l=services; l ;l=l->next) {
		struct service_info_s *si = l->data;

		if (!metautils_addr_valid_for_connect(&si->addr))
			return BADREQ("Invalid service address");
		if (!si->type[0])
			return BADREQ("Service type not specified");
		GError *err = validate_srvtype(si->type);
		if (err)
			return err;

		si->put_score.timestamp = now;
		si->get_score.timestamp = now;

		struct service_tag_s *tag_put_lock = service_info_get_tag(
				si->tags, NAME_TAGNAME_PUT_LOCK);
		struct service_tag_s *tag_get_lock = service_info_get_tag(
				si->tags, NAME_TAGNAME_GET_LOCK);

		switch (op) {
			case REGOP_PUSH:
				si->put_score.value = SCORE_UNSET;
				si->get_score.value = SCORE_UNSET;
				continue;
			case REGOP_LOCK:
				if (si->put_score.value != SCORE_UNSET)
					si->put_score.value = CLAMP(si->put_score.value, SCORE_DOWN, SCORE_MAX);
				if (si->get_score.value != SCORE_UNSET)
					si->get_score.value = CLAMP(si->get_score.value, SCORE_DOWN, SCORE_MAX);
				continue;
			case REGOP_UNLOCK:
				if (tag_put_lock) {
					si->put_score.value = SCORE_UNLOCK;
				} else {
					si->put_score.value = SCORE_UNSET;
				}
				if (tag_get_lock) {
					si->get_score.value = SCORE_UNLOCK;
				} else {
					si->get_score.value = SCORE_UNSET;
				}

				if (!tag_put_lock && !tag_get_lock) {
					si->put_score.value = SCORE_UNLOCK;
					si->get_score.value = SCORE_UNLOCK;
				}
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
			// We "learn" the service after it is registered successfully
			service_tag_set_value_boolean (service_info_ensure_tag (
						si->tags, NAME_TAGNAME_FIRST), TRUE);
		}

		if (ttl_expire_local_services > 0 && op != REGOP_UNLOCK) {
			struct service_info_s *v = service_info_dup (si);
			REG_WRITE(
					const struct service_info_s *si0 = lru_tree_get(srv_registered, k);
					if (si0)
						v->put_score.value = si0->put_score.value;
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
		if (si0 && si0->put_score.value != SCORE_UNSET) \
			si->put_score.value = si0->put_score.value; \
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
		return conscience_remote_push_services(args, cs, services,
				oio_ext_get_deadline());
	}
}

static enum http_rc_e
_registration(struct req_args_s *args, enum reg_op_e op, struct json_object *jsrv)
{
	GError *err = NULL;
	GSList *services = NULL;

	if (!push_queue)
		return _reply_bad_gateway(args, SYSERR("Service upstream disabled"));

	if ((err = _cs_check_tokens(args)) != NULL)
		return _reply_common_error(args, err);

	if ((err = _load_services_info(jsrv, &services)) != NULL) {
		g_slist_free_full(services, (GDestroyNotify)service_info_clean);
		return _reply_common_error(args, err);
	}

	/* Register the whole batch */
	err = _registration_batch(args, op, services);

	g_slist_free_full(services, (GDestroyNotify)service_info_clean);
	if (err)
		return _reply_common_error(args, err);
	return _reply_success_json(args, NULL);
}

static enum http_rc_e
_deregistration(struct req_args_s *args, struct json_object *jsrv)
{
	GError *err = NULL;
	GSList *services = NULL;

	if ((err = _cs_check_tokens(args)) != NULL)
		return _reply_common_error(args, err);

	if ((err = _load_services_info(jsrv, &services)) != NULL) {
		g_slist_free_full(services, (GDestroyNotify)service_info_clean);
		return _reply_common_error(args, err);
	}

	/* Deregister */
	CSURL(cs);
	err = conscience_remote_remove_services(args, cs, NULL, services,
			oio_ext_get_deadline());

	g_slist_free_full(services, (GDestroyNotify)service_info_clean);
	if (err) {
		g_prefix_error(&err, "Conscience error: ");
		return _reply_common_error(args, err);
	}
	return _reply_success_json(args, NULL);
}

/* -------------------------------------------------------------------------- */

// CS{{
// GET /v3.0/{NS}/conscience/info?what=<>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Get information about conscience. You can select information using "what".
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/conscience/info?what=types HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 79
//
// .. code-block:: json
//
//    ["account","echo","meta0","meta1","meta2","oiofs","rawx","rdir","redis","sqlx"]
//
// }}CS
enum http_rc_e
action_conscience_info (struct req_args_s *args)
{
	args->rp->no_access();
	GError *err;
	const char *v = OPT("what");

#ifdef HAVE_ENBUG
	if (proxy_enbug_cs_failure_rate >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_common_error(args, err);

	if (v && !strcmp(v, "types")) {
		gboolean service_types_loaded = FALSE;
		GString *out = g_string_sized_new(128);
		g_string_append_c(out, '[');
		NSINFO_READ(
			if (srvtypes) {
				service_types_loaded = TRUE;
				if (*srvtypes) {
					g_string_append_c(out, '"');
					g_string_append(out, *srvtypes);
					g_string_append_c(out, '"');
					for (gchar **ps = srvtypes+1; *ps ;ps++) {
						g_string_append_c(out, ',');
						g_string_append_c(out, '"');
						g_string_append(out, *ps);
						g_string_append_c(out, '"');
					}
				}
			});
		if (!service_types_loaded) {
			g_string_free(out, TRUE);
			return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE,
					"Service types not yet loaded"));
		}
		g_string_append_c(out, ']');
		return _reply_success_json (args, out);
	}

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
		return _reply_common_error(args, err);

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

// CS{{
// GET /v3.0/{NS}/conscience/list?type=<services type>[&cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Get list of services registered
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/conscience/list?type=rawx HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 509
//
// .. code-block:: text
//
//    [{"addr":"127.0.0.1:6010","score":81,...}]
//
// }}CS
enum http_rc_e
action_conscience_list (struct req_args_s *args)
{
	args->rp->no_access();

	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("Missing type"));
	const char *format = OPT("format");
	gboolean json_format = !format || !(*format) || strcmp(format, "json") == 0;

#ifdef HAVE_ENBUG
	if (proxy_enbug_cs_failure_rate >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	gboolean all = strcmp(type, "all") == 0;
	gboolean full = _request_get_flag(args, "full");

	GError *err;
	if (!all && (err = _cs_check_tokens(args)) != NULL)
		return _reply_common_error(args, err);

	if (!CONSCIENCE() && !all && json_format && flag_cache_enabled) {
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
				args->rp->access_tail("cache:HIT");
				return _reply_success_bytes(args, HTTP_CONTENT_TYPE_JSON, json);
			} else {
				GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "cache miss");
				args->rp->access_tail("cache:MISS");
			}
		} else {
			GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "stats expected");
		}
	} else {
		GRID_TRACE("%s(%s) direct query: %s", __FUNCTION__, type, "cache disabled");
	}

	CSURL(cs);
	GSList *sl = NULL;
	err = conscience_remote_get_services(args, cs, type, full, &sl,
			oio_ext_get_deadline());
	if (NULL != err) {
		g_slist_free_full (sl, (GDestroyNotify) service_info_clean);
		g_prefix_error (&err, "Conscience error: ");
		return _reply_common_error (args, err);
	}

	// Refresh down hosts with current value
	gridd_client_update_global_down_hosts(sl);

	if (json_format) {
		return _reply_success_json(args,
				_cs_json_pack_and_free_srvinfo_list(sl, all));
	} else if (strcmp(format, "prometheus") == 0) {
		return _reply_success_bytes(args, HTTP_CONTENT_TYPE_TEXT,
				g_string_free_to_bytes(
						_cs_prometheus_pack_and_free_srvinfo_list(sl)));
	} else if (strcmp(format, "aggregated") == 0) {
		return _reply_success_bytes(args, HTTP_CONTENT_TYPE_TEXT,
				g_string_free_to_bytes(
						_cs_prometheus_aggregate_and_free_srvinfo_stats(sl)));
	}
	return _reply_format_error(args, BADREQ("Unknown format"));
}

// CS{{
// GET /v3.0/{NS}/conscience/resolve?type=<service type>&service_id=<service id>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Get service address from ID
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/conscience/resolve?type=rawx&service_id=363794e0-a2fc-47d9-94d8-90615dc0fdb8 HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 27
//
// .. code-block:: json
//
//    { "addr": "127.0.0.1:6010"}
//
// }}CS
enum http_rc_e
action_conscience_resolve_service_id (struct req_args_s *args)
{
	args->rp->no_access();

	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("Missing type"));

	const char *service_id = SERVICE_ID();
	if (!service_id)
		return _reply_format_error (args, BADREQ("Missing service id"));

#ifdef HAVE_ENBUG
	if (proxy_enbug_cs_failure_rate >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	GError *err;
	if (NULL != (err = _cs_check_tokens(args)))
		return _reply_common_error(args, err);

	CSURL(cs);
	gchar *addr = NULL;
	gchar *internal_addr = NULL;
	err = conscience_resolve_service_id(cs, type, service_id, &addr, &internal_addr);
	if (NULL != err) {
		g_prefix_error (&err, "Conscience error: ");
		return _reply_common_error (args, err);
	}
	GString *gstr = g_string_sized_new (256);
	g_string_append_c (gstr, '{');
	g_string_append_printf(gstr," \"addr\": \"%s\"", addr);
	if (oio_str_is_set(internal_addr)) {
		g_string_append_printf(gstr,", \"internal_addr\": \"%s\"", internal_addr);
	}
	g_string_append_c (gstr, '}');

	g_free(addr);
	g_free(internal_addr);

	return _reply_success_json (args, gstr);
}

// CS{{
// POST /v3.0/{NS}/conscience/flush?type=<service_type>[&cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Deregister all services with the given type.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/conscience/flush?type=rawx HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CS
enum http_rc_e
action_conscience_flush (struct req_args_s *args)
{
	GError *err = NULL;
	const char *srvtype = TYPE();

	if (!srvtype)
		return _reply_format_error(args, BADREQ("Missing type"));

	if ((err = _cs_check_tokens(args)) != NULL)
		return _reply_common_error(args, err);

#ifdef HAVE_ENBUG
	if (proxy_enbug_cs_failure_rate >= oio_ext_rand_int_range(1,100))
		return _reply_retry(args, NEWERROR(CODE_UNAVAILABLE, "FAKE"));
#endif

	CSURL(cs);
	err = conscience_remote_remove_services(args, cs, srvtype, NULL,
			oio_ext_get_deadline());

	if (err) {
		g_prefix_error(&err, "Conscience error: ");
		return _reply_common_error(args, err);
	}
	return _reply_success_json(args, NULL);
}

static enum http_rc_e
_rest_conscience_deregister(struct req_args_s *args, struct json_object *jargs)
{
	return _deregistration(args, jargs);
}

// CS{{
// POST /v3.0/{NS}/conscience/deregister?type=<services type>[&cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/conscience/deregister HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 189
//    Content-Type: application/x-www-form-urlencoded
//
// Body when deregistering one service:
//
// .. code-block:: json
//
//    {
//      "addr": "127.0.0.1:6010",
//      "type": "rawx"
//    }
//
// Body when deregistering several services at once:
//
// .. code-block:: json
//
//    [
//      { "addr": "127.0.0.1:6010",
//        "type": "rawx" },
//      { "addr": "127.0.0.1:6011",
//        "type": "rawx"}
//    ]
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CS
enum http_rc_e
action_conscience_deregister(struct req_args_s *args)
{
	return rest_action(args, _rest_conscience_deregister);
}

static enum http_rc_e
_rest_conscience_register(struct req_args_s *args, struct json_object *jargs)
{
	return _registration(args, REGOP_PUSH, jargs);
}

// CS{{
// POST /v3.0/{NS}/conscience/register[?cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/conscience/register HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 189
//    Content-Type: application/x-www-form-urlencoded
//
// Body when registering one service:
//
// .. code-block:: json
//
//    {
//      "addr": "127.0.0.1:6010",
//      "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 },
//      "type": "rawx"
//    }
//
// Body when registering several services at once:
//
// .. code-block:: json
//
//    [
//      { "addr": "127.0.0.1:6010",
//        "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 },
//        "type": "rawx" },
//      { "addr": "127.0.0.1:6011",
//        "tags": { "stat.cpu": 100, "stat.idle": 100, "stat.io": 100 },
//        "type": "rawx"}
//    ]
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CS
enum http_rc_e
action_conscience_register(struct req_args_s *args)
{
	args->rp->no_access();
	return rest_action(args, _rest_conscience_register);
}

static enum http_rc_e
_rest_conscience_lock(struct req_args_s *args, struct json_object *jargs)
{
	return _registration(args, REGOP_LOCK, jargs);
}

// CS{{
// POST /v3.0/{NS}/conscience/lock[?cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/conscience/lock HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 39
//    Content-Type: application/x-www-form-urlencoded
//
// Body when locking one service:
//
// .. code-block:: json
//
//    {
//      "addr": "127.0.0.1:6010",
//      "type": "rawx"
//    }
//
// Body when locking several services at once:
//
// .. code-block:: json
//
//    [
//      { "addr": "127.0.0.1:6010",
//        "type": "rawx" },
//      { "addr": "127.0.0.1:6011",
//        "type": "rawx"}
//    ]
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CS
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

// CS{{
// POST /v3.0/{NS}/conscience/unlock[?cs=<conscience addr>]
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/conscience/unlock HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 39
//    Content-Type: application/x-www-form-urlencoded
//
//
// Body when unlocking one service:
//
// .. code-block:: json
//
//    {
//      "addr": "127.0.0.1:6010",
//      "type": "rawx"
//    }
//
// Body when unlocking several services at once:
//
// .. code-block:: json
//
//    [
//      { "addr": "127.0.0.1:6010",
//        "type": "rawx" },
//      { "addr": "127.0.0.1:6011",
//        "type": "rawx"}
//    ]
//
// Standard response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CS
enum http_rc_e
action_conscience_unlock (struct req_args_s *args)
{
	return rest_action (args, _rest_conscience_unlock);
}
