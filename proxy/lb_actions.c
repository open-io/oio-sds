/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2022-2025 OVH SAS

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
_lb_check_tokens (struct req_args_s *args)
{
	if (!validate_namespace(NS()))
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");
	const char *type = TYPE();
	if (!type)
		BADREQ("Missing type");
	return validate_srvtype(type);
}

// New handlers ----------------------------------------------------------------

static GString *
_lb_pack_srvid_tab(const char **ids)
{
	GString *gstr = g_string_sized_new (512);
	g_string_append_c(gstr, '[');
	for (const char **pp = ids; *pp; pp++) {
		if (pp != ids)
			g_string_append_c(gstr, ',');

		gchar *straddr = NULL;
		oio_parse_service_key(*pp, NULL, NULL, &straddr);
		g_string_append_printf(gstr, "{\"addr\":\"%s\",\"id\":\"%s\"}",
				straddr, *pp);
		g_free(straddr);
	}
	g_string_append_c(gstr, ']');
	return gstr;
}

static enum http_rc_e
_lb(struct req_args_s *args, const char *srvtype)
{
	enum http_rc_e code;

	const char *slot = OPT("slot");
	const char *sz = OPT("size");

	gint64 howmany = 1;
	if (sz && !oio_str_is_number(sz, &howmany))
		return _reply_format_error(args, BADREQ("Invalid size"));

	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lb_world, srvtype);
	GString *targets = g_string_sized_new(64);
	if (howmany > 1) {
		g_string_append(targets, sz);
		g_string_append_c(targets, OIO_CSV_SEP_C);
	}
	if (slot) {
		if (g_str_has_prefix(slot, srvtype)) {
			g_string_append(targets, slot);
			g_string_append_c(targets, OIO_CSV_SEP_C);
		} else {
			g_string_append_printf(targets, "%s-%s"OIO_CSV_SEP, srvtype, slot);
		}
	}
	g_string_append(targets, srvtype);
	GRID_DEBUG("Temporary pool [%s] will target [%s]", srvtype, targets->str);
	oio_lb_world__add_pool_targets(pool, targets->str);
	g_string_free(targets, TRUE);

	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
	void _on_id(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
		g_ptr_array_add(ids, g_strdup(sel->item->id));
	}
	gboolean flawed = FALSE;
	GError *err = oio_lb_pool__poll(pool, NULL, _on_id, &flawed);
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria: ", ids->len);
		code = _reply_common_error(args, err);
	} else {
		g_ptr_array_add(ids, NULL);
		GString *gstr = _lb_pack_srvid_tab((const char**)ids->pdata);
		if (flawed)
			args->rp->add_header(
					PROXYD_HEADER_PREFIX "lb-flawed", g_strdup("1"));
		code = _reply_success_json(args, gstr);
	}

	oio_lb_pool__destroy(pool);
	g_ptr_array_free(ids, TRUE);
	return code;
}

enum http_rc_e
action_lb_choose (struct req_args_s *args)
{
	GError *err;
	args->rp->no_access();
	if (NULL != (err = _lb_check_tokens(args)))
		return _reply_notfound_error (args, err);
	return _lb(args, TYPE());
}

static oio_location_t *
_json_to_locations(struct json_object *arr)
{
	if (!arr)
		return NULL;
	GArray *out = g_array_new(TRUE, TRUE, sizeof(oio_location_t));
	int len = json_object_array_length(arr);
	for (int i = 0; i < len; i++) {
		oio_location_t loc = json_object_get_int64(
				json_object_array_get_idx(arr, i));
		g_array_append_val(out, loc);
	}
	return (oio_location_t*) g_array_free(out, FALSE);
}

static oio_location_t *
_json_ids_to_locations(struct json_object *arr, oio_location_t *prev)
{
	if (!arr)
		return prev;
	GArray *out = g_array_new(TRUE, TRUE, sizeof(oio_location_t));
	if (prev) {
		guint len = 0;
		while (prev[len] != 0)
			len++;
		g_array_append_vals(out, prev, len);
		g_free(prev);
	}

	const guint max = json_object_array_length(arr);
	for (guint i = 0; i < max; i++) {
		const char *id = json_object_get_string(
				json_object_array_get_idx(arr, i));
		struct oio_lb_item_s *item = oio_lb_world__get_item(lb_world, id);
		if (item) {
			g_array_append_val(out, item->location);
			g_free(item);
		}
	}
	return (oio_location_t*) g_array_free(out, FALSE);
}

static GError*
_decode_lb_body(struct json_object *body,
		oio_location_t **avoid, oio_location_t **known,
		gboolean *force_fair_constraints)
{
	if (body && !json_object_is_type(body, json_type_object))
		return BADREQ("Expected: json object");

	struct json_object *javoid = NULL, *javoid_locs = NULL;
	struct json_object *jknown = NULL, *jknown_locs = NULL;
	struct json_object *jfair = NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"avoid",           &javoid,       json_type_array, 0},
		{"avoid_locations", &javoid_locs,  json_type_array, 0},
		{"known",           &jknown,       json_type_array, 0},
		{"known_locations", &jknown_locs,  json_type_array, 0},
		{"force_fair_constraints", &jfair, json_type_boolean, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err = NULL;
	if (body && (err = oio_ext_extract_json(body, mapping)))
		return err;
	*avoid = _json_to_locations(javoid_locs);
	*known = _json_to_locations(jknown_locs);
	*avoid = _json_ids_to_locations(javoid, *avoid);
	*known = _json_ids_to_locations(jknown, *known);
	*force_fair_constraints = json_object_get_boolean(jfair);  // NULL-safe
	return NULL;
}

static enum http_rc_e
_poll(struct req_args_s *args, struct json_object *body)
{
	GError *err = NULL;
	enum http_rc_e code;
	const gchar *policy = OPT("policy");
	const gchar *pool = OPT("pool");
	oio_location_t *avoid = NULL, *known = NULL;
	gboolean force_fair_constraints = FALSE;

	err = _decode_lb_body(body, &avoid, &known, &force_fair_constraints);
	if (err)
		return _reply_common_error(args, err);

	if (pool) {
		pool = g_strdup(pool);
	} else {
		struct storage_policy_s *sp = NULL;
		NSINFO_READ(sp = storage_policy_init(&nsinfo, policy));
		if (!sp) {
			storage_policy_clean(sp);
			return _reply_common_error(args, NEWERROR(
					CODE_POLICY_NOT_SUPPORTED,
					"Invalid storage policy: %s", policy));
		}
		pool = g_strdup(storage_policy_get_service_pool(sp));
		storage_policy_clean(sp);
	}

	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
	void _on_id(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
		g_ptr_array_add(ids, g_strdup(sel->item->id));
	}
	gboolean flawed = FALSE;
	err = oio_lb__patch_with_pool(lb, pool, avoid, known, _on_id, NULL,
			force_fair_constraints, FALSE, &flawed);
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria: ", ids->len);
		code = _reply_common_error(args, err);
	} else {
		if (flawed) {
			args->rp->access_tail("flawed:true");
			gchar metric_name[256] = {0};
			g_snprintf(metric_name, sizeof(metric_name),
					"lb.constraints.%s.flawed.count", pool);
			network_server_incr_stat(args->server, metric_name);
		} else {
			args->rp->access_tail("flawed:false");
		}
		g_ptr_array_add(ids, NULL);
		GString *gstr = _lb_pack_srvid_tab((const char**)ids->pdata);
		code = _reply_json(args, CODE_FINAL_OK, "OK", gstr);
	}

	g_ptr_array_free(ids, TRUE);
	g_free(avoid);
	g_free(known);
	g_free((gpointer)pool);
	return code;
}

enum http_rc_e
action_lb_poll(struct req_args_s *args)
{
	GError *err = NULL;
	args->rp->no_access();
	if (!validate_namespace(NS()))
		err = NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");
	else if (!OPT("policy") && !OPT("pool"))
		err = BADREQ("Missing policy or pool parameter");

	if (err)
		return _reply_notfound_error(args, err);
	return rest_action(args, _poll);
}

enum http_rc_e
action_lb_reload (struct req_args_s *args)
{
	(void) lb_cache_reload();
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
_create_pool(struct req_args_s *args, struct json_object *body)
{
	if (!body || !json_object_is_type(body, json_type_object))
		return _reply_common_error(args, BADREQ("Expected: json object"));

	const gchar *name = OPT("name");

	struct json_object *jtargets = NULL, *jopts = NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"targets", &jtargets, json_type_string, 1},
		{"options", &jopts,    json_type_object, 0},
		{NULL, NULL, 0, 0}
	};
	GError *err = NULL;
	if (body && (err = oio_ext_extract_json(body, mapping))) {
		return _reply_format_error(args, err);
	}

	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lb_world, name);
	oio_lb_world__add_pool_targets(pool, json_object_get_string(jtargets));

	if (jopts) {
		json_object_object_foreach(jopts, key, val) {
			if (json_object_is_type(val, json_type_array) ||
					json_object_is_type(val, json_type_object)) {
				oio_lb_pool__destroy(pool);
				err = BADREQ("Bad value for option %s: "
						"should be a string, integer or boolean", key);
				return _reply_format_error(args, err);
			}
			oio_lb_world__set_pool_option(pool, key,
					json_object_get_string(val));
		}
	}

	oio_lb__force_pool(lb, pool);

	return _reply_created(args);
}

enum http_rc_e
action_lb_create_pool(struct req_args_s *args)
{
	GError *err = NULL;
	gboolean force = oio_str_parse_bool(OPT("force"), FALSE);
	if (!validate_namespace(NS()))
		err = NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");
	else if	(!OPT("name"))
		err = BADREQ("Missing name parameter");
	else if (oio_lb__has_pool(lb, OPT("name")) && !force)
		err = NEWERROR(CODE_CONTENT_EXISTS, "A pool named [%s] already exists",
				OPT("name"));
	if (err)
		return _reply_common_error(args, err);
	return rest_action(args, _create_pool);
}
