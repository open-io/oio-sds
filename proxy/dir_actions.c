/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2024 OVH SAS

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

static GString * _pack_m1url_list (GString *gstr, gchar ** urlv) {
	if (!gstr)
		gstr = g_string_sized_new (128);
	g_string_append_c (gstr, '[');
	for (gchar ** v = urlv; urlv && *v; v++) {
		struct meta1_service_url_s *m1 = meta1_unpack_url (*v);
		meta1_service_url_encode_json (gstr, m1);
		meta1_service_url_clean (m1);
		if (*(v + 1))
			g_string_append_c (gstr, ',');
	}
	g_string_append_c (gstr, ']');
	return gstr;
}

static GString * _pack_and_freev_m1url_list (GString *gstr, gchar ** urlv) {
	gstr = _pack_m1url_list (gstr, urlv);
	g_strfreev (urlv);
	return gstr;
}

static GError * _m1_action (struct oio_url_s *url, gchar ** m1v,
		GError * (*hook) (const char * m1addr)) {
	if (m1v && *m1v) {
		gboolean _wrap (gconstpointer p) {
			gchar *m1u = meta1_strurl_get_address ((const char*)p);
			STRING_STACKIFY (m1u);
			return service_is_ok (m1u);
		}
		gsize len = oio_ext_array_partition ((void**)m1v,
				g_strv_length (m1v), _wrap);
		if (len <= 0) {
			/* Maybe all meta1 databases have been moved
			 * and the old meta1 has been shut down */
			hc_decache_reference(resolver, url);
		} else if (oio_proxy_dir_shuffle) {
			oio_ext_array_shuffle ((void**)m1v, len);
		}
	}

	for (gchar ** pm1 = m1v; *pm1; ++pm1) {
		struct meta1_service_url_s *m1 = meta1_unpack_url (*pm1);
		if (!m1)
			continue;
		if (0 != g_ascii_strcasecmp(m1->srvtype, NAME_SRVTYPE_META1)) {
			meta1_service_url_clean (m1);
			continue;
		}

		struct addr_info_s m1a;
		if (!grid_string_to_addrinfo (m1->host, &m1a)) {
			GRID_INFO ("Invalid META1 [%s] for [%s]",
				m1->host, oio_url_get (url, OIOURL_WHOLE));
			meta1_service_url_clean (m1);
			continue;
		}

		GError *err = hook (m1->host);
		if (err && CODE_IS_NETWORK_ERROR(err->code)) {
			GRID_WARN("M1 cnx error [%s]: (%d) %s",
					m1->host, err->code, err->message);
			service_invalidate (m1->host);
		}
		meta1_service_url_clean (m1);

		if (!err)
			return NULL;
		if (CODE_IS_NETWORK_ERROR (err->code) || err->code == CODE_REDIRECT)
			g_clear_error (&err);
		else {
			if (error_clue_for_decache(err)) {
				hc_decache_reference(resolver, url);
			}
			g_prefix_error (&err, "META1 error: ");
			return err;
		}
	}

	return NEWERROR (CODE_UNAVAILABLE, "No meta1 answered");
}

GError * _m1_locate_and_action(struct req_args_s *args,
		GError * (*hook) (const char * m1addr)) {
	GError *err = NULL;
	gchar **m1v = NULL;
	struct oio_url_s *url = args->url;
	const char *service_id = SERVICE_ID();
	if (service_id) {
		gchar **service_ids = g_strsplit(service_id, OIO_CSV_SEP, -1);
		if (g_strv_length(service_ids) > 1) {
			err = BADREQ("Only one service can be requested");
		} else {
			GPtrArray *tmp = g_ptr_array_new();
			for (gchar **sid = service_ids; *sid; sid++) {
				g_ptr_array_add(tmp, g_strdup_printf("1|%s|%s|",
						NAME_SRVTYPE_META1, *sid));
			}
			g_ptr_array_add(tmp, NULL);
			m1v = (gchar **) g_ptr_array_free(tmp, FALSE);
		}
		g_strfreev(service_ids);
	} else {
		err = hc_resolve_reference_directory(
				resolver, url, &m1v, FALSE, oio_ext_get_deadline());
		if (err) {
			g_prefix_error(&err, "No META1: ");
		}
	}
	if (!err) {
		EXTRA_ASSERT(m1v != NULL);
		err = _m1_action(url, m1v, hook);
	}
	g_strfreev(m1v);
	return err;
}

static GError *decode_json_string_array (gchar *** pkeys,
		struct json_object *j) {
	gchar **keys = NULL;
	GError *err = NULL;

	if (json_object_is_type (j, json_type_null)) {
		*pkeys = g_malloc0(sizeof(void*));
		return NULL;
	}

	// Parse the keys
	if (!json_object_is_type (j, json_type_array))
		return BADREQ ("Invalid/Unexpected JSON");

	GPtrArray *v = g_ptr_array_new ();
	guint count = 0;
	for (gint i = json_object_array_length (j); i > 0; --i) {
		++count;
		struct json_object *item =
			json_object_array_get_idx (j, i - 1);
		if (!json_object_is_type (item, json_type_string)) {
			err = BADREQ ("Invalid string at [%u]", count);
			break;
		}
		g_ptr_array_add (v, g_strdup (json_object_get_string (item)));
	}
	if (!err) {
		g_ptr_array_add (v, NULL);
		keys = (gchar **) g_ptr_array_free (v, FALSE);
	} else {
		g_ptr_array_free (v, TRUE);
	}

	*pkeys = keys;
	return err;
}

/* -------------------------------------------------------------------------- */

static enum http_rc_e
action_dir_srv_link (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("No service type provided"));
	gboolean autocreate = _request_get_flag (args, "autocreate");
	gboolean dryrun = _request_get_flag (args, "dryrun");

	gchar **urlv = NULL;
	GError *hook (const char * m1) {
		return meta1v2_remote_link_service (
				m1, args->url, type, dryrun, autocreate, &urlv,
				oio_ext_get_deadline());
	}

	GError *err = _m1_locate_and_action(args, hook);
	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		hc_decache_reference_service (resolver, args->url, type);
	}

	if (err) {
		if (CODE_IS_NSIMPOSSIBLE(err->code))
			return _reply_forbidden_error (args, err);
		return _reply_common_error (args, err);
	}

	EXTRA_ASSERT (urlv != NULL);
	return _reply_success_json (args, _pack_and_freev_m1url_list (NULL, urlv));
}

static enum http_rc_e
action_dir_srv_force (struct req_args_s *args, struct json_object *jargs)
{
	struct meta1_service_url_s *m1u = NULL;
	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("No service type provided"));

	gboolean force = _request_get_flag (args, "replace");
	gboolean autocreate = _request_get_flag (args, "autocreate");

	GError *hook (const char * m1) {
		gchar *packed = meta1_pack_url (m1u);
		GError *e = meta1v2_remote_force_reference_service (
				m1, args->url, packed, autocreate, force,
				oio_ext_get_deadline());
		g_free (packed);
		return e;
	}

	GError *err = meta1_service_url_load_json_object (jargs, &m1u);

	if (!err)
		err = _m1_locate_and_action(args, hook);
	if (m1u) {
		meta1_service_url_clean (m1u);
		m1u = NULL;
	}

	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		hc_decache_reference_service (resolver, args->url, type);
	}

	if (err) {
		if (CODE_IS_NSIMPOSSIBLE(err->code) || err->code == CODE_SRV_ALREADY)
			return _reply_forbidden_error (args, err);
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_dir_srv_renew (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("No service type provided"));
	gboolean autocreate = _request_get_flag (args, "autocreate");
	gboolean dryrun = _request_get_flag (args, "dryrun");

	gchar **urlv = NULL;
	GError *hook (const char * m1) {
		return meta1v2_remote_renew_reference_service (
				m1, args->url, type, dryrun, autocreate, &urlv,
				oio_ext_get_deadline());
	}

	GError *err = _m1_locate_and_action(args, hook);

	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		hc_decache_reference_service (resolver, args->url, type);
	}

	if (err) {
		if (CODE_IS_NSIMPOSSIBLE(err->code))
			return _reply_forbidden_error (args, err);
		return _reply_common_error (args, err);
	}
	EXTRA_ASSERT (urlv != NULL);
	return _reply_success_json (args, _pack_and_freev_m1url_list (NULL, urlv));
}

/**
 * Find replacements for some services linked to a reference.
 *
 * Expects a JSON object like:
 *
 *  {
 *    "kept": {
 *      "seq": 1,
 *      "type": "meta2",
 *      "host": "192.168.56.1:6005,192.168.56.2:6005",
 *      "args": ""
 *    },
 *    "replaced": {
 *      "seq": 1,
 *      "type": "meta2",
 *      "host": "192.168.56.3:6005",
 *      "args": ""
 *    }
 *  }
 *
 * "kept" is the description of services that must be kept.
 * "replaced" is the description of services that must be replaced.
 * Note that the meta1 expects that the union of "kept" and "replaced"
 * matches exactly the list of services it knows for the specified
 * sequence number.
 */
static enum http_rc_e
action_dir_srv_relink (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	struct meta1_service_url_s *m1u_kept = NULL, *m1u_repl = NULL;
	gchar **newset = NULL;

	const gchar *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("No service type provided"));

	gboolean dryrun = _request_get_flag (args, "dryrun");

	struct json_object *jkept, *jrepl;
	struct oio_ext_json_mapping_s mapping[] = {
		{"kept", &jkept, json_type_object, 0},
		{"replaced", &jrepl, json_type_object, 0},
		{NULL, NULL, 0, 0}
	};
	err = oio_ext_extract_json (jargs, mapping);
	if (!err && !jkept && !jrepl)
		err = BADREQ("Missing [kept] and [replaced]");
	if (!err && jkept) {
		err = meta1_service_url_load_json_object (jkept, &m1u_kept);
		if (err)
			g_prefix_error (&err, "invalid service in [%s]: ", "kept");
	}
	if (!err && jrepl) {
		err = meta1_service_url_load_json_object (jrepl, &m1u_repl);
		if (err)
			g_prefix_error (&err, "invalid service in [%s]: ", "replaced");
	}

	if (!err) {
		gchar *kept = NULL, *repl = NULL;
		GError *hook (const gchar * m1) {
			if (newset)
				g_strfreev (newset);
			return meta1v2_remote_relink_service (
					m1, args->url, kept, repl, dryrun, &newset,
					oio_ext_get_deadline());
		}
		kept = meta1_pack_url (m1u_kept);
		repl = m1u_repl ? meta1_pack_url (m1u_repl) : NULL;
		err = _m1_locate_and_action(args, hook);
		g_free (kept);
		g_free (repl);
	}

	meta1_service_url_clean (m1u_kept);
	meta1_service_url_clean (m1u_repl);

	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		hc_decache_reference_service (resolver, args->url, type);
	}

	if (err) {
		if (newset)
			g_strfreev (newset);
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, _pack_and_freev_m1url_list (NULL, newset));
}

static enum http_rc_e
action_dir_prop_get (struct req_args_s *args, struct json_object *jargs)
{
	gchar **pairs = NULL, **keys = NULL;
	GError *err = decode_json_string_array (&keys, jargs);
	if (!err) {
		GError *hook(const char *m1) {
			if (pairs) g_strfreev(pairs);
			pairs = NULL;
			return meta1v2_remote_reference_get_property(
					m1, args->url, keys, &pairs,
					oio_ext_get_deadline());
		}
		err = _m1_locate_and_action(args, hook);
		g_strfreev(keys);
		keys = NULL;
	}
	if (!err) {
		GString *gs = g_string_sized_new(256);
		// FIXME(FVE): this response should include account and container
		// names. This requires adding headers in meta1 response (because
		// passing these in the properties array would overwrite properties
		// with the same keys).
		g_string_append_static(gs, "{");
		OIO_JSON_append_str(gs, "cid", oio_url_get(args->url, OIOURL_HEXID));
		g_string_append_c(gs, ',');
		g_string_append_static(gs, "\"properties\":");
		KV_encode_gstr2(gs, pairs);
		g_string_append_c(gs, '}');
		g_strfreev(pairs);
		return _reply_success_json(args, gs);
	}
	return _reply_common_error (args, err);
}

static enum http_rc_e
action_dir_prop_set (struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	gboolean flush = NULL != OPT("flush");

	gchar **pairs = NULL;
	if (NULL != (err = KV_read_properties(jargs, &pairs, "properties", TRUE)))
		return _reply_format_error(args, err);

	GError *hook (const char * m1) {
		return meta1v2_remote_reference_set_property (
				m1, args->url, pairs, flush,
				oio_ext_get_deadline());
	}
	err = _m1_locate_and_action(args, hook);
	g_strfreev(pairs);
	if (!err)
		return _reply_success_json (args, NULL);
	return _reply_common_error (args, err);
}

static enum http_rc_e
action_dir_prop_del (struct req_args_s *args, struct json_object *jargs)
{
	gchar **keys = NULL;
	GError *err = decode_json_string_array (&keys, jargs);

	GError *hook (const char *m1) {
		return meta1v2_remote_reference_del_property (
				m1, args->url, keys,
				oio_ext_get_deadline());
	}

	if (!err) {
		err = _m1_locate_and_action(args, hook);
		g_strfreev (keys);
		keys = NULL;
	}
	if (!err)
		return _reply_success_json (args, NULL);
	return _reply_common_error (args, err);
}

static enum http_rc_e
action_dir_ref_create_with_properties (struct req_args_s *args, gchar **props) {
	GError *hook (const char * m1) {
		return meta1v2_remote_create_reference (
				m1, args->url, props,
				oio_ext_get_deadline());
	}
	GError *err = _m1_locate_and_action(args, hook);
	if (!err)
		return _reply_created (args);
	if (err->code == CODE_CONTAINER_EXISTS) {
		g_clear_error (&err);
		return _reply_accepted (args);
	}
	return _reply_common_error (args, err);
}

static enum http_rc_e
action_dir_ref_create (struct req_args_s *args, struct json_object *jargs) {
	gchar **props = NULL;
	if (jargs && json_object_is_type(jargs, json_type_object)) {
		struct json_object *jprops = NULL;
		if (json_object_object_get_ex(jargs, "properties", &jprops)) {
			GError *err = KV_decode_object(jprops, &props);
			if (err)
				return _reply_format_error(args, err);
		}
	}

	enum http_rc_e rc = action_dir_ref_create_with_properties (args, props);
	g_strfreev(props);
	return rc;
}

/* -------------------------------------------------------------------------- */

// DIR{{
// POST /v3.0/{NS}/reference/create?acct={account}&ref={reference name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Create new reference with given properties.
//
// Sample request:
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/create?acct=my_account&ref=myreference HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 13
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: json
//
//    {"properties":{}}
//
// Sample response:
//
// .. code-block:: http
//
//    HTTP/1.1 201 Created
//    Connection: Close
//    Content-Length: 0
//
// }}DIR
enum http_rc_e action_ref_create (struct req_args_s *args) {
	return rest_action(args, action_dir_ref_create);
}

// DIR{{
// GET /v3.0/{NS}/reference/show?acct={account}&ref={reference name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get information about a reference.
//
// Sample request:
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/reference/show?acct=my_account&ref=myreference HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// Sample response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 194
//
// .. code-block:: json
//
//    {
//      "dir":[{"seq":1,"type":"meta0","host":"127.0.0.1:6006","args":""},{"seq":1,"type":"meta1","host":"127.0.0.1:6007","args":""}],
//      "srv":[{"seq":1,"type":"meta2","host":"127.0.0.1:6008","args":""}],
//      "cid":"13C0470DBCE55371E6BD5975EFF23A18F658CDC1656A7474DEF1ED0B0EDDA9FC",
//      "account":"my_account",
//      "name":"myreference"
//    }
//
// }}DIR
enum http_rc_e action_ref_show (struct req_args_s *args) {
	const char *type = TYPE();

	if (!validate_namespace(NS()))
		return _reply_forbidden_error(args, NEWERROR(
					CODE_NAMESPACE_NOTMANAGED, "Namespace not managed"));

	GError *err = NULL;
	gchar **urlv = NULL;
	if (type) {
		err = hc_resolve_reference_service (
				resolver, args->url, type, &urlv, oio_ext_get_deadline());
	} else {
		GError *hook (const char * m1) {
			return meta1v2_remote_list_reference_services (
					m1, args->url, type, &urlv, oio_ext_get_deadline());
		}
		err = _m1_locate_and_action(args, hook);
	}

	if (!err) {
		gchar **dirv = NULL;
		err = hc_resolve_reference_directory(
				resolver, args->url, &dirv, FALSE, oio_ext_get_deadline());
		GString *out = g_string_sized_new (512);
		g_string_append_c (out, '{');
		g_string_append_static (out, "\"dir\":");
		if (dirv)
			out = _pack_and_freev_m1url_list (out, dirv);
		else
			g_string_append_static (out, "null");
		g_string_append_static (out, ",\"srv\":");
		out = _pack_and_freev_m1url_list (out, urlv);

		g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "cid",
				oio_url_get(args->url, OIOURL_HEXID));

		g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "account",
				oio_url_get(args->url, OIOURL_ACCOUNT));

		g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "name",
				oio_url_get(args->url, OIOURL_USER));

		g_string_append_static (out, "}");
		return _reply_success_json (args, out);
	}
	return _reply_common_error (args, err);
}

// DIR{{
// POST /v3.0/{NS}/reference/destroy?acct={account}&ref={reference name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Destroy reference.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/destroy?acct=my_account&ref=myreference HTTP/1.1
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
// }}DIR
enum http_rc_e action_ref_destroy (struct req_args_s *args) {
	gboolean force = _request_get_flag (args, "force");

	GError *hook (const char * m1) {
		return meta1v2_remote_delete_reference (
				m1, args->url, force,
				oio_ext_get_deadline());
	}
	GError *err = _m1_locate_and_action(args, hook);
	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		NSINFO_READ(if (srvtypes) {
			for (gchar ** p = srvtypes; *p; ++p)
				hc_decache_reference_service (resolver, args->url, *p);
		});
		hc_decache_reference(resolver, args->url);
	}
	if (!err)
		return _reply_nocontent (args);
	if (err->code == CODE_USER_INUSE)
		return _reply_forbidden_error (args, err);
	return _reply_common_error (args, err);
}

// DIR{{
// POST /v3.0/{NS}/reference/relink?acct={account}&ref={reference name}&type={type}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {
//      "kept":{"seq":1,"type":"rdir","host":"","args":""},
//      "replaced":{"seq":1,"type":"rdir","host":"127.0.0.1:6011,127.0.0.1:6014","args":""}
//    }
//
// Find replacement for some linked services to a reference
//
// "kept" is the description of services that must be kept.
// "replaced" is the description of services that must be replaced.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/relink?acct=my_account&ref=myreference&type=rdir HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 143
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 117
//
// .. code-block:: json
//
//    [
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6012","args":""},
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6015","args":""}
//    ]
//
// }}DIR
enum http_rc_e action_ref_relink (struct req_args_s *args) {
	return rest_action (args, action_dir_srv_relink);
}

// DIR{{
// POST /v3.0/{NS}/reference/link?acct={account}&ref={reference name}&type={type}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Link services to a reference
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/link?acct=my_account&ref=myreference&type=rdir HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 117
//
// .. code-block:: json
//
//    [
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6010","args":""},
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6015","args":""}
//    ]
//
// }}DIR
enum http_rc_e action_ref_link (struct req_args_s *args) {
	return rest_action (args, action_dir_srv_link);
}

// DIR{{
// POST /v3.0/{NS}/reference/unlink?acct={account}&ref={reference name}&type={type}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Unlink service from a reference
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/unlink?acct=my_account&ref=myreference&type=rdir HTTP/1.1
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
// }}DIR
enum http_rc_e action_ref_unlink (struct req_args_s *args) {
	const char *type = TYPE();
	if (!type)
		return _reply_format_error (args, BADREQ("No service type provided"));

	GError *hook (const char * m1) {
		return meta1v2_remote_unlink_service (
				m1, args->url, type,
				oio_ext_get_deadline());
	}

	GError *err = _m1_locate_and_action(args, hook);

	if (!err || CODE_IS_NETWORK_ERROR(err->code)) {
		/* Also decache on timeout, a majority of request succeed,
		 * and it will probably silently succeed  */
		hc_decache_reference_service (resolver, args->url, type);
	}

	if (!err)
		return _reply_success_json (args, NULL);
	return _reply_common_error (args, err);
}

// DIR{{
// POST /v3.0/{NS}/reference/renew?acct={account}&ref={reference name}&type={type}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/renew?acct=my_account&ref=myreference&type=rdir HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 117
//
// .. code-block:: json
//
//    [
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6010","args":""},
//      {"seq":1,"type":"rdir","host":"127.0.0.1:6015","args":""}
//    ]
//
// }}DIR
enum http_rc_e action_ref_renew (struct req_args_s *args) {
	return rest_action (args, action_dir_srv_renew);
}

// DIR{{
// POST /v3.0/{NS}/reference/force?acct={account}&ref={reference name}&type={type}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {"seq":1,"type":"rdir","host":"127.0.0.1:6010","args":""}
//
// Force service to be linked to a reference
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/force?acct=my_account&ref=myreference&type=rdir HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 59
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}DIR
enum http_rc_e action_ref_force (struct req_args_s *args) {
	return rest_action (args, action_dir_srv_force);
}

// DIR{{
// POST /v3.0/{NS}/reference/get_properties?acct={account}&ref={container name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get reference properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/get_properties?acct=my_account&ref=myreference HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 90
//
// .. code-block:: json
//
//    {
//      "cid":"B6A905025EBA78C555B4437321C176B4F9CC1EF49A45BBA8FA561D7F08592D2D",
//      "properties":{}
//    }
//
// }}DIR
enum http_rc_e action_ref_prop_get (struct req_args_s *args) {
	return rest_action (args, action_dir_prop_get);
}

// DIR{{
// POST /v3.0/{NS}/reference/set_properties?acct={account}&ref={container name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// .. code-block:: json
//
//    {
//      "properties":{"test":"1"}
//    }
//
// Set reference properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/set_properties?acct=my_account&ref=myreference HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 27
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}DIR
enum http_rc_e action_ref_prop_set (struct req_args_s *args) {
	return rest_action (args, action_dir_prop_set);
}

// POST /v3.0/{NS}/reference/del_properties?acct={account}&ref={container name}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// .. code-block:: json
//
//    ["test"]
//
// Set reference properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/reference/del_properties?acct=my_account&ref=myreference HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 8
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}DIR
enum http_rc_e action_ref_prop_del (struct req_args_s *args) {
	return rest_action (args, action_dir_prop_del);
}
