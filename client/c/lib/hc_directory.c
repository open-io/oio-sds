/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.directory"
#endif

#include "./gs_internals.h"

static gs_error_t*
_create_friendly_error(GError *local_error)
{
	GRID_DEBUG("Original error: (%d) %s", local_error->code,
			local_error->message);

	switch (local_error->code) {
		case CODE_CONTAINER_NOTFOUND :
			return gs_error_new(local_error->code, "This reference does not exist.\n"
					"Please ensure you have create the reference before retry\n");
		case CODE_CONTAINER_EXISTS :
			return gs_error_new(local_error->code, "This reference is already created\n");
		case CODE_CONTAINER_INUSE :
			return gs_error_new(local_error->code, "This reference is still linked with some services.\n");
		case CODE_CONTAINER_PROP_NOTFOUND :
			return gs_error_new(local_error->code, "This kind of service is not managed by your namespace.\n");
		case CODE_CONTENT_PROP_NOTFOUND :
			return gs_error_new(local_error->code, "No more service of this type available.\n");
		case CODE_INTERNAL_ERROR :
			return gs_error_new(local_error->code, "Server internal error\n");
		default :
			return gs_error_new(local_error->code, "Error code not managed "
					"<%d> : %s\n", local_error->code, local_error->message);
	}
	return NULL;
}

typedef GError* (*request_cb) (addr_info_t *a, const container_id_t ref_id,
		gchar **master);

static gs_error_t*
_m1v2_request(gs_grid_storage_t *hc, const gchar *refname, request_cb cb)
{
	GSList *excluded = NULL;
	GError *local_error = NULL;
	gs_error_t *result = NULL;
	addr_info_t *meta1_addr = NULL;
	container_id_t ref_id;

	meta1_name2hash(ref_id, gs_get_full_vns(hc), refname);

	for (;;) {
		meta1_addr = gs_resolve_meta1v2 (hc, ref_id, NULL, 0,
				&excluded, &local_error);

		if (!meta1_addr) {
			result = gs_error_new(CODE_INTERNAL_ERROR, "No META1 found for [%s]", refname);
			break;
		}

		gchar *master = NULL;
		local_error = cb(meta1_addr, ref_id, &master);
		gs_update_meta1_master(hc, ref_id, master);
		g_free(master);
		master = NULL;

		if (!local_error)
			break;

		excluded = g_slist_prepend(excluded, meta1_addr);
		meta1_addr = NULL;

		if (local_error) {
			if (CODE_IS_NETWORK_ERROR(local_error->code))
				g_clear_error(&local_error);
			else {
				result = _create_friendly_error(local_error);
				break;
			}
		}
	}

	if (excluded) {
		g_slist_foreach(excluded, addr_info_gclean, NULL);
		g_slist_free(excluded);
	}
	if (meta1_addr)
		g_free(meta1_addr);
	if (local_error)
		g_clear_error(&local_error);

	return result;
}

/* ------------------------------------------------------------------------- */

gs_error_t*
hc_create_reference(gs_grid_storage_t *hc, const char *reference)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_create_reference(a, &e,
				gs_get_full_vns(hc), ref_id, reference,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_delete_reference(gs_grid_storage_t *hc, const char *reference)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_delete_reference(a, &e,
				gs_get_full_vns(hc), ref_id,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_link_service_to_reference(gs_grid_storage_t *hc, const char *reference, const char *srv_type, char ***result)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		*result = meta1v2_remote_link_service(a, &e,
				gs_get_full_vns(hc), ref_id, srv_type,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_list_reference_services(gs_grid_storage_t *hc, const char *reference, const char *srv_type, char ***result)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		(void) master;
		*result = meta1v2_remote_list_reference_services(a, &e,
				gs_get_full_vns(hc), ref_id, srv_type,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP));
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_unlink_reference_service(gs_grid_storage_t *hc, const char *reference, const char *srv_type)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		if(!strchr(srv_type, '|')) {
			meta1v2_remote_unlink_service(a, &e,
					gs_get_full_vns(hc), ref_id, srv_type,
					gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
					gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
					master);
		} else {
			char **toks = g_strsplit(srv_type, "|", 0);
			gint64 seq = 0;
			if((g_strv_length(toks) < 2) || (0 >= (seq = g_ascii_strtoll(toks[0], NULL, 10)))) {
				e = NEWERROR(CODE_BAD_REQUEST, "Invalid service description [%s]", srv_type);
			} else {
				meta1v2_remote_unlink_one_service(a, &e,
						gs_get_full_vns(hc), ref_id, toks[1],
						gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
						gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
						master, seq);
			}
			g_strfreev(toks);

		}
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_has_reference(gs_grid_storage_t *hc, const char *reference)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_has_reference(a, &e,
				gs_get_full_vns(hc), ref_id,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP));
		(void) rc;
		(void) master;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_force_service(gs_grid_storage_t *hc, const char *reference, const char *url)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_force_reference_service(a, &e,
				gs_get_full_vns(hc), ref_id, url,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_poll_service(gs_grid_storage_t *hc, const char *reference,
		const char *srvtype, char **srv)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gchar **urlv = meta1v2_remote_poll_reference_service(a, &e,
				gs_get_full_vns(hc), ref_id, srvtype,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		if (urlv) {
			*srv = g_strdup(urlv[0]);
			g_strfreev(urlv);
		}
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_configure_service(gs_grid_storage_t *hc, const char *reference,
		const char *url)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_configure_reference_service(a, &e,
				gs_get_full_vns(hc), ref_id, url,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_set_reference_property(gs_grid_storage_t *hc, const char *reference,
		const char *key, const char *value)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		char *pairs[] = {NULL,NULL};
		GError *e = NULL;
		pairs[0] = g_strdup_printf("%s=%s", key, value);
		gint rc = meta1v2_remote_reference_set_property(a, &e,
				gs_get_full_vns(hc), ref_id, pairs,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX), 
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		g_free(pairs[0]);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_get_reference_property(gs_grid_storage_t *hc, const char *reference,
		char **keys, char ***result)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_reference_get_property(a, &e,
				gs_get_full_vns(hc), ref_id, keys, result,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP));
		(void) rc;
		(void) master;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

gs_error_t*
hc_delete_reference_property(gs_grid_storage_t *hc, const char *reference,
		char **keys)
{
	GError* cb(addr_info_t *a, const container_id_t ref_id, gchar **master) {
		GError *e = NULL;
		gint rc = meta1v2_remote_reference_del_property(a, &e,
				gs_get_full_vns(hc), ref_id, keys,
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_CNX),
				gs_grid_storage_get_to_sec(hc, GS_TO_M1_OP),
				master);
		(void) rc;
		return e;
	}

	return _m1v2_request(hc, reference, cb);
}

