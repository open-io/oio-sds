/*
OpenIO SDS meta1v2
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

#ifndef OIO_SDS__meta1v2__meta1_remote_h
# define OIO_SDS__meta1v2__meta1_remote_h 1

# include <stdlib.h>
# include <errno.h>
# include <string.h>
# include <unistd.h>

# include <metautils/lib/metacomm.h>

/**
 * @addtogroup meta1v2_remotev1
 * @{
 */

#define NAME_MSGNAME_M1_CREATE     "REQ_M1_CREATE"
#define NAME_MSGNAME_M1_CONT_BY_ID   "REQ_M1_CONT_BY_ID"
#define NAME_MSGNAME_M1_UPDATE_CONTAINERS "REQ_M1_UPDATECONTAINERS"
#define NAME_MSGNAME_M1_GET_VNS_STATE     "REQ_M1_GET_VNS_STATE"

gboolean meta1_remote_create_container_v2 (addr_info_t *meta1, gint ms, GError **err,
		const char *cName, const char *virtualNs, container_id_t cid,
		gdouble to_step, gdouble to_overall, char **master);

struct meta1_raw_container_s* meta1_remote_get_container_by_id(
		struct metacnx_ctx_s *ctx, container_id_t cid, GError **err,
		gdouble to_step, gdouble to_overall);

gboolean meta1_remote_update_containers(gchar *meta1_addr_str,
		GSList *list_of_containers, gint ms, GError **err);

GHashTable* meta1_remote_get_virtual_ns_state(addr_info_t *meta1, gint ms,
		GError **err);

/** @} */

/**
 * @addtogroup meta1v2_remote 
 * @{
 */

// on references
#define NAME_MSGNAME_M1V2_HAS "M1V2_HAS"
#define NAME_MSGNAME_M1V2_CREATE "M1V2_CREATE"
#define NAME_MSGNAME_M1V2_DESTROY "M1V2_DESTROY"
// on services
#define NAME_MSGNAME_M1V2_SRVSET "M1V2_SRVSET"
#define NAME_MSGNAME_M1V2_SRVNEW "M1V2_SRVNEW"
#define NAME_MSGNAME_M1V2_SRVSETARG "M1V2_SRVSETARG"
#define NAME_MSGNAME_M1V2_SRVDEL "M1V2_SRVDEL"
#define NAME_MSGNAME_M1V2_SRVALL "M1V2_SRVALL"
#define NAME_MSGNAME_M1V2_SRVALLONM1 "M1V2_SRVALLONM1"
#define NAME_MSGNAME_M1V2_SRVAVAIL "M1V2_SRVAVAIL"
// On preperties
#define NAME_MSGNAME_M1V2_CID_PROPGET "M1V2_CID_PROPGET"
#define NAME_MSGNAME_M1V2_CID_PROPSET "M1V2_CID_PROPSET"
#define NAME_MSGNAME_M1V2_CID_PROPDEL "M1V2_CID_PROPDEL"
#define NAME_MSGNAME_M1V2_GETPREFIX "M1V2_GET_PREFIXES"
#define NAME_MSGNAME_M1V2_LISTBYPREF "M1V2_LISTBYPREFIX"
#define NAME_MSGNAME_M1V2_LISTBYSERV "M1V2_LISTBYSERV"
#define NAME_MSGNAME_M1V2_UPDATEM1POLICY "M1V2_UPDATEM1POLICY"

#define NAME_HEADER_DRYRUN "DRYRUN"

gboolean meta1v2_remote_create_reference (const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid,
		const gchar *refname, gdouble to_step, gdouble to_overall,
		char **master);

gboolean meta1v2_remote_delete_reference(const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid
		, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_has_reference(const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid,
		gdouble to_step, gdouble to_overall);

gchar ** meta1v2_remote_link_service(const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refID,
		const gchar *service_type, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_unlink_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_unlink_one_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype , gdouble to_step, gdouble to_overall, char **master,
		gint64 seqid);

gchar ** meta1v2_remote_list_reference_services(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall);

gchar** meta1v2_remote_poll_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master);

gchar ** meta1v2_remote_update_m1_policy(const addr_info_t *meta1,
		GError **err, const char *ns,  const container_id_t prefix,
		const container_id_t refid, const gchar *srvtype,
		const gchar* action, gboolean checkonly, const gchar *excludeurl,
		gdouble to_step, gdouble to_overall);

gboolean meta1v2_remote_force_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_configure_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_reference_get_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **keys, gchar ***result, gdouble to_step, gdouble to_overall);

gboolean meta1v2_remote_reference_set_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **pairs, gdouble to_step, gdouble to_overall, char **master);

gboolean meta1v2_remote_reference_del_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **keys, gdouble to_step, gdouble to_overall, char **master);

gchar** meta1v2_remote_list_services(const addr_info_t *m1, GError **err,
        const gchar *ns, const container_id_t refid  );

GError * meta1v2_remote_list_references(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		GByteArray **result);

GError * meta1v2_remote_list_references_by_service(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		const gchar *srvtype, const gchar *url,
		GByteArray **result);

gboolean meta1v2_remote_get_prefixes(const addr_info_t *m1,
		GError **err, gchar ***result );

/** @} */

#endif /*OIO_SDS__meta1v2__meta1_remote_h*/