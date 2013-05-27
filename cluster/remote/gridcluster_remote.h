/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file gridcluster_remote.h
 */

#ifndef _GRIDCLUSTER_REMOTE_H
#define _GRIDCLUSTER_REMOTE_H

/**
 * @addtogroup gridcluster_remote
 * @{
 */

#include <metatypes.h>
#include <metacomm.h>


/**
 * Get infos about namespace
 *
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the namespace info
 */
namespace_info_t *gcluster_get_namespace_info(addr_info_t *addr,
		long to, GError **error);


/**
 * Get infos about namespace
 * new version supporting namspace options
 *
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the namespace info with options
 */
namespace_info_t *gcluster_get_namespace_info_full(addr_info_t *addr,
		long to, GError **error);


/**
 * Get the full volume list from the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the list of volume_info_t pointers or NULL if an error occured
 */
GSList *gcluster_get_volume_list(addr_info_t *addr, long to,
		GError **error);


/**
 * Get the meta0 from the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return a meta0_info_t pointer or NULL if an error occured
 */
meta0_info_t* gcluster_get_meta0(addr_info_t *addr, long to, GError **error);


/**
 * @param addr
 * @param to_cnx
 * @param to_req
 * @param err
 * @return
 */
meta0_info_t* gcluster_get_meta0_2timeouts(addr_info_t * addr, long to_cnx,
		long to_req, GError ** error);


/**
 * Get the meta0 from the conscience
 *
 * @param addr the conscience addr
 * @param to_cnx
 * @param to_req
 * @param error a glib error pointer
 * @return a meta0_info_t pointer or NULL if an error occured
 */
meta0_info_t * gcluster_get_meta0_2tos(addr_info_t * addr, long to_cnx,
		long to_req, GError ** error);


/**
 * Get the full meta1 list from the conscience
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the list of meta1_info_t pointers or NULL if an error occured
 */
GSList *gcluster_get_meta1_list(addr_info_t *addr, long to, GError **error);


/**
 * Get the full meta2 list from the conscience
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the list of meta2_info_t pointers or NULL if an error occured
 */
GSList *gcluster_get_meta2_list(addr_info_t *addr, long to, GError **error);


/**
 * Push a list of volume_stat_t to the conscience
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to
 * @param vstat a GSList of volume_stat_t
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_volume_stat(addr_info_t *addr, long to, GSList *vstat,
		GError **error);


/**
 * Push a list of meta1_stat_t to the conscience
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to
 * @param mstat a GSList of meta1_stat_t
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_meta1_stat(addr_info_t *addr, long to, GSList *mstat,
		GError **error);


/**
 * Push a list of meta2_stat_t to the conscience
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to
 * @param mstat a GSList of meta2_stat_t
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_meta2_stat(addr_info_t *addr, long to, GSList *mstat,
		GError **error);


/**
 * Push a list of meta2_info_t to the conscience to fix and lock a score
 *
 * @deprecated
 * @param addr the conscience addr
 * @param to a GSList of meta2_info_t
 * @param m2_list
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_meta2_score(addr_info_t *addr, long to,
		GSList *m2_list, GError **error);


/**
 * Push a list of volume_info_t to the conscience to fix and lock a score
 *
 * @param addr the conscience addr
 * @param to
 * @param vol_list
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_vol_score(addr_info_t *addr, long to,
		GSList *vol_list, GError **error);


/**
 * Push a list of broken containers to the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param container_list a GSList of strings
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_broken_container(addr_info_t *addr, long to,
		GSList *container_list, GError **error);


/**
 * @param cnx
 * @param ns_name
 * @param cid
 * @param error
 * @return
 */
gint gcluster_v2_push_broken_container(struct metacnx_ctx_s *cnx,
		const gchar *ns_name, const container_id_t cid, GError **error);


/**
 * @param cnx
 * @param ns_name
 * @param cid
 * @param path
 * @param error
 * @return
 */
gint gcluster_v2_push_broken_content(struct metacnx_ctx_s *cnx,
		const gchar *ns_name, const container_id_t cid, const gchar *path,
		GError **error);


/**
 * Push a list of virtual namespace space used to the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param space_used a GHashTable of strings/gba
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_push_virtual_ns_space_used(addr_info_t * addr,
		long to, GHashTable *space_used, GError ** error);


/**
 * Tell the conscience that a rawx was fully scaned to repair these containers
 *
 * @param addr the conscience addr
 * @param to
 * @param container_list a GSList of strings
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_fix_broken_container(addr_info_t *addr, long to,
		GSList *container_list, GError **error);


/**
 * Remove a list of broken containers from the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param container_list a GSList of strings
 * @param error a glib error pointer
 * @return 1 if succeed, 0 otherwise
 */
gint gcluster_rm_broken_container(addr_info_t *addr, long to,
		GSList *container_list, GError **error);


/**
 * Get the full broken container list from the conscience
 *
 * @param addr the conscience addr
 * @param to
 * @param error a glib error pointer
 * @return the list of containers or NULL if an error occured
 */
GSList *gcluster_get_broken_container(addr_info_t *addr, long to,
		GError **error);


/**
 * Remove a list of broken containers from the conscience
 *
 * @param addr
 * @param to
 * @param type
 * @param error
 * @return 1 if succeed, 0 otherwise
 */
GSList *gcluster_get_services( addr_info_t *addr, long to,
		const gchar *type, GError **error);


/**
 * Get the full broken container list from the conscience
 *
 * @param addr the conscience addr
 * @param to_cnx
 * @param to_req
 * @param type
 * @param error a glib error pointer
 * @return the list of containers or NULL if an error occured
 */
GSList *gcluster_get_services2( addr_info_t *addr, long to_cnx, long to_req,
		const gchar *type, GError **error);


/*!
 * @param addr
 * @param to_cnx
 * @param to_req
 * @param type
 * @param error
 * @return
 */
GSList * gcluster_get_services_from_ctx(struct metacnx_ctx_s *ctx,
		const gchar * type, GError ** error);


/**
 * @param addr
 * @param to
 * @param services_list
 * @param lock_action
 * @param error
 * @return
 */
gint gcluster_push_services(addr_info_t *addr, long to,
		GSList *services_list, gboolean lock_action, GError **error);


/*!
 * With all the stats and all the tags.
 *
 * @see gcluster_get_services_from_ctx()
 * @param ctx
 * @param type
 * @param error
 * @return
 */
GSList* gcluster_get_services_full(struct metacnx_ctx_s *ctx, const gchar * type, GError **error);

/*!
 * @param addr
 * @param to
 * @param name
 * @param error
 * @return
 */
GByteArray* gcluster_get_srvtype_event_config(addr_info_t *addr, long to,
		gchar *name, GError **error);

/** @} */

#endif	/* _GRIDCLUSTER_REMOTE_H */
