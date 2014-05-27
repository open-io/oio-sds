/**
 * @file gridcluster_remote.h
 */

#ifndef _GRIDCLUSTER_REMOTE_H
#define _GRIDCLUSTER_REMOTE_H

/**
 * @addtogroup gridcluster_remote
 * @{
 */

#include <metautils/lib/metacomm.h>


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


meta0_info_t* gcluster_get_meta0(addr_info_t *addr,
		long to, GError **error);

meta0_info_t* gcluster_get_meta0_2timeouts(addr_info_t * addr,
		long to_cnx, long to_req, GError ** error);

meta0_info_t * gcluster_get_meta0_2tos(addr_info_t * addr,
		long to_cnx, long to_req, GError ** error);


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
 * Get the list of service types from conscience.
 *
 * @param addr The address of the conscience
 * @param timeout The timeout in milliseconds
 * @param [out] error A pointer to a GError*, that will be not NULL
 *   if an error occurs
 * @return A GSList* with the service types (gchar*)
 */
GSList *gcluster_get_service_types(addr_info_t *addr, long timeout,
		GError **error);

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
