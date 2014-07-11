/**
 * @file meta1_remote.h
 */

#ifndef __META1_REMOTE_H__
#define __META1_REMOTE_H__

# include <stdlib.h>
# include <errno.h>
# include <string.h>
# include <unistd.h>

# include <metautils/lib/metacomm.h>

/**
 * @addtogroup meta1v2_remotev1
 * @{
 */

#define NAME_MSGNAME_M1_INFO       "REQ_M1_INFO"
#define NAME_MSGNAME_M1_CREATE     "REQ_M1_CREATE"
#define NAME_MSGNAME_M1_DESTROY    "REQ_M1_DESTROY"
#define NAME_MSGNAME_M1_GET        "REQ_M1_GET"
#define NAME_MSGNAME_M1_GETFLAGS   "REQ_M1_GETFLAGS"
#define NAME_MSGNAME_M1_SETFLAGS   "REQ_M1_SETFLAGS"
#define NAME_MSGNAME_M1_RANGE_ADD  "REQ_M1_RANGE_ADD"
#define NAME_MSGNAME_M1_RANGE_DEL  "REQ_M1_RANGE_DEL"
#define NAME_MSGNAME_M1_RANGE_GET  "REQ_M1_RANGE_GET"
#define NAME_MSGNAME_M1_RANGE_SET  "REQ_M1_RANGE_SET"
#define NAME_MSGNAME_M1_RANGE_LIST "REQ_M1_RANGE_LIST"
#define NAME_MSGNAME_M1_GETALLONM2   "REQ_M1_GETALLONM2"
#define NAME_MSGNAME_M1_FORCECREATE  "REQ_M1_FORCECREATE"
#define NAME_MSGNAME_M1_CONT_BY_ID   "REQ_M1_CONT_BY_ID"
#define NAME_MSGNAME_M1_CONT_BY_NAME "REQ_M1_CONT_BY_NAME"
#define NAME_MSGNAME_M1_GETMATCHES   "REQ_M1_GETMATCHES"
#define NAME_MSGNAME_M1_MIGRATE_CONTAINER "REQ_M1_MIGRATECONTAINER"
#define NAME_MSGNAME_M1_UPDATE_CONTAINERS "REQ_M1_UPDATECONTAINERS"
#define NAME_MSGNAME_M1_GET_VNS_STATE     "REQ_M1_GET_VNS_STATE"

/**
 * @see meta1_remote_destroy_container_with_flags()
 */
#define M1FLAG_DESTROY_FORCED    0x00000001

/**
 * @see meta1_remote_destroy_container_with_flags()
 */
#define M1FLAG_DESTROY_NOFOLLOW  0x00000002

/**
 * Create a container on a GridStorage, starting on the given META1 server.
 *
 * A call to ths function tells the META1 server to find and contact a
 * META2 server to store the container.
 *
 * Both the name and the ID of the container must be valid NULL terminated
 * character arrays.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cName The name of the container
 * @param cid the identifier of the container
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_create_container (addr_info_t *meta1, gint ms, GError **err,
		const char *cName, container_id_t cid);


/**
 * Create a container on a GridStorage, starting on the given META1 server.
 *
 * A call to ths function tells the META1 server to find and contact a
 * META2 server to store the container.
 *
 * Both the name and the ID of the container must be valid NULL terminated
 * character arrays.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cName The name of the container
 * @param virtualNs The name of the virtualNamespace
 * @param cid the identifier of the container
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_create_container_v2 (addr_info_t *meta1, gint ms, GError **err,
		const char *cName, const char *virtualNs, container_id_t cid,
		gdouble to_step, gdouble to_overall, char **master);


/**
 * Destroys a container on a GridStorage when its META1 location is known.
 *
 * The targeted META1 server must be the META1 server that manages the
 * container associated to the given name. The remote server will contact
 * the meta2 servers that store the container and tell them to  destroy it.
 *
 * This function has been made for convenience. It is equivalent to
 * meta1_remote_destroy_container_by_id() used with the result of meta1_name2hash()
 * on the given container name.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cName the nae of the container to be destroyed.
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_destroy_container_by_name (addr_info_t *meta1, gint ms, GError **err,
		const char *cName, gdouble to_step, gdouble to_overall, char **master);


/**
 * Destroys a container on a GridStorage. The container is identified
 * with its name.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cid the identifier of the container.
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_destroy_container_by_id (addr_info_t *meta1, gint ms, GError **err,
	const container_id_t cid);


/**
 * @param meta1
 * @param ms
 * @param err
 * @param cid
 * @param flags
 * @return
 */
gboolean meta1_remote_destroy_container_with_flags (addr_info_t *meta1, gint ms, GError **err,
	const container_id_t cid, guint32 flags, gdouble to_step, gdouble to_overall, char **master);


/**
 * Locate a META2 server managing a container identified by its name
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cName a not-NULL pointer to a NULL terminated byte array.
 * 
 * @return NULL in case of failure, a valid list af addr_info_t* in case of success.
 */
GSList* meta1_remote_get_meta2_by_container_name (addr_info_t *meta1, gint ms, GError **err,
	const char *cName);


/**
 * Locate a META2 server managing a container identified by its identifier
 *
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cid a pointer to the container identifier
 * 
 * @return NULL in case of failure, a valid list af addr_info_t* in case of success.
 */
GSList* meta1_remote_get_meta2_by_container_id (addr_info_t *meta1, gint ms, GError **err,
	const container_id_t cid, gdouble to_step, gdouble to_overall);


/**
 * Changes th eflag on the container on the distant META1 server.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cid a valid pointer to the indentifier to the container.
 * @param flags the new set of flags
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_set_container_flag (addr_info_t *meta1, gint ms, GError **err,
	const container_id_t cid, guint32 flags);


/**
 * Retrieves the flags set on the remote container.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param cid a valid pointer to the identifier of the container.
 * @param flags a pointer to the integer that will be set with the flags set
 *              on the distat container.
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_get_container_flag (addr_info_t *meta1, gint ms, GError **err,
	const container_id_t cid, guint32 *flags);


/**
 * Delete a whole range of container's identifiers in the targeted META1 server.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param prefix
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_range_del (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix);


/**
 * Add a new range of container's identifiers in the targeted META1 server
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param prefix the targeted prefix
 * @param pData the data that will be associated to this prefix
 * 
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_range_add (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData);


/**
 * Set the attributes of a container's ID ranges on the targeted META1 server.
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param prefix the targeted prefix
 * @param pData the prefix parameters to be set
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_range_set (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData);


/**
 * Retrieves the parameters associated to this prefix on a META1 server
 *
 * @param meta1 the address of the META1 that has to manage the new container
 * @param ms the maximum time (in ms) spent in network latencies)
 * @param err an error structure set if the function fails.
 * @param prefix the targeted prefix
 * @param pData a valid pointer to a structure that will be set.
 * @return TRUE in case of success, FALSE in case of failure.
 */
gboolean meta1_remote_range_get (addr_info_t *meta1, gint ms, GError **err,
		prefix_t prefix, prefix_data_t *pData);


/**
 * Returns a pointer to a GSList of pointers to GByteArray
 * @param meta1
 * @param ms
 * @param err
 * @return
 */
GSList* meta1_remote_range_list( addr_info_t *meta1, gint ms, GError **err);


/**
 * Contact the META1 and ask about the container ID stored on the META2-directory
 * whose address is given
 *
 * @param ctx
 * @param m2_addr
 * @param err
 * @return
 */
GSList* meta1_remote_get_containers_on_meta2( struct metacnx_ctx_s *ctx,
		addr_info_t *m2_addr, GError **err);


/**
 * @param ctx 
 * @param cid
 * @param name
 * @param addr_list 
 * @param err 
 * @return 
 */
gboolean meta1_remote_force_creation( struct metacnx_ctx_s *ctx, GError **err,
		const container_id_t cid, const gchar *name, GSList *addr_list);


/**
 * Get the raw META1 entry (struct meta1_raw_container_s) for the given container id
 *
 * @param ctx
 * @param cid
 * @param err
 * @return
 */
struct meta1_raw_container_s* meta1_remote_get_container_by_id(
		struct metacnx_ctx_s *ctx, container_id_t cid, GError **err,
		gdouble to_step, gdouble to_overall);


/**
 * Get the raw META1 entry (struct meta1_raw_container_s) for the given container name
 *
 * @param ctx
 * @param container_name
 * @param err
 * @return
 */
struct meta1_raw_container_s* meta1_remote_get_container_by_name(
		struct metacnx_ctx_s *ctx, gchar *container_name, GError **err);

/**
 * @param ctx
 * @param list_of_patterns
 * @param result
 * @param err
 * @return
 */
gboolean meta1_remote_get_container_names_matching(struct metacnx_ctx_s *ctx,
		GSList *list_of_patterns, GSList **result, GError **err);


/**
 * @brief
 * @param cnx
 * @param cid
 * @param old_m2
 * @param new_m2
 * @param new_set
 * @param gerr
 * @return
 */
gboolean meta1_remote_change_container_reference(struct metacnx_ctx_s *cnx,
		const container_id_t cid, const addr_info_t *old_m2,
		const addr_info_t *new_m2, GSList **new_set, GError **gerr);


/**
 * @param meta1
 * @param list_of_containers
 * @param ms
 * @param err
 * @return
 */
gboolean
meta1_remote_update_containers(gchar *meta1_addr_str, GSList *list_of_containers,
		gint ms, GError **err);


/**
 * @param meta1
 * @param ms
 * @param err
 * @return
 */
GHashTable* meta1_remote_get_virtual_ns_state(addr_info_t *meta1, gint ms,
		GError **err);


/** @} */

/**
 * @addtogroup meta1v2_remote 
 * @{
 */

#define NAME_MSGNAME_M1V2_HAS "M1V2_HAS"
#define NAME_MSGNAME_M1V2_CREATE "M1V2_CREATE"
#define NAME_MSGNAME_M1V2_DESTROY "M1V2_DESTROY"
#define NAME_MSGNAME_M1V2_SRVSET "M1V2_SRVSET"
#define NAME_MSGNAME_M1V2_SRVNEW "M1V2_SRVNEW"
#define NAME_MSGNAME_M1V2_SRVSETARG "M1V2_SRVSETARG"
#define NAME_MSGNAME_M1V2_SRVDEL "M1V2_SRVDEL"
#define NAME_MSGNAME_M1V2_SRVALL "M1V2_SRVALL"
#define NAME_MSGNAME_M1V2_SRVALLONM1 "M1V2_SRVALLONM1"
#define NAME_MSGNAME_M1V2_SRVAVAIL "M1V2_SRVAVAIL"
#define NAME_MSGNAME_M1V2_CID_PROPGET "M1V2_CID_PROPGET"
#define NAME_MSGNAME_M1V2_CID_PROPSET "M1V2_CID_PROPSET"
#define NAME_MSGNAME_M1V2_CID_PROPDEL "M1V2_CID_PROPDEL"
#define NAME_MSGNAME_M1V2_GETPREFIX "M1V2_GET_PREFIXES"
#define NAME_MSGNAME_M1V2_OPENALL "M1V2_OPENALL"
#define NAME_MSGNAME_M1V2_LISTBYPREF "M1V2_LISTBYPREFIX"
#define NAME_MSGNAME_M1V2_LISTBYSERV "M1V2_LISTBYSERV"
#define NAME_MSGNAME_M1V2_UPDATEM1POLICY "M1V2_UPDATEM1POLICY"

#define NAME_HEADER_DRYRUN "DRYRUN"

/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @param refname
 * @return
 */
gboolean meta1v2_remote_create_reference (const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid,
		const gchar *refname, gdouble to_step, gdouble to_overall,
		char **master);


/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @return 
 */
gboolean meta1v2_remote_delete_reference(const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid
		, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @return
 */
gboolean meta1v2_remote_has_reference(const addr_info_t *meta1,
		GError **err, const gchar *ns, const container_id_t refid,
		gdouble to_step, gdouble to_overall);


/**
 * @param meta1
 * @param err
 * @param ns
 * @param refID
 * @param service_type
 * @return
 */
gchar ** meta1v2_remote_link_service(const addr_info_t *meta1, GError **err,
		const char *ns, const container_id_t refID,
		const gchar *service_type, gdouble to_step, gdouble to_overall, char **master);



/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @param srvtype
 * @return
 */
gboolean meta1v2_remote_unlink_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param ...
 */
gboolean meta1v2_remote_unlink_one_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype , gdouble to_step, gdouble to_overall, char **master,
		gint64 seqid);

/**
 * @param meta1
 * @param err
 * @param ns
 * @param refID
 * @param service_type
 * @return
 */
gchar ** meta1v2_remote_list_reference_services(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall);


/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @param srvtype
 * @return
 */
gchar** meta1v2_remote_poll_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *srvtype, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param meta1
 * @param err
 * @param ns
 * @param prefix
 * @param refid
 * @param srvtype
 * @param action
 * @param checkonly
 * @param excludeurl
 * @return
 */
gchar **
meta1v2_remote_update_m1_policy(const addr_info_t *meta1,
                GError **err, const char *ns,  const container_id_t prefix, const container_id_t refid,
                const gchar *srvtype, const gchar* action, gboolean checkonly, const gchar *excludeurl, gdouble to_step, gdouble to_overall);
/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @param url
 * @return
 */
gboolean meta1v2_remote_force_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master);


/**
 * @param meta1
 * @param err
 * @param ns
 * @param refid
 * @param url
 * @return
 */
gboolean meta1v2_remote_configure_reference_service(const addr_info_t *meta1,
		GError **err, const char *ns, const container_id_t refid,
		const gchar *url, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param m1
 * @param ns
 * @param err
 * @param refid
 * @param keys
 * @param result
 * @return
 */
gboolean meta1v2_remote_reference_get_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **keys, gchar ***result, gdouble to_step, gdouble to_overall);

/**
 * @param m1
 * @param err
 * @param ns
 * @param refid
 * @param pairs
 * @return
 */
gboolean meta1v2_remote_reference_set_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **pairs, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param m1
 * @param err
 * @param ns
 * @param refid
 * @param keys
 * @return
 */
gboolean meta1v2_remote_reference_del_property(const addr_info_t *m1,
		GError **err, const gchar *ns, const container_id_t refid,
		gchar **keys, gdouble to_step, gdouble to_overall, char **master);

/**
 * @param m1
 * @param ns
 * @param refid
 * @parem result
 * @return
 */
gchar** meta1v2_remote_list_services(const addr_info_t *m1, GError **err,
        const gchar *ns, const container_id_t refid  );


/**
 * @param m1
 * @param ns
 * @param refid
 * @parem result
 * @return
 */
GError * meta1v2_remote_list_references(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		GByteArray **result);

/**
 * @param m1
 * @param ns
 * @param refid
 * @param srvtype
 * @param url
 * @param result
 * @return
 */
GError * meta1v2_remote_list_references_by_service(const addr_info_t *m1,
		const gchar *ns, const container_id_t refid,
		const gchar *srvtype, const gchar *url,
		GByteArray **result);



/**
 * @param m1
 * @param err
 * @param result
 * @return
 */
gboolean meta1v2_remote_get_prefixes(const addr_info_t *m1,
		GError **err, gchar ***result );

/** @} */

#endif /*__META1_REMOTE_H__*/
