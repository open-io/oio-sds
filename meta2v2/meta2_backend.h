#ifndef HC_META2_V1__H
# define HC_META2_V1__H 1

# ifndef  META2_TYPE_NAME
#  define META2_TYPE_NAME "meta2"
# endif

# include <meta2v2/meta2_utils.h>
# include <glib.h>

struct grid_lbpool_s;
struct meta2_backend_s;
struct event_config_s;
struct sqlx_repository_s;
struct m2v2_create_params_s;
struct hc_resolver_s;

/*! Fills 'result' with a valid filename to be used by the sqlx repository.
 *
 * @param ignored
 * @param n
 * @param t
 * @param result
 */
void meta2_file_locator(gpointer ignored, const gchar *n, const gchar *t,
		GString *result);

/*! Builds a meta2 backend for the given NAMESPACE.
 *
 * @param result a placeholder ste in case of success (when return NULL)
 * @param repo the storage for all the bases
 * @param ns_name the namespace name
 * @return the error that occured or NULL in case of success
 */
GError* meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns_name,
		struct grid_lbpool_s *glp, struct hc_resolver_s *resolver);

/*!
 *
 * @param m2
 */
void meta2_backend_clean(struct meta2_backend_s *m2);

/*!
 * Thread-safely set the internal nsinfo of the meta2_backend.
 *
 * The backend is unusable until a valid NS-info has been provided.
 *
 * @param m2
 * @param ns_info
 */
void meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ns_info);

/*!
 * Fills 'dst'with a hollow copy of the internal namespace_info of the given
 * meta2_backend. YOU MUST CLEAN IT USING namespace_info_clear.
 *
 * Be sure a valid namespace_info_s is pointed by dst (a zero'ed ns_info is
 * valid).
 *
 * @param m2
 * @param dst
 * @return
 */
gboolean meta2_backend_get_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *dst);

struct event_config_s * meta2_backend_get_event_config(struct meta2_backend_s *m2,
		const gchar *ns_name);

/*!
 * Tests if the backend has been fully initiated. I.e. it checks a
 * valid NSinfo has been provided.
 *
 * @param m2
 * @return
 */
gboolean meta2_backend_initiated(struct meta2_backend_s *m2);

/**
 * @param m2
 * @param type
 * @param si
 * @return
 */
GError* meta2_backend_poll_service(struct meta2_backend_s *m2,
		const gchar *type, struct service_info_s **si);


/* -------------------------------------------------------------------------- */

GError *meta2_backend_has_master_container(struct meta2_backend_s *m2,
		struct hc_url_s *url);

/*!
 * @param m2
 * @param name
 * @return NULL if the container exists
 */
GError *meta2_backend_has_container(struct meta2_backend_s *m2,
		struct hc_url_s *url);

/*!
 * @param m2
 * @param name
 * @param params
 * @return NULL if the container has been created
 */
GError *meta2_backend_create_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, struct m2v2_create_params_s *params);

#define M2V2_DESTROY_PURGE 0x01 /* XXX Not implemented.
								   performs a PURGE before the destroy */
#define M2V2_DESTROY_FLUSH 0x02 /* cleanly triggers a removal of all the
								   contents, even if snapshots are present. */
#define M2V2_DESTROY_FORCE 0x04 /* destroy even if aliases or snapshots are
								   still present */
#define M2V2_DESTROY_LOCAL 0x08 /* Destroy only the local base */

/*!
 * @param m2
 * @param name
 * @return
 */
GError* meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags);

/*!
 * Destroy all contents of a container.
 *
 * @param m2 A pointer to the meta2 backend
 * @param url The URL of the container to flush
 * @return A GError in case of error, NULL otherwise
 */
GError* meta2_backend_flush_container(struct meta2_backend_s *m2,
		struct hc_url_s *url);




#define M2V2_MODE_DRYRUN  0x10000000
/*!
 * @param m2
 * @param name
 * @return NULL if the container could be purged
 */
GError *meta2_backend_purge_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags, m2_onbean_cb cb, gpointer u0);

/*!
 * For backward compatibility
 *
 * @param m2
 * @param url
 * @return
 */
GError* meta2_backend_open_container(struct meta2_backend_s *m2,
		struct hc_url_s *url);

/*!
 * For backward compatibility
 *
 * @param m2
 * @param url
 * @return
 */
GError* meta2_backend_close_container(struct meta2_backend_s *m2,
		struct hc_url_s *url);

/*!
 * @param m2
 * @param url
 * @param flags Is only accepted M2V2_FLAG_NOFORMATCHECK
 * @param list_of_props
 * @return
 */
GError* meta2_backend_set_container_properties(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags, GSList *list_of_props);

/*!
 * @param m2b
 * @param url
 * @param cb_data
 * @param cb
 * @return
 */
GError* meta2_backend_get_container_properties(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags, gpointer cb_data, m2_onprop_cb cb);

/*!
 * Find and unreference duplicate content headers.
 *
 * @param m2b Pointer to the meta2 backend
 * @param url URL of the container to process
 * @return A GError if an error occurs, NULL otherwise
 */
GError* meta2_backend_deduplicate_contents(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, GString **status_message);

/*!
 * Find and unreference duplicate chunks of a container.
 *
 * @param m2b Pointer to the meta2 backend
 * @param url URL of the container to process
 * @return A GError if an error occurs, NULL otherwise
 */
GError* meta2_backend_deduplicate_chunks(struct meta2_backend_s *m2b,
        struct hc_url_s *url);

/*!
 * Find and unreference duplicate chunks of a content.
 *
 * @param m2b Pointer to the meta2 backend
 * @param url URL of the content to process
 * @return A GError if an error occurs, NULL otherwise
 */
GError* meta2_backend_deduplicate_alias_chunks(struct meta2_backend_s *m2b,
        struct hc_url_s *url);

/* -------------------------------------------------------------------------- */

/*!
 * @param m2b
 * @param url
 * @param lp
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_list_aliases(struct meta2_backend_s *m2b,
		struct hc_url_s *url, struct list_params_s *lp,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param flags 0 or a combination (ORed) of M2V2_FLAG_ALLVERSION
 *        and M2V2_FLAG_NODELETED
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_get_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/*!
 * Create a new version of the ALIAS but with the given chunks linked to
 * the existing CONTENT.
 *
 * @param m2b
 * @param url
 * @param beans
 * @return
 */
GError* meta2_backend_force_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans);

/*!
 * Delete all the beans listed, regardless of their type. This is REALLY
 * DANGEROUS, do not use this feature.
 *
 * @param m2b
 * @param url
 * @param beans
 * @return
 */
GError* meta2_backend_delete_beans(struct meta2_backend_s *m2b,
                struct hc_url_s *url, GSList *beans);

/*!
 * Filters out only the CONTENTS-typed beans and call
 * meta2_backend_delete_beans()
 *
 * @see meta2_backend_delete_beans()
 * @param m2b
 * @param url
 * @param beans
 * @return
 */
GError* meta2_backend_delete_chunks(struct meta2_backend_s *m2b,
                struct hc_url_s *url, GSList *beans);



/*!
 * @param m2b
 * @param url
 * @param bRecalc
 * @return
 */
GError* meta2_backend_refresh_container_size(struct meta2_backend_s *m2b,
				struct hc_url_s *url, gboolean bRecalc);


/*!
 * @param m2b
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_put_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param src
 * @return
 */
GError* meta2_backend_copy_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *src);

/*!
 * @param m2b
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_append_to_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param sync_del TRUE in case of synchronous deletion
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gboolean sync_del,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param k
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_get_all_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *k, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param prop_name
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_get_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name,
		guint32 flags, m2_onbean_cb cb, gpointer u0);

/*!
 * @param m2b
 * @param url
 * @param prop_name
 * @return
 */
GError* meta2_backend_del_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name);

/*!
 * Removes from the DB identified by 'url' the properties named 'prop_name'.
 *
 * This doesn't just flag the properties as deleted.
 *
 * @param m2b
 * @param url
 * @param prop_name
 * @return
 */
GError* meta2_backend_flush_property(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const gchar *prop_name);

/*!
 * Helper for testing purpose
 *
 * @param m2b
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_set_properties(struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/* TESTING ------------------------------------------------------------------ */

/*!
 *
 * @param m2b
 * @param url
 * @param flags
 * @param version
 * @return
 */
GError* meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags, gint64 *version);

/*!
 * @param m2b
 * @param url
 * @param size
 * @param polname
 * @param cb
 * @param cb_data
 * @return
 */
GError* meta2_backend_generate_beans(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 size, const gchar *polname,
		gboolean append, m2_onbean_cb cb, gpointer cb_data);

GError* meta2_backend_generate_beans_v1(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 size, const gchar *polname,
		gboolean append, const char *mdsys, const char *mdusr,
		m2_onbean_cb cb, gpointer cb_data);

/*!
 * @param m2b
 * @param url
 * @param result
 * @return
 */
GError* meta2_backend_get_max_versions(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 *result);

/**
 * @param m2b
 * @param url
 * @param status
 * @return
 */
GError* meta2_backend_get_container_status(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 *status);

/**
 * @param m2b
 * @param url
 * @param expected
 * @param repl
 * @return
 */
GError* meta2_backend_set_container_status(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 *expected, guint32 repl);


/**
 * @param m2b
 * @param url
 * @param beans
 * @return
 */
GError* meta2_backend_update_alias_header(struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans, gboolean skip_checks);

/**
 * Generate spare chunk (in form of a chunk_info list). This function takes care
 * of the storage policy during the chunks generation (distance, nb_chunks,...)
 *
 * @param m2b
 * @param url
 * @param polname
 * @param result
 * @param answer_beans Returned spare chunks are (struct bean_CHUNKS_s *)
 *   instead of (chunk_info_t *)
 * @return
 */
GError* meta2_backend_get_spare_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *polname, GSList **result,
		gboolean answer_beans);

/**
 * Generate spare chunk (in form of a chunk_info list). This function
 * takes care of some informations: the number of wanted chunks, the distance
 * between each chunk, a "not-in" list whose chunks may already used and for
 * which the distance of spare chunks must match, and a "broken" chunk list which
 * is the list of already tried chunks url (e.g for which rawx seems to not work)
 *
 * @param m2b
 * @param url
 * @param count
 * @param dist
 * @param notin
 * @param broken
 * @param result
 * @param answer_beans Returned spare chunks are (struct bean_CHUNKS_s *)
 *   instead of (chunk_info_t *)
 * @return
 */
GError* meta2_backend_get_conditionned_spare_chunks(struct meta2_backend_s *m2b,
		struct hc_url_s *url, gint64 count, gint64 dist, const char *notin,
		const char * broken, GSList **result, gboolean answer_beans);

/**
 * Generate spare chunks (in form of a bean_CHUNKS_s list).
 *
 * @param m2b
 * @param url
 * @param stgpol The name of the storage policy to comply with.
 * @param notin The list of already known chunks (struct bean_CHUNKS_s *),
 *   that should be taken into account when computing distance between chunks.
 * @param broken A list of chunks whose location should be avoided.
 * @param[out] result The list of generated spare chunks.
 * @return A GError in case of error
 */
GError* meta2_backend_get_conditionned_spare_chunks_v2(
		struct meta2_backend_s *m2b, struct hc_url_s *url, const gchar *stgpol,
		GSList *notin, GSList *broken, GSList **result);

/**
 * Take a snapshot of the current state of a container.
 *
 * @param m2b A pointer to the meta2 backend
 * @param url The URL of the container to take snapshot of
 * @param snapshot_name The name to give to the snapshot
 * @return A GError in case of error, or NULL on success
 */
GError* meta2_backend_take_snapshot(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *snapshot_name);

/**
 * Delete a snapshot.
 *
 * @param m2b A pointer to the meta2 backend
 * @param url The URL of the container to delete snapshot from
 * @param snapshot_name The name of the snapshot to delete
 * @return A GError in case of error, or NULL on success
 */
GError* meta2_backend_delete_snapshot(struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *snapshot_name);

/**
 * Get the list of snapshots.
 *
 * @param m2b A pointer to the meta2 backend
 * @param url The URL of the container to list snapshots of
 * @param cb A callback that will be given the snapshot beans
 * @param u0 The first parameter of the callback
 * @return A GError in case of error, NULL otherwise
 */
GError* meta2_backend_list_snapshots(struct meta2_backend_s *m2b,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0);

/**
 * Restore a snapshot by copying all aliases of this snapshot, and putting
 * a deleted flag on all aliases more recent than the snapshot.

 * @param url The URL of the container to list snapshots of
 * @param cb A callback that will be given the snapshot beans
 * @param snapshot_name The name of the snapshot to delete
 * @param hard_restore Instead of making a copy, delete all aliases
 *   more recent than the snapshot
 * @return A GError in case of error, or NULL on success
 */
GError* meta2_backend_restore_snapshot(struct meta2_backend_s *m2b,
        struct hc_url_s *url, const gchar *snapshot_name,
		gboolean hard_restore);

/* ----------------------- */

struct meta2_dumpv1_hooks_s
{
	/*!
	 * @brief Notify a raw content has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_content)  (gpointer u, meta2_raw_content_v2_t *p);

	/*!
	 * @brief Notify a KeyValue pair (admin table) has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_admin)    (gpointer u, key_value_pair_t *p);

	/*!
	 * @brief Notify a container property has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_property) (gpointer u, meta2_property_t *p);

	/*!
	 * @brief Notify a container_event has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_event)    (gpointer u, container_event_t *p);
};


struct meta2_restorev1_hooks_s
{
	/*!
	 * @brief Notify a raw content has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_content)  (gpointer u, const meta2_raw_content_v2_t *p);

	/*!
	 * @brief Notify a KeyValue pair (admin table) has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_admin)    (gpointer u, const key_value_pair_t *p);

	/*!
	 * @brief Notify a container property has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_property) (gpointer u, const meta2_property_t *p);

	/*!
	 * @brief Notify a container_event has been found
	 * @warning The hooks is reponsible for the 'p' liberation
	 * @param u the arbitrary context pointer
	 * @param p a valid pointer to an object found
	 * @return TRUE to continue the dump, FALSE to stop it
	 */
	gboolean (*on_event)    (gpointer u, const container_event_t *p);
};


/**
 * @param m2b
 * @param local_cid
 * @param peer_cid
 * @param peer_addr
 * @param notify_udata
 * @return
 */
GError* meta2_backend_restore_container_from_peer(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const container_id_t peer_cid, const addr_info_t *peer_addr,
		gpointer notify_udata, struct meta2_restorev1_hooks_s (*notify_hooks));

/**
 * Get a list of URLs of contents referencing a specific chunk id.
 *
 * @param limit The maximum number of URLs to get (-1 means no limit)
 */
GError* meta2_backend_get_content_urls_from_chunk_id(
		struct meta2_backend_s *m2b, struct hc_url_s *url,
		const gchar* chunk_id, gint64 limit, GSList **urls);

/**
 * Notifies all meta1 services of modified containers.
 * @param m2b meta2 backend info
 */
void meta2_backend_notify_modified_containers(struct meta2_backend_s *m2b);

/**
 * Builds m0_mapping field in m2b.
 * @param m2b meta2 backend info
 * @return TRUE if successful, FALSE otherwise.
 */
gboolean meta2_backend_build_meta0_prefix_mapping(struct meta2_backend_s *m2b);

/**
 * Returns whether quota is enabled.
 * @param m2b meta2 backend info
 * @return TRUE if quota is enabled, FALSE otherwise
 */
gboolean meta2_backend_is_quota_enabled(struct meta2_backend_s *m2b);

/**
 * Return a string which contain m2_addr: "IP:PORT"
 */
const gchar* meta2_backend_get_local_addr(struct meta2_backend_s *m2);




#endif /* HC_META2_V1__H */
