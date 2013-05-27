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

#ifndef HC_META2_V1__H
# define HC_META2_V1__H 1

# ifndef  META2_TYPE_NAME
#  define META2_TYPE_NAME "meta2"
# endif

# include <glib.h>
# include <meta2_utils.h>

struct meta2_backend_s;
struct sqlx_repository_s;
struct m2v2_create_params_s;

/*! Fills 'result' with a valid filename to be used by the sqlx repository.
 *
 * @param ignored
 * @param n
 * @param t
 * @param result
 */
void meta2_file_locator(gpointer ignored, const gchar *n, const gchar *t,
		GString *result);

/*!
 *
 * @param result a placeholder ste in case of success (when return NULL)
 * @param repo the storage for all the bases
 * @param ns_name the namespace name
 * @return the error that occured or NULL in case of success
 */
GError* meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns_name);

/*!
 *
 * @param m2
 */
void meta2_backend_clean(struct meta2_backend_s *m2);

/*!
 * @param m2
 * @param type
 * @param iter
 */
void meta2_backend_configure_type(struct meta2_backend_s *m2, const gchar *type,
		struct grid_lb_iterator_s *iter);

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

/*!
 * @param m2
 * @param name
 * @return
 */
GError* meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, guint32 flags);

#define M2V2_DESTROY_PURGE 0x01 /* XXX Not implemented.
								   performs a PURGE before the destroy */
#define M2V2_DESTROY_FLUSH 0x02 /* XXX Not implemented.
								   cleanly triggers a removal of all the
								   contents, even if snapshots are present. */
#define M2V2_DESTROY_FORCE 0x04 /* even if aliases or snapshots are still
								   present */

/*!
 * @param m2
 * @param name
 * @return NULL if the container could be purged
 */
GError *meta2_backend_purge_container(struct meta2_backend_s *m2,
		struct hc_url_s *url, GSList** del_chunks_list);

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
		struct hc_url_s *url, GString **status_message);

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
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_list_aliases(struct meta2_backend_s *m2b,
		struct hc_url_s *url, guint32 flags,
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
 * Delete ALL CHUNKS entry in container db matching ALL chunks contained by the beans list
 * the existing CONTENT.
 *
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
 * @param cb
 * @param u0
 * @return
 */
GError* meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0);

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
		GSList *beans);

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
#endif /* HC_META2_V1__H */
