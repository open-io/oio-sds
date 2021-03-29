/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__meta2v2__meta2_backend_h
# define OIO_SDS__meta2v2__meta2_backend_h 1

# include <core/oiolb.h>
# include <meta2v2/meta2_utils.h>
# include <glib.h>

struct meta2_backend_s;
struct event_config_s;
struct sqlx_repository_s;
struct m2v2_create_params_s;
struct hc_resolver_s;

/** Builds a meta2 backend for the given NAMESPACE.  */
GError* meta2_backend_init(struct meta2_backend_s **result,
		struct sqlx_repository_s *repo, const gchar *ns_name,
		struct oio_lb_s *lb, struct hc_resolver_s *resolver);

void meta2_backend_clean(struct meta2_backend_s *m2);

/** Thread-safely set the internal nsinfo of the meta2_backend.
 * The backend is unusable until a valid NS-info has been provided. */
void meta2_backend_configure_nsinfo(struct meta2_backend_s *m2,
		struct namespace_info_s *ns_info);

/** Fills 'dst'with a hollow copy of the internal namespace_info of the given
 * meta2_backend. YOU MUST CLEAN IT USING namespace_info_clear.
 *
 * Be sure a valid namespace_info_s is pointed by dst (a zero'ed ns_info is
 * valid). */
struct namespace_info_s * meta2_backend_get_nsinfo(struct meta2_backend_s *m2);

/** Tests if the backend has been fully initiated. I.e. it checks a
 * valid NSinfo has been provided. */
gboolean meta2_backend_initiated(struct meta2_backend_s *m2);

/** Return a string which contain m2_addr: "IP:PORT" */
const gchar* meta2_backend_get_local_addr(struct meta2_backend_s *m2);

GError *meta2_backend_open_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b, enum sqlx_open_type_e open_mode);

void meta2_backend_close_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b);

void meta2_backend_change_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b);

void meta2_backend_db_properties_change_callback(struct sqlx_sqlite3_s *sq3,
		struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct db_properties_s *db_properties);

/* -------------------------------------------------------------------------- */

GError *meta2_backend_create_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, struct m2v2_create_params_s *params);

GError* meta2_backend_destroy_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, guint32 flags);

GError *meta2_backend_has_container(struct meta2_backend_s *m2,
		struct oio_url_s *url);

GError *meta2_backend_container_isempty (struct meta2_backend_s *m2,
		struct oio_url_s *url);

/* Destroy all contents of a container. */
GError* meta2_backend_flush_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0, gboolean *truncated);

GError* meta2_backend_purge_container(struct meta2_backend_s *m2,
		struct oio_url_s *url, gint64 *pmaxvers, m2_onbean_cb cb, gpointer u0);

/* -------------------------------------------------------------------------- */

GError* meta2_backend_list_aliases(struct meta2_backend_s *m2b, struct oio_url_s *url,
		struct list_params_s *lp, GSList *headers,
		m2_onbean_cb cb, gpointer u0, gchar ***out_properties);

/**
 * @param flags 0 or a combination (ORed) of M2V2_FLAG_ALLVERSION
 *        and M2V2_FLAG_NODELETED */
GError* meta2_backend_get_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/** Delete all the beans listed, regardless of their type. This is REALLY
 * DANGEROUS, do not use this feature. */
GError* meta2_backend_delete_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans);

/** Inserts all the beans listed, as is, regardless of their type. This is REALLY
 * DANGEROUS, do not use this feature. */
GError* meta2_backend_insert_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gboolean frozen, gboolean force);

/** Updates all the beans listed (old by new), as is, regardless of their type.
 * This is REALLY DANGEROUS, do not use this feature. */
GError* meta2_backend_update_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *new_chunks, GSList *old_chunks,
		gboolean frozen);

GError* meta2_backend_notify_container_state(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean recompute,
		gint64 damaged_objects, gint64 missing_chunks);

GError* meta2_backend_put_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in, gint64 missing_chunks,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* meta2_backend_change_alias_policy(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in, gint64 missing_chunks,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* meta2_backend_append_to_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *beans, gint64 missing_chunks,
		m2_onbean_cb cb, gpointer u0);

typedef void (*meta2_send_event_cb)(gchar *event, gpointer udata);

GError* meta2_backend_check_content(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList **beans, gint64 *missing_chunks,
		meta2_send_event_cb send_event, gboolean update);

/** Update a content with the given chunks replacing the existing chunks
 *  at the same position. */
GError *meta2_backend_update_content(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in, gint64 missing_chunks,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

/** Truncate a content at the metachunk whose offset is immediately
 * superior to truncate_size */
GError * meta2_backend_truncate_content(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 truncate_size,
		GSList **out_deleted, GSList **out_added);

/** Create a new version of the ALIAS but with the given chunks linked to
 * the existing CONTENT.  */
GError* meta2_backend_force_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, GSList *in, gint64 missing_chunks,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError * meta2_backend_purge_alias(struct meta2_backend_s *m2,
		struct oio_url_s *url, gint64 *pmaxvers, m2_onbean_cb cb, gpointer u0);

GError *meta2_backend_drain_content(struct meta2_backend_s *m2b,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0);

GError* meta2_backend_delete_alias(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean delete_marker,
		m2_onbean_cb cb, gpointer u0);

/* Properties -------------------------------------------------------------- */

GError* meta2_backend_get_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/** Delete the specified properties, or all properties if "propv" is empty.
 * After success, "out" will contain an alias bean and the property beans
 * that have been deleted (with null values). The caller is responsible for
 * cleaning the list. */
GError* meta2_backend_del_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gchar **propv, GSList **out);

/** Insert the specified properties, delete the ones with no value.
 * After success, "out" will contain an alias bean and the property beans
 * that have been modified. The caller is responsible for cleaning the list. */
GError* meta2_backend_set_properties(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gboolean flush, GSList *beans,
		GSList **out);

/* Back-Links listing ------------------------------------------------------- */

/** Get a list of CONTENT_HEADER ownning the given chunk id. */
GError* meta2_backend_content_from_chunkid (struct meta2_backend_s *m2b,
		struct oio_url_s *url, const gchar* chunk_id,
		m2_onbean_cb cb, gpointer u0);

GError* meta2_backend_content_from_contenthash (struct meta2_backend_s *m2b,
		struct oio_url_s *url, GBytes *h,
		m2_onbean_cb cb, gpointer u0);

GError* meta2_backend_content_from_contentid (struct meta2_backend_s *m2b,
		struct oio_url_s *url, GBytes *h,
		m2_onbean_cb cb, gpointer u0);

/* TESTING ------------------------------------------------------------------ */

GError* meta2_backend_get_alias_version(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *version);

GError* meta2_backend_generate_beans(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 size, const gchar *polname,
		gboolean append, m2_onbean_cb cb, gpointer cb_data);

GError* meta2_backend_get_max_versions(struct meta2_backend_s *m2b,
		struct oio_url_s *url, gint64 *result);

#endif /*OIO_SDS__meta2v2__meta2_backend_h*/
