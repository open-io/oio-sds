/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__meta2v2__meta2_utils_h
# define OIO_SDS__meta2v2__meta2_utils_h 1

# include <sqlite3.h>
# include <metautils/lib/metautils.h>
# include <meta2v2/autogen.h>
# include <meta2v2/meta2_utils.h>

#define CONTAINER_STATUS_ENABLED 0x00000000
#define CONTAINER_STATUS_FROZEN  (guint32)-1
#define CONTAINER_STATUS_DISABLED (guint32)-2

#define VERSIONS_ENABLED(max_versions) (max_versions > 1 || max_versions < 0)
#define VERSIONS_SUSPENDED(max_versions) (max_versions == 1)
#define VERSIONS_DISABLED(max_versions) (max_versions == 0)
#define VERSIONS_UNLIMITED(max_versions) (max_versions < 0)

#define SNAPSHOTS_ENABLED(max_versions) (VERSIONS_ENABLED(max_versions))

struct storage_policy_s;
struct hc_url_s;
struct grid_lb_iterator_s;
struct lb_next_opt_s;
struct chunk_pair_s;
struct sqlx_sqlite3_s;

typedef struct m2v2_chunk_pair_s
{
	struct bean_CONTENTS_s *content;
	struct bean_CHUNKS_s *chunk;
} m2v2_chunk_pair_t;

struct list_params_s
{
	gint64 maxkeys;
	const char *snapshot;
	const char *prefix;
	const char *marker_start;
	const char *marker_end;
	guint8 flag_nodeleted :1;
	guint8 flag_allversion :1;
	guint8 flag_headers:1;
};

typedef struct chunk_pair_s
{
	struct bean_CONTENTS_s *content;
	struct bean_CHUNKS_s *chunk;
	struct {
		gint meta;
		gint rain;
		gboolean parity;
	} position;
} chunk_pair_t;

struct dup_alias_params_s
{
	struct sqlx_sqlite3_s *sq3;
	gint64 c_version;
	gint64 src_c_version;
	gboolean overwrite_latest;
	gboolean set_deleted;
	GSList *errors;
};

gboolean m2v2_parse_chunk_position(const gchar *str, gint *ppos,
		gboolean *ppar, gint *psub);

typedef void (*m2_onbean_cb) (gpointer u, gpointer bean);

typedef gboolean (*m2_onprop_cb) (gpointer u, const gchar *k,
		const guint8 *v, gsize vlen);

/** Get the cumulated size of contents in the database.  */
guint64 m2db_get_container_size(sqlite3 *db, gboolean check_alias);

/**
 * @param sq3 A pointer to the database.
 * @param def The default value if namespace not defined in DB.
 * @return The namespace name defined in the admin table. Must be freed.
 */
gchar *m2db_get_namespace(struct sqlx_sqlite3_s *sq3, const gchar *def);

gint64 m2db_get_max_versions(struct sqlx_sqlite3_s *sq3, gint64 def);

void m2db_set_max_versions(struct sqlx_sqlite3_s *sq3, gint64 max);

/** Get the delay before actually deleting a content marked as deleted.  */
gint64 m2db_get_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 def);

/** Set the delay before actually deleting a content marked as deleted. */
void m2db_set_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 delay);

gint64 m2db_get_quota(struct sqlx_sqlite3_s *sq3, gint64 def);

void m2db_set_quota(struct sqlx_sqlite3_s *sq3, gint64 quota);

gint64 m2db_get_size(struct sqlx_sqlite3_s *sq3);

void m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size);

gint64 m2db_get_version(struct sqlx_sqlite3_s *sq3);

void m2db_increment_version(struct sqlx_sqlite3_s *sq3);

GError* m2db_get_container_properties(struct sqlx_sqlite3_s *sq3,
		guint32 flags, gpointer cb_data, m2_onprop_cb cb);

void m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url);

GError* m2db_set_container_properties(struct sqlx_sqlite3_s *sq3, guint32 flags,
		GSList *props);

GError* m2db_get_alias1(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, struct bean_ALIASES_s **out);

GError* m2db_get_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, m2_onbean_cb cb, gpointer u);

GError* m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		m2_onbean_cb cb, gpointer u);

GError* m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		m2_onbean_cb cb, gpointer u);

GError* m2db_del_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gchar **namev);

GError* m2db_flush_property(struct sqlx_sqlite3_s *sq3, const gchar *k);

GError* m2db_set_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		GSList *beans, m2_onbean_cb cb, gpointer u0);

/*! Get an alias only */
GError* m2db_latest_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct bean_ALIASES_s **out);

GError* m2db_get_versioned_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gpointer *result);

GError* m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, gboolean del_chunks, m2_onbean_cb cb, gpointer u0);

/* ------------------------------------------------------------------------- */

GError* m2db_get_alias_version(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gint64 *version);

struct m2db_put_args_s
{
	struct sqlx_sqlite3_s *sq3;
	gint64 max_versions;
	struct hc_url_s *url;
	struct namespace_info_s nsinfo;
	struct grid_lbpool_s *lbpool;
};

GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *beans);

GError* m2db_copy_alias(struct m2db_put_args_s *args, const char *source);

GError* m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, namespace_info_t *ni,
		gint64 max_versions, struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

GError* m2_generate_beans(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		m2_onbean_cb cb, gpointer cb_data);

GError* m2_generate_beans_v1(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, const char *mdsys, const char *mdusr,
		struct grid_lb_iterator_s *iter, m2_onbean_cb cb, gpointer cb_data);

/*! @param result A list of (chunk_info_t *) */
GError* m2_generate_spare_chunks(struct hc_url_s *url, struct storage_policy_s *pol,
		struct grid_lb_iterator_s *iter, GSList **result);

/*! @param result A list of (struct bean_CHUNKS_s *) */
GError* m2_generate_spare_chunks_beans(struct hc_url_s *url,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		GSList **result);

/*! @param result A list of (chunk_info_t *) */
GError* m2_generate_conditionned_spare_chunks(struct grid_lb_iterator_s *iter,
		struct lb_next_opt_s *opt, service_filter filter, GSList **result);

/*! @param result A list of (struct bean_CHUNKS_s *) */
GError* m2_generate_conditionned_spare_chunks_beans(struct grid_lb_iterator_s *iter,
		struct lb_next_opt_s *opt, service_filter filter, GSList **result);

GError* m2db_set_storage_policy(struct sqlx_sqlite3_s *sq3, const gchar *polname,
		int repl);

GError* m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result);

GError* m2db_get_container_status(struct sqlx_sqlite3_s *sq3, guint32 *status);

GError* m2db_set_container_status(struct sqlx_sqlite3_s *sq3, guint32 r);

GError* m2db_update_alias_header(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, GSList *beans);

GError* m2db_purge_alias_being_deleted(struct sqlx_sqlite3_s *sq3, GSList *beans,
		GSList **deleted);

/**
 * @param db
 * @param max_versions Maximum number of versions to keep
 * @param retention_delay Delay in seconds before actually purging
 *     a deleted alias (use -1 to keep all deleted aliases)
 * @param flags: M2V2_DRYRUN_MODE, ...
 * @param cb: callback for chunks that have been removed from
 *     the database, and that should be removed from disk
 * @param u0: argument for the callback
 * @return
 */
GError* m2db_purge(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gint64 retention_delay, guint32 flags, m2_onbean_cb cb, gpointer u0);

/** Delete all aliases of the container, without doing any check.  */
GError* m2db_flush_container(sqlite3 *db);

/** Run a chunk deduplication cycle on the meta2 database.  */
GError* m2db_deduplicate_chunks(struct sqlx_sqlite3_s *sq3,
		namespace_info_t *nsinfo, struct hc_url_s *url);

/** Run a chunk deduplication cycle on a specific alias of the meta2 database. */
GError* m2db_deduplicate_alias_chunks(struct sqlx_sqlite3_s *sq3,
		namespace_info_t *nsinfo, struct hc_url_s *url);

GError* m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, guint32 flags, GString **status_message);

/** Get a list of URLs of contents referencing a specific chunk id.  */
GError* m2db_content_urls_from_chunk_id(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar* chunk_id, gint64 limit,
		GSList **urls);

/**
 * Create a new alias for each existing alias of the container, with
 * incremented version number, so all aliases of the container share the same
 * container_version, and can be included in a snapshot.
 *
 * This function can also restore a snapshot by using the container_version
 * parameter. */
GError* m2db_dup_all_aliases(struct sqlx_sqlite3_s *sq3,
		gint64 container_version, gboolean set_deleted,
		gboolean overwrite_latest);

/** Save a list of snapshot beans to the database. */
GError* m2db_set_snapshots(struct sqlx_sqlite3_s *sq3, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/**
 * Take a snapshot of the specified container version with a specific name
 *
 * @param db A pointer to the database
 * @param name A name for the snapshot
 * @param version The container version to create a snapshot of
 * @param cb A callback called after successfully saving the snapshot
 *     (can be NULL)
 * @param u0 First parameter for the callback
 * @return A GError in case of error, NULL otherwise
 *
 * @note The callback, if provided, is responsible for freeing the
 * @note snapshot bean it gets as second parameter.
 */
GError* m2db_take_snapshot(struct sqlx_sqlite3_s *sq3, const gchar *name,
		m2_onbean_cb cb, gpointer u0);

/**
 * Get snapshots by name and/or version.
 *
 * @param db A pointer to the database
 * @param name The name of the snapshot or NULL
 * @param version The version of the snapshot or any negative number
 * @param cb A callback called with the snapshot beans
 * @param u0 First parameter for the callback
 * @return A GError in case of error, NULL otherwise
 *
 * @note The callback is responsible for freeing the snapshot beans.
 *
 * @note If name is NULL and version is negative, all snapshots
 * @note will be returned.
 */
GError* m2db_get_snapshots(struct sqlx_sqlite3_s *sq3, const gchar *name,
		gint64 version, m2_onbean_cb cb, gpointer u0);

/**
 * Get one snapshot by its name.
 *
 * @param db A pointer to the database
 * @param name The name of the snapshot (must not be NULL)
 * @param[out] snapshot The pointer to where the snapshot bean should be saved
 * @return A GError in case of error or snapshot not found, NULL otherwise
 *
 * @note The calling function is responsible for freeing the snapshot
 */
GError* m2db_get_snapshot_by_name(struct sqlx_sqlite3_s *sq3, const gchar *name,
		struct bean_SNAPSHOTS_s **snapshot);

/**
 * Delete a snapshot.
 *
 * @param db A pointer to the database
 * @param snapshot The snapshot to delete
 * @return A GError in case of error, NULL on success
 */
GError* m2db_delete_snapshot(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot);

/**
 * Restore a snapshot by copying all aliases of this snapshot, and putting
 * a deleted flag on all aliases more recent than the snapshot.
 *
 * @param db A pointer to the database
 * @param snapshot The snapshot to restore
 * @param hard_restore Instead of creating new aliases, delete all aliases
 *   more recent than the snapshot
 * @return A GError in case of error, NULL on success
 */
GError* m2db_restore_snapshot(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot, gboolean hard_restore);

/**
 * Restore one alias from a snapshot.
 *
 * @param db A pointer to the database
 * @param snapshot The snapshot to restore alias from
 * @param alias_name The name of the alias to restore
 * @return A GError in case of error, NULL on success
 */
GError* m2db_restore_snapshot_alias(struct sqlx_sqlite3_s *sq3,
		struct bean_SNAPSHOTS_s *snapshot, const gchar *alias_name);

/**
 * Check if an alias is part of a snapshot.
 *
 * @note This function does a request to the database, and is not efficient
 *
 * @note If snapshots are disabled, returns false immediately
 */
gboolean is_in_a_snapshot(struct sqlx_sqlite3_s *sq3,
		struct bean_ALIASES_s *alias);

/* --------- TYPE CONVERSION ---------- */

/*!  */
GSList* m2v2_beans_from_raw_content(const char *id, meta2_raw_content_t *rc);

/*!  */
GSList* m2v2_beans_from_raw_content_custom(const char *id, meta2_raw_content_t *rc,
		char* (*make_pos) (guint32, void*), void *udata);

/*!  */
meta2_raw_content_t* raw_content_from_m2v2_beans(const container_id_t cid, GSList *beans);

/*! @param id Hexadecimal content id (can be NULL if computed later) */
GSList* m2v2_beans_from_raw_content_v2(const char *id, meta2_raw_content_v2_t *rc);

/*!  */
meta2_raw_content_v2_t* raw_content_v2_from_m2v2_beans(const container_id_t cid,
		GSList *beans);

/*!  */
GSList* chunk_info_list_from_m2v2_beans(GSList *beans, char **mdsys);

/*!  */
GSList* m2v2_beans_from_chunk_info_list(GByteArray *id, const char *alias,
		GSList *chunks);

/** Converts a property bean to an old meta2_property_t. */
meta2_property_t *bean_to_meta2_prop(struct bean_PROPERTIES_s *in_prop);

/* chunk_pair */
void init_chunk_pair(GPtrArray *chunks, chunk_pair_t *pair, struct bean_CONTENTS_s *c0);

gint compare_pairs_positions(chunk_pair_t *c0, chunk_pair_t *c1);

/* MISC */
char * extract_url_from_chunk(struct bean_CHUNKS_s *chunk);

char * location_from_chunk(struct bean_CHUNKS_s *chunk, struct grid_lbpool_s *glp);

void m2v2_dup_alias(struct dup_alias_params_s *params, gpointer bean);

#endif /*OIO_SDS__meta2v2__meta2_utils_h*/
