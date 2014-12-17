#ifndef META2_UTILS__H
# define META2_UTILS__H 1
# include <sqlite3.h>
# include <metautils/lib/metautils.h>
# include <meta2v2/autogen.h>
# include <meta2v2/meta2_utils.h>

# define CODE_SRVTYPE_NOTMANAGED 440

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

struct list_params_s {
	guint32 flags;
	const char *snapshot_name;

	enum {
		S3,
		REDC,
		DEFAULT,
	} type;

	union {
		struct {
			const char *prefix;
			const char *marker;
			const char *delimiter;
			gint64 maxkeys;
		} s3;

		struct {
			const char *name_pattern;
			const char *metadata_pattern;
		} redc;
	} params ;
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


/*!
 * @param str
 * @param ppos
 * @param ppar
 * @param psub
 * @return FALSE if the format is not valid, or a true if the out parameters
 *         have been set
 */
gboolean m2v2_parse_chunk_position(const gchar *str, gint *ppos,
		gboolean *ppar, gint *psub);

/*!
 * @param u
 * @param bean
 */
typedef void (*m2_onbean_cb) (gpointer u, gpointer bean);

/*!
 * @param u
 * @param k
 * @param v
 * @param vlen
 * @return
 */
typedef gboolean (*m2_onprop_cb) (gpointer u, const gchar *k,
		const guint8 *v, gsize vlen);

/**
 * Get the cumulated size of contents in the database.
 */
guint64 m2db_get_container_size(sqlite3 *db, gboolean check_alias);

/**
 * @param sq3 A pointer to the database.
 * @param def The default value if namespace not defined in DB.
 * @return The namespace name defined in the admin table. Must be freed.
 */
gchar *m2db_get_namespace(struct sqlx_sqlite3_s *sq3, const gchar *def);

/*!
 * @param sq3
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_max_versions(struct sqlx_sqlite3_s *sq3, gint64 def);

/*!
 * @param db
 * @param max
 */
void m2db_set_max_versions(struct sqlx_sqlite3_s *sq3, gint64 max);

/**
 * Get the delay before actually deleting a content marked as deleted.
 *
 * @param db Pointer to the meta2 database
 * @param def The default value
 * @return The delay in seconds
 */
gint64 m2db_get_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 def);

/**
 * Set the delay before actually deleting a content marked as deleted.
 *
 * @param db Pointer to the meta2 database
 * @param delay The delay in seconds, or -1 to prevent deletion
 */
void m2db_set_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 delay);

/*!
 * @param db
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_quota(struct sqlx_sqlite3_s *sq3, gint64 def);

/*!
 * @param db
 * @param max
 */
void m2db_set_quota(struct sqlx_sqlite3_s *sq3, gint64 quota);

/*!
 * @param db
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_size(struct sqlx_sqlite3_s *sq3);

/*!
 * @param db
 * @param max
 */
void m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size);

/*!
 * @param db
 * @return
 */
gint64 m2db_get_version(struct sqlx_sqlite3_s *sq3);

/*!
 * @param db
 */
void m2db_increment_version(struct sqlx_sqlite3_s *sq3);

/*!
 *
 * @param db
 * @param flags
 * @param cb_data
 * @param cb
 * @return
 */
GError* m2db_get_container_properties(struct sqlx_sqlite3_s *sq3,
		guint32 flags, gpointer cb_data, m2_onprop_cb cb);

/*!
 * @param db
 * @param url
 */
void m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url);

/*!
 *
 * @param db
 * @param props
 * @return
 */
GError* m2db_set_container_properties(struct sqlx_sqlite3_s *sq3, guint32 flags,
		GSList *props);

/*!
 * @param db
 * @param polname
 * @param repl
 * @return
 */
GError* m2db_set_storage_policy(struct sqlx_sqlite3_s *sq3, const gchar *polname,
		int repl);

/*!
 *
 * @param db
 * @param url
 * @param cb
 * @param u
 * @return
 */
GError* m2db_get_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, m2_onbean_cb cb, gpointer u);

/*!
 * @param db
 * @param lp
 * @param cb
 * @param u
 * @return
 */
GError* m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		m2_onbean_cb cb, gpointer u);

/*!
 * @param db
 * @param url
 * @param flags
 * @param cb
 * @param u
 * @return
 */
GError* m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, m2_onbean_cb cb, gpointer u);

/*!
 * @param db
 * @param k
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_get_all_properties(struct sqlx_sqlite3_s *sq3, const gchar *k,
		guint32 flags, m2_onbean_cb cb, gpointer u0);

/*!
 * @param db
 * @param url
 * @param prop_name
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_get_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar *k, guint32 flags, m2_onbean_cb cb, gpointer u0);

/*!
 * @param db
 * @param url
 * @param k
 * @return
 */
GError* m2db_del_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar *k);

/*!
 * @param db
 * @param k
 * @return
 */
GError* m2db_flush_property(struct sqlx_sqlite3_s *sq3, const gchar *k);

/*!
 * @param db
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_set_properties(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, GSList *beans, m2_onbean_cb cb, gpointer u0);

/*! Get an alias only
 *
 * @param db
 * @param url
 * @param result
 * @return
 */
GError* m2db_latest_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gpointer *result);

/*!
 * @param db
 * @param url
 * @param alias
 * @return
 */
GError* m2db_get_versioned_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gpointer *result);

/*!
 * @param db
 * @param max_versions
 * @param url
 * @param del_chunks Remove no-more referenced chunks from the base
 * @param cb Callback that will receive all unreferenced beans
 * @param u0
 * @return
 */
GError* m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, gboolean del_chunks, m2_onbean_cb cb, gpointer u0);

/* ------------------------------------------------------------------------- */

typedef struct m2v2_chunk_pair_s
{
	struct bean_CONTENTS_s *content;
	struct bean_CHUNKS_s *chunk;
} m2v2_chunk_pair_t;

struct m2v2_check_error_s
{
	GError *original_error; // The optional error that raised this flaw.
	struct bean_ALIASES_s *alias;
	struct bean_CONTENTS_HEADERS_s *header;

	enum m2v2_check_error_type_e {
		M2CHK_CHUNK_DUPLI_BADPOS, // Bad format for position
		M2CHK_CHUNK_DUPLI_GAP, // One position has no chunk at all
		M2CHK_CHUNK_DUPLI_SIZE, // Size mismatch for the given position
		M2CHK_CHUNK_DUPLI_HASH, // Hash mismatch for the given position
		M2CHK_CHUNK_DUPLI_TOOMUCH, // Too many chunk at the same position
		M2CHK_CHUNK_DUPLI_TOOFEW, // Too few chunk at the same position
		M2CHK_CHUNK_DUPLI_BAD_DISTANCE,

		M2CHK_CHUNK_RAIN_BADPOS, // Bad format for position
		M2CHK_CHUNK_RAIN_TOOMUCH, // does not match the policy
		M2CHK_CHUNK_RAIN_TOOFEW, // Too few but repairable
		M2CHK_CHUNK_RAIN_LOST, // Too many chunks missing, reconstruction not possible
		M2CHK_CHUNK_RAIN_BAD_DISTANCE,
		M2CHK_CHUNK_RAIN_BAD_ALGO,

		M2CHK_CONTENT_SIZE_MISMATCH,
		M2CHK_CONTENT_STGCLASS,
		M2CHK_RAWX_UNKNOWN, // RAWX not found in services
	} type;

	union {
		// Duplication
		struct {
			m2v2_chunk_pair_t pair;
		} dupli_badpos;
		struct {
			gint first_missing;
			gint last_missing;
		} dupli_gap;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_hashes;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_sizes;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
			gint count; // nb exceeding chunks
		} chunk_dupli_toomuch;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
			gint count; // nb missing chunks
			guint dist; // nb missing chunks
		} chunk_dupli_toofew;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_dist;

		// RAIN
		struct {
			m2v2_chunk_pair_t pair;
		} rain_badpos;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_toomuch;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
			GArray *pairs_unavailable; // m2v2_chunk_pair_t
			gint64 metachunk_pos;
		} rain_toofew;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_lost;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_dist;

		// COMMON
		struct {
			m2v2_chunk_pair_t pair;
		} rawx_unknown;
		struct {
			GArray *bad_pairs; // m2v2_chunk_pair_t
			GArray *all_pairs; // m2v2_chunk_pair_t
		} stgclass;

	} param;
};

#define M2V2_CHECK_GAPS 0x01
#define M2V2_CHECK_DIST 0x02
#define M2V2_CHECK_STGCLS 0x04
#define M2V2_CHECK_SRVINFO 0x08

struct check_args_s
{
	struct grid_lbpool_s *lbpool;
	struct namespace_info_s *ns_info;
	guint32 mask_checks;
};

struct m2v2_check_s
{
	struct namespace_info_s *ns_info;
	struct grid_lbpool_s *lbpool;
	struct hc_url_s *url;

	GPtrArray *aliases; // <struct bean_ALIASES_s*>
	GPtrArray *headers; // <struct bean_CONTENTS_HEADERS_s*>
	GPtrArray *contents; // <struct bean_CONTENTS_s*>
	GPtrArray *chunks; // <struct bean_CHUNKS_s*>
	GPtrArray *props; // <struct bean_PROPERTIES_s*>

	GPtrArray *unavail_chunks; // <struct bean_CHUNKS_s*>

	GPtrArray *flaws; // <struct m2v2_check_error_s*>
	guint8 flags; // Private use
};

guint32 m2db_get_mask_check_put(struct namespace_info_s *ni);

struct m2v2_check_s* m2v2_check_create(struct hc_url_s *url,
		struct check_args_s *args);

void m2v2_check_feed_with_bean_list(struct m2v2_check_s *check, GSList *beans);

GError* m2v2_check_consistency(struct m2v2_check_s *check);

void m2v2_check_destroy(struct m2v2_check_s *check);

/* ------------------------------------------------------------------------- */

/*!
 * @param url
 * @param beans
 * @param args optional arguments
 * @return
 */
GError* m2db_check_alias_beans_list(struct hc_url_s *url, GSList *beans,
		struct check_args_s *args);

/*!
 *
 * @param db
 * @param url
 * @param flags
 * @param version
 * @return
 */
GError* m2db_get_alias_version(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		guint32 flags, gint64 *version);

struct m2db_put_args_s
{
	struct sqlx_sqlite3_s *sq3;
	gint64 max_versions;
	struct hc_url_s *url;
	struct namespace_info_s nsinfo;
	struct grid_lbpool_s *lbpool;
};

/*!
 * @param args
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param db
 * @param url
 * @param beans
 * @return
 */
//GError* m2db_force_alias(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, GSList *beans);
GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *beans);


/*!
 * @param args
 * @param source
 * @return
 */
GError* m2db_copy_alias(struct m2db_put_args_s *args, const char *source);

/*!
 * @param db
 * @param max_versions
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, namespace_info_t *ni,
		gint64 max_versions, struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param url
 * @param size
 * @param chunk_size
 * @param pol
 * @param iter
 * @param cb
 * @param cb_udata
 * @return
 */
GError* m2_generate_beans(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		m2_onbean_cb cb, gpointer cb_data);

GError* m2_generate_beans_v1(struct hc_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, const char *mdsys, const char *mdusr,
		struct grid_lb_iterator_s *iter, m2_onbean_cb cb, gpointer cb_data);

/*!
 * @param url
 * @param pol
 * @param iter
 * @param result A list of (chunk_info_t *)
 * @return
 */
GError* m2_generate_spare_chunks(struct hc_url_s *url, struct storage_policy_s *pol,
		struct grid_lb_iterator_s *iter, GSList **result);

/*!
 * @param url
 * @param pol
 * @param iter
 * @param result A list of (struct bean_CHUNKS_s *)
 * @return
 */
GError* m2_generate_spare_chunks_beans(struct hc_url_s *url,
		struct storage_policy_s *pol, struct grid_lb_iterator_s *iter,
		GSList **result);

/*!
 * @param iter
 * @param opt
 * @param filter
 * @param result A list of (chunk_info_t *)
 * @return
 */
GError* m2_generate_conditionned_spare_chunks(struct grid_lb_iterator_s *iter,
		struct lb_next_opt_s *opt, service_filter filter, GSList **result);

/*!
 * @param iter
 * @param opt
 * @param filter
 * @param result A list of (struct bean_CHUNKS_s *)
 * @return
 */
GError* m2_generate_conditionned_spare_chunks_beans(struct grid_lb_iterator_s *iter,
		struct lb_next_opt_s *opt, service_filter filter, GSList **result);

/*!
 * @param db
 * @param url
 * @param nsinfo
 * @param result
 * @return
 */
GError* m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result);

/*!
 * @param db
 * @param status
 * @return
 */
GError* m2db_get_container_status(struct sqlx_sqlite3_s *sq3, guint32 *status);

/*!
 * @param db
 * @param r
 * @return
 */
GError* m2db_set_container_status(struct sqlx_sqlite3_s *sq3, guint32 r);

/*!
 * @param db
 * @param beans
 * @return
 */
GError* m2db_update_alias_header(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct hc_url_s *url, GSList *beans, gboolean skip_checks);

/*!
 * @param db
 * @param content
 * @return
 */
GError* m2db_delete_content(struct sqlx_sqlite3_s *sq3, gpointer content);

/*!
 * @param db
 * @param chunk
 * @return
 */
GError* m2db_delete_chunk(struct sqlx_sqlite3_s *sq3, gpointer chunk);

/*!
 * Substitute chunks by another one in the whole container.
 *
 * @param sq3 Pointer to sqlx m2v2 database (container)
 * @param url URL of the container
 * @param new_chunk Chunk to substitute to old_chunks
 * @param old_chunks Chunks to be substituted by new_chunk
 * @return a GError in case of error, NULL otherwise
 */
GError* m2db_substitute_chunk_everywhere(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url,
		struct bean_CHUNKS_s *new_chunk, GSList *old_chunks,
		m2_onbean_cb cb, gpointer udata);

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

/**
 * Delete all aliases of the container, without doing any check.
 *
 * @param db A pointer to the database
 * @return A GError if an error occurs, NULL otherwise
 */
GError* m2db_flush_container(sqlite3 *db);

/**
 * Run a chunk deduplication cycle on the meta2 database.
 *
 * @param db The meta2 database object to search duplicate chunks in
 * @param url
 * @return A GError in case of error, NULL otherwise
 */
GError* m2db_deduplicate_chunks(struct sqlx_sqlite3_s *sq3,
		namespace_info_t *nsinfo, struct hc_url_s *url);

/**
 * Run a chunk deduplication cycle on a specific alias of the meta2 database.
 *
 * @param db The meta2 database object to search duplicate chunks in
 * @param url
 * @return A GError in case of error, NULL otherwise
 */
GError* m2db_deduplicate_alias_chunks(struct sqlx_sqlite3_s *sq3,
		namespace_info_t *nsinfo, struct hc_url_s *url);

GError* m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, guint32 flags, GString **status_message);

/**
 * Get a list of URLs of contents referencing a specific chunk id.
 *
 * @param limit the maximum number of urls to get (-1 means no limit)
 */
GError* m2db_content_urls_from_chunk_id(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, const gchar* chunk_id, gint64 limit,
		GSList **urls);

/**
 * Create a new alias for each existing alias of the container, with
 * incremented version number, so all aliases of the container share the same
 * container_version, and can be included in a snapshot.
 *
 * This function can also restore a snapshot by using the container_version
 * parameter.
 *
 * @param db The meta2 database pointer
 * @param container_version The container version to copy aliases from, or -1
 * @param set_deleted Set the deleted flag to TRUE on duplicated aliases
 * @param overwrite_latest Use version number of the most recent alias for the duplicate
 * @return A GError in case of error, NULL on success
 */
GError* m2db_dup_all_aliases(struct sqlx_sqlite3_s *sq3,
		gint64 container_version, gboolean set_deleted,
		gboolean overwrite_latest);

/**
 * Save a list of snapshot beans to the database.
 *
 * @param db A pointer to the database
 * @param beans A list of (struct bean_SNAPSHOTS_s *)
 * @param cb A callback called after each successfully saved snapshot
 * @param u0 First parameter for the callback
 * @return A GError in case of error, NULL otherwise
 */
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

/*!
 * @param id
 * @param rc
 * @return
 */
GSList* m2v2_beans_from_raw_content(const char *id, meta2_raw_content_t *rc);

/*!
 * @param id
 * @param rc
 * @param make_pos
 * @param udata
 * @return
 */
GSList* m2v2_beans_from_raw_content_custom(const char *id, meta2_raw_content_t *rc,
		char* (*make_pos) (guint32, void*), void *udata);

/*!
 * @param beans
 * @return
 */
meta2_raw_content_t* raw_content_from_m2v2_beans(const container_id_t cid, GSList *beans);

/*!
 * @param id Hexadecimal content id (can be NULL if computed later)
 * @param rc
 * @return
 */
GSList* m2v2_beans_from_raw_content_v2(const char *id, meta2_raw_content_v2_t *rc);

/*!
 * @param cid
 * @param beans
 * @return
 */
meta2_raw_content_v2_t* raw_content_v2_from_m2v2_beans(const container_id_t cid,
		GSList *beans);

/*!
 * @param beans
 * @return
 */
GSList* chunk_info_list_from_m2v2_beans(GSList *beans, char **mdsys);

/*!
 * @param beans
 * @return
 */
GSList* m2v2_beans_from_chunk_info_list(GByteArray *id, const char *alias,
		GSList *chunks);

/**
 * Converts a property bean to an old meta2_property_t.
 */
meta2_property_t *bean_to_meta2_prop(struct bean_PROPERTIES_s *in_prop);

/* chunk_pair */
void init_chunk_pair(GPtrArray *chunks, chunk_pair_t *pair, struct bean_CONTENTS_s *c0);

gint compare_pairs_positions(chunk_pair_t *c0, chunk_pair_t *c1);

/* MISC */
char * extract_url_from_chunk(struct bean_CHUNKS_s *chunk);

char * location_from_chunk(struct bean_CHUNKS_s *chunk, struct grid_lbpool_s *glp);

void m2v2_dup_alias(struct dup_alias_params_s *params, gpointer bean);

#endif
