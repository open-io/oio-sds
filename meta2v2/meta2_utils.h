/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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
# include <core/oiolb.h>
# include <metautils/lib/metautils.h>
# include <meta2v2/meta2_utils.h>
# include <meta2v2/autogen.h>

#define VERSIONS_UNLIMITED(V) ((V) < 0)
#define VERSIONS_DISABLED(V)  ((V) == 0)
#define VERSIONS_SUSPENDED(V) ((V) == 1)
#define VERSIONS_ENABLED(V)   ((V) < 0 || (V) > 1)
#define VERSIONS_LIMITED(V)   ((V) > 1)

#define CHUNK_METHOD_DRAINED "drained"

#define LAST_UNICODE_CHAR "\xf4\x8f\xbf\xbd"

struct storage_policy_s;
struct oio_url_s;
struct sqlx_sqlite3_s;

struct list_params_s
{
	gint64 maxkeys;
	const char *prefix;
	const char *delimiter;
	const char *marker_start;
	const char *version_marker;
	const char *marker_end;
	guint8 flag_mpu_marker_only:1;
	guint8 flag_nodeleted :1;
	guint8 flag_allversion:1;
	guint8 flag_headers   :1;
	guint8 flag_properties:1;
	guint8 flag_local     :1;
	guint8 flag_recursion :1;
};

struct m2v2_position_s {
	int meta, intra;
	unsigned int flag_parity : 1;
	unsigned int flag_rain : 1;
	unsigned int flag_ok : 1;
};

struct m2v2_sorted_content_s {
	struct bean_CONTENTS_HEADERS_s *header;
	GSList *aliases;    // GSList<struct bean_ALIASES_s*>
	GSList *properties; // GSList<struct bean_PROPERTIES_s*>
	GTree *metachunks;  // GTree<gint,GSList<struct bean_CHUNKS_s*>>
};

struct checked_content_s;

void m2v2_position_encode(GString *out, struct m2v2_position_s *p);

struct m2v2_position_s m2v2_position_decode(const char *str);

/* If the chunk has a short ID, with only a service ID, replace it
 * by a full URL composed of the service ID and a path generated
 * from an object's description, the storage policy and the chunk position.
 * Returns an error if something is missing and the chunk URL could
 * not be computed. */
GError *m2v2_extend_chunk_url(struct oio_url_s *url, const gchar *policy,
		struct bean_CHUNKS_s *chunk);

/* Sort the beans of a content. Use m2v2_sorted_content_free to free
 * the result. The beans must be freed separately. */
void m2v2_sort_content(GSList *beans, struct m2v2_sorted_content_s **content);

/* For each chunk of the content, replace the short chunk ID by a full URL,
 * if the chunk ID is not already a URL. Returns an error if something is
 * missing from the object description and at least one chunk URL could
 * not be computed. */
GError *m2v2_sorted_content_extend_chunk_urls(
		struct m2v2_sorted_content_s *content, struct oio_url_s *url);


/* Ensure chunk position to insert is not already present. */
GError *m2v2_check_chunk_uniqueness(
		struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, const GSList *beans,
		struct namespace_info_s *nsinfo);

/* Free a sorted content (the beans must be freed separately). */
void m2v2_sorted_content_free(struct m2v2_sorted_content_s *content);

/* Remove protocol and path from the chunk's URL, keen only the service ID. */
void m2v2_shorten_chunk_id(struct bean_CHUNKS_s *bean);

/* Remove the protocol and path from chunk URLs, keen only service IDs.
 * If meta2.store_chunk_ids is false, do nothing. */
void m2v2_shorten_chunk_ids(GSList *beans);

typedef void (*m2_onbean_cb) (gpointer u, gpointer bean);

/** Recompute the cumulated size and number of contents in the database
 * 	(for each policy). */
void m2db_recompute_container_size_and_obj_count(struct sqlx_sqlite3_s *sq3,
		gboolean check_alias);

/** Get the number of shard ranges in the database. */
void m2db_get_container_shard_count(struct sqlx_sqlite3_s *sq3,
		gint64 *shard_count_out);

gint64 m2db_get_max_versions(struct sqlx_sqlite3_s *sq3, gint64 def);

void m2db_set_max_versions(struct sqlx_sqlite3_s *sq3, gint64 max);

gint64 m2db_get_ctime(struct sqlx_sqlite3_s *sq3);

void m2db_set_ctime(struct sqlx_sqlite3_s *sq3, gint64 now);

/** Get the delay before actually deleting a content marked as deleted.  */
gint64 m2db_get_keep_deleted_delay(struct sqlx_sqlite3_s *sq3, gint64 def);

/** Get the flag to delete exceeding versions. */
gint64 m2db_get_flag_delete_exceeding_versions(struct sqlx_sqlite3_s *sq3,
		gint64 def);

gint64 m2db_get_quota(struct sqlx_sqlite3_s *sq3, gint64 def);

gint64 m2db_get_size(struct sqlx_sqlite3_s *sq3);

gint64 m2db_get_size_by_policy(struct sqlx_sqlite3_s *sq3, const gchar *policy);

gchar** m2db_get_size_properties_by_policy(struct sqlx_sqlite3_s *sq3);

void m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size);

void m2db_set_size_by_policy(struct sqlx_sqlite3_s *sq3, gint64 size,
		const gchar *policy);

void m2db_update_size(struct sqlx_sqlite3_s *sq3, gint64 inc,
		const gchar *policy);

gint64 m2db_get_obj_count(struct sqlx_sqlite3_s *sq3);

gint64 m2db_get_obj_count_by_policy(struct sqlx_sqlite3_s *sq3,
		const gchar *policy);

gchar** m2db_get_obj_count_properties_by_policy(struct sqlx_sqlite3_s *sq3);

void m2db_set_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count);

void m2db_set_obj_count_by_policy(struct sqlx_sqlite3_s *sq3, gint64 count,
		const gchar *policy);

void m2db_update_obj_count(struct sqlx_sqlite3_s *sq3, gint64 inc,
		const gchar *policy);

gint64 m2db_get_shard_count(struct sqlx_sqlite3_s *sq3);

void m2db_set_shard_count(struct sqlx_sqlite3_s *sq3, gint64 count);

void m2db_increment_version(struct sqlx_sqlite3_s *sq3);

void m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url);

GError* m2db_get_sharding_lower(struct sqlx_sqlite3_s *sq3, gchar **result);

GError* m2db_get_sharding_upper(struct sqlx_sqlite3_s *sq3, gchar **result);

gint64 m2db_get_drain_obj_count(struct sqlx_sqlite3_s *sq3);

void m2db_set_drain_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count);

void m2db_del_drain_obj_count(struct sqlx_sqlite3_s *sq3);

gint64 m2db_get_drain_state(struct sqlx_sqlite3_s *sq3);

void m2db_set_drain_state(struct sqlx_sqlite3_s *sq3, gint64 state);

void m2db_del_drain_state(struct sqlx_sqlite3_s *sq3);

GError* m2db_get_drain_marker(struct sqlx_sqlite3_s *sq3, gchar **result);

void m2db_set_drain_marker(struct sqlx_sqlite3_s *sq3, const gchar *marker);

void m2db_del_drain_marker(struct sqlx_sqlite3_s *sq3);

gint64 m2db_get_drain_timestamp(struct sqlx_sqlite3_s *sq3);

void m2db_set_drain_timestamp(struct sqlx_sqlite3_s *sq3, gint64 timestamp);

void m2db_del_drain_timestamp(struct sqlx_sqlite3_s *sq3);

/* Get just the ALIAS, with version allowed */
GError* m2db_get_alias1(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		guint32 flags, struct bean_ALIASES_s **out);

/* Get the BEANS starting at the ALIAS pointed by <url>
 * with version and recursion allowed */
GError* m2db_get_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		guint32 flags, m2_onbean_cb cb, gpointer u);

/* Get the version on the ALIAS specified by <url>. */
GError* m2db_get_alias_version(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gint64 *version);

/*! Get just the alias with the latest version, whatever the version in <url> */
GError* m2db_latest_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct bean_ALIASES_s **out);

/* Get just the ALIAS with version allowed */
GError* m2db_get_versioned_alias(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct bean_ALIASES_s **out);

/* Check if alias doesn't exist */
GError* check_alias_doesnt_exist(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url);

/* Check if alias doesn't exist separately checking the path and the content ID */
GError* check_alias_doesnt_exist2(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url);

/** List objects (a.k.a aliases) in the container.
 *
 * @param[out] next_marker Name of the last alias encountered before the
 *                         deadline (possibly a delete marker), to be used
 *                         as lp.marker_start when calling this function again
 */
GError* m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		GSList *headers, m2_onbean_cb cb, gpointer u, gchar **next_marker);

GError* m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u);

/* Delete the specified properties, or all properties if "namev" is empty.
 * After success, "out" will contain an alias bean and the property beans
 * that have been deleted (will null values). The caller is responsible for
 * cleaning the list. */
GError* m2db_del_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gchar **namev, GSList **out);

/* Insert the specified properties, delete the ones with no value.
 * After success, "out" will contain an alias bean and the property beans
 * that have been modified. The caller is responsible for cleaning the list. */
GError* m2db_set_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gboolean flush, GSList *beans, GSList **out);

GError* m2db_drain_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0);

GError* m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gboolean bypass_governance, gboolean create_delete_marker,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0,
		gboolean *delete_marker_created);

void checked_content_free(struct checked_content_s *checked_content);

void checked_content_append_json_string(struct checked_content_s *checked_content,
		GString *message);

GError* m2db_check_content(struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo,
		struct checked_content_s **checked_content, gboolean update);

GError* m2db_update_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		GSList *beans, m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_truncate_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gint64 truncate_size, GSList **out_deleted, GSList **out_added);

/* ------------------------------------------------------------------------- */

struct m2db_put_args_s
{
	struct sqlx_sqlite3_s *sq3;
	struct oio_url_s *url;
	gint64 ns_max_versions;
	// Should be true when in WORM mode and no admin flag
	gboolean worm_mode;
	gboolean preserve_chunk_ids;
};

GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_change_alias_policy(struct m2db_put_args_s *args,
		GSList *new_beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_restore_drained(struct m2db_put_args_s *args,
		GSList *new_beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *in,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_append_to_alias(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

GError* m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		m2_onbean_cb cb, gpointer cb_data, gboolean *flawed);

GError* m2db_set_storage_policy(struct sqlx_sqlite3_s *sq3, const gchar *polname,
		int repl);

GError* m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result);

/**
 * @param db
 * @param max_versions Maximum number of versions to keep
 * @param retention_delay Delay in seconds before actually purging
 *     a deleted alias (use -1 to keep all deleted aliases)
 * @param flags: M2V2_DRYRUN_MODE, ...
 * @param cb: callback for lists of beans (one list per alias)
 *     that have been removed from the database,
 *     and that should be notified
 * @param u0: argument for the callback
 * @return
 */
GError* m2db_purge(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		gint64 retention_delay, const gchar *alias,
		m2_onbean_cb cb, gpointer u0);

/** Delete all aliases of the container, without doing any check.  */
GError* m2db_flush_container(struct sqlx_sqlite3_s *sq3, m2_onbean_cb cb,
		gpointer u0, gboolean *truncated);

GError* m2db_drain_container(struct sqlx_sqlite3_s *sq3, m2_onbean_cb cb,
		gpointer u0, gint64 limit, gboolean *truncated);

GError* m2db_transition_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s* nsinfo, gboolean* updated, gboolean* send_event,
		const gchar *new_policy, gboolean force_event_emit);

/* --- Low level ----------------------------------------------------------- */

/** Generate a chunk "bean", filled with only an address and ctime. */
struct bean_CHUNKS_s *generate_chunk_bean(struct oio_url_s *url,
		const gchar *pos, struct oio_lb_selected_item_s *sel,
		const struct storage_policy_s *policy, gboolean force_random_ids);

/** Generate a property "bean", with details about the quality of a chunk. */
struct bean_PROPERTIES_s *generate_chunk_quality_bean(
		struct oio_lb_selected_item_s *sel,
		const gchar *chunkid, struct oio_url_s *url);

/** Get the version of the first alias bean from the list. */
gint64 find_alias_version(GSList *bean);

/* Sharding ----------------------------------------------------------------- */

GError* m2db_find_shard_ranges(struct sqlx_sqlite3_s *sq3, gint64 threshold,
		GError* (*get_shard_size)(gint64, guint, gint64*),
		m2_onbean_cb cb, gpointer u0);

GError* m2db_get_shards_in_range(struct sqlx_sqlite3_s *sq3, const gchar *req_lower,
		const gchar *req_upper, m2_onbean_cb cb, gpointer u0);

GError* m2db_merge_shards(struct sqlx_sqlite3_s *sq3,
		struct sqlx_sqlite3_s *to_merge_sq3, gboolean *truncated);

GError* m2db_remove_merged_entries(struct sqlx_sqlite3_s *sq3);

GError* m2db_replace_shard_ranges(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, GSList *new_shard_ranges);

GError* m2db_list_shard_ranges(struct sqlx_sqlite3_s *sq3,
		struct list_params_s *lp, m2_onbean_cb cb, gpointer u);

GError* m2db_get_shard_range(struct sqlx_sqlite3_s *sq3, const gchar *path,
		struct bean_SHARD_RANGE_s **pshard_range);

GError* m2db_check_shard_range(struct sqlx_sqlite3_s *sq3, const gchar *path);

GError* m2db_clean_shard(struct sqlx_sqlite3_s *sq3, gboolean local,
		gint64 max_entries_cleaned, gchar *lower, gchar *upper,
		gboolean *truncated);

GError* m2db_clean_root_container(struct sqlx_sqlite3_s *sq3, gboolean local,
		gint64 max_entries_cleaned, gboolean *truncated);

/* object lock triggers */
GError* m2db_create_triggers(struct sqlx_sqlite3_s *sq3);

void m2db_drop_triggers(struct sqlx_sqlite3_s *sq3);

/** Globally enable (or disable) meta2-defined SQL triggers. */
GError* m2db_enable_triggers(struct sqlx_sqlite3_s *sq3, gboolean enabled);

#endif /*OIO_SDS__meta2v2__meta2_utils_h*/
