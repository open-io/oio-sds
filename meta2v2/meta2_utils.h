/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

struct storage_policy_s;
struct oio_url_s;
struct sqlx_sqlite3_s;

struct list_params_s
{
	gint64 maxkeys;
	const char *prefix;
	const char *marker_start;
	const char *marker_end;
	guint8 flag_nodeleted :1;
	guint8 flag_allversion:1;
	guint8 flag_headers   :1;
	guint8 flag_properties:1;
	guint8 flag_local     :1;
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
	gint64 n_chunks;
};

struct checked_content_s;


struct m2v2_position_s m2v2_position_decode(const char *str);

void m2v2_position_encode(GString *out, struct m2v2_position_s *p);

/* Sort the beans of a content. Use m2v2_sorted_content_free to free
 * the result. The beans must be freed separately. */
void m2v2_sort_content(GSList *beans, struct m2v2_sorted_content_s **content);

/* Free a sorted content (the beans must be freed separately). */
void m2v2_sorted_content_free(struct m2v2_sorted_content_s *content);

typedef void (*m2_onbean_cb) (gpointer u, gpointer bean);

/** Get the cumulated size and number of contents in the database. */
void m2db_get_container_size_and_obj_count(sqlite3 *db, gboolean check_alias,
		guint64 *size, gint64 *count);

/** Get the number of shard ranges in the database. */
void m2db_get_container_shard_count(sqlite3 *db, gint64 *shard_count_out);

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

void m2db_set_size(struct sqlx_sqlite3_s *sq3, gint64 size);

gint64 m2db_get_obj_count(struct sqlx_sqlite3_s *sq3);

void m2db_set_obj_count(struct sqlx_sqlite3_s *sq3, gint64 count);

gint64 m2db_get_shard_count(struct sqlx_sqlite3_s *sq3);

void m2db_set_shard_count(struct sqlx_sqlite3_s *sq3, gint64 count);

gint64 m2db_get_damaged_objects(struct sqlx_sqlite3_s *sq3);

void m2db_set_damaged_objects(struct sqlx_sqlite3_s *sq3, gint64 damaged);

gint64 m2db_get_missing_chunks(struct sqlx_sqlite3_s *sq3);

void m2db_set_missing_chunks(struct sqlx_sqlite3_s *sq3, gint64 missing);

void m2db_increment_version(struct sqlx_sqlite3_s *sq3);

void m2db_set_container_name(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url);

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

/* Check if alias doesn't exsist */
GError* check_alias_doesnt_exist(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url);

/* Check if alias doesn't exist separately checking the path and the content ID */
GError* check_alias_doesnt_exist2(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url);

GError* m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		GSList *headers, m2_onbean_cb cb, gpointer u);

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
		gboolean delete_marker, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u0);

void checked_content_free(struct checked_content_s *checked_content);

void checked_content_append_json_string(struct checked_content_s *checked_content,
		GString *message);

guint checked_content_get_missing_chunks(struct checked_content_s *checked_content);

GError* m2db_check_content(struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo,
		struct checked_content_s **checked_content, gboolean update);

GError* m2db_get_content_missing_chunks(
		struct m2v2_sorted_content_s *sorted_content,
		struct namespace_info_s *nsinfo, gint64 *missing_chunks);

void m2db_check_content_quality(
		struct m2v2_sorted_content_s *sorted_content, GSList *chunk_meta,
		GSList **to_be_improved);

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
};

GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *beans,
		m2_onbean_cb cb_deleted, gpointer u0_deleted,
		m2_onbean_cb cb_added, gpointer u0_added);

GError* m2db_change_alias_policy(struct m2db_put_args_s *args,
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
		m2_onbean_cb cb, gpointer cb_data);

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

/* --- Low level ----------------------------------------------------------- */

/** Generate a chunk "bean", filled with only an address and ctime. */
struct bean_CHUNKS_s *generate_chunk_bean(struct oio_url_s *url,
		const gchar *pos, struct oio_lb_selected_item_s *sel,
		const struct storage_policy_s *policy);

/** Generate a property "bean", with details about the quality of a chunk. */
struct bean_PROPERTIES_s *generate_chunk_quality_bean(
		struct oio_lb_selected_item_s *sel,
		const gchar *chunkid, struct oio_url_s *url);

/** Get the version of the first alias bean from the list. */
gint64 find_alias_version(GSList *bean);

#endif /*OIO_SDS__meta2v2__meta2_utils_h*/
