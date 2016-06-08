/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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
# include <meta2v2/autogen.h>
# include <meta2v2/meta2_utils.h>

#define CONTAINER_STATUS_ENABLED 0x00000000
#define CONTAINER_STATUS_FROZEN  (guint32)-1
#define CONTAINER_STATUS_DISABLED (guint32)-2

#define VERSIONS_UNLIMITED(V) ((V) < 0)
#define VERSIONS_DISABLED(V)  ((V) == 0)
#define VERSIONS_SUSPENDED(V) ((V) == 1)
#define VERSIONS_ENABLED(V)   ((V) < 0 || (V) > 1)
#define VERSIONS_LIMITED(V)   ((V) > 1)

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
	guint8 flag_allversion :1;
	guint8 flag_headers:1;
};

struct dup_alias_params_s
{
	struct sqlx_sqlite3_s *sq3;
	gint64 c_version;
	gint64 src_c_version;
	gboolean overwrite_latest;
	gboolean set_deleted;
	GSList *errors;
};

gchar* m2v2_build_chunk_url (const char *srv, const char *id);


struct m2v2_position_s {
	int meta, intra;
	unsigned int flag_parity : 1;
	unsigned int flag_rain : 1;
	unsigned int flag_ok : 1;
};

struct m2v2_position_s m2v2_position_decode (const char *str);

void m2v2_position_encode (GString *out, struct m2v2_position_s *p);


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

gint64 m2db_get_ctime(struct sqlx_sqlite3_s *sq3);

void m2db_set_ctime(struct sqlx_sqlite3_s *sq3, gint64 now);

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

GError* m2db_list_aliases(struct sqlx_sqlite3_s *sq3, struct list_params_s *lp,
		GSList *headers, m2_onbean_cb cb, gpointer u);

GError* m2db_get_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		m2_onbean_cb cb, gpointer u);

GError* m2db_del_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gchar **namev);

GError* m2db_flush_property(struct sqlx_sqlite3_s *sq3, const gchar *k);

GError* m2db_set_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gboolean flush, GSList *beans, m2_onbean_cb cb, gpointer u0);

GError* m2db_delete_alias(struct sqlx_sqlite3_s *sq3, gint64 max_versions,
		struct oio_url_s *url, m2_onbean_cb cb, gpointer u0);

GError* m2db_link_content(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		GBytes *id);

/* ------------------------------------------------------------------------- */

struct m2db_put_args_s
{
	struct sqlx_sqlite3_s *sq3;
	gint64 max_versions;
	struct oio_url_s *url;
	struct namespace_info_s *nsinfo;
};

GError* m2db_put_alias(struct m2db_put_args_s *args, GSList *in,
		GSList **out_deleted, GSList **out_added);

GError* m2db_force_alias(struct m2db_put_args_s *args, GSList *in,
		GSList **out_deleted, GSList **out_added);

GError* m2db_copy_alias(struct m2db_put_args_s *args, const char *source);

GError* m2db_append_to_alias(struct sqlx_sqlite3_s *sq3, namespace_info_t *ni,
		gint64 max_versions, struct oio_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

GError* m2_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		m2_onbean_cb cb, gpointer cb_data);

GError* m2db_set_storage_policy(struct sqlx_sqlite3_s *sq3, const gchar *polname,
		int repl);

GError* m2db_get_storage_policy(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result);

GError* m2db_get_container_status(struct sqlx_sqlite3_s *sq3, guint32 *status);

GError* m2db_set_container_status(struct sqlx_sqlite3_s *sq3, guint32 r);

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
		gint64 retention_delay);

/** Delete all aliases of the container, without doing any check.  */
GError* m2db_flush_container(sqlite3 *db);

GError* m2db_deduplicate_contents(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url);

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

/* --------- TYPE CONVERSION ---------- */

char * extract_url_from_chunk(struct bean_CHUNKS_s *chunk);

void m2v2_dup_alias(struct dup_alias_params_s *params, gpointer bean);

#endif /*OIO_SDS__meta2v2__meta2_utils_h*/
