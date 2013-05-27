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

#ifndef META2_UTILS__H
# define META2_UTILS__H 1
# include <sqlite3.h>

# include "../metautils/lib/hc_url.h"
# include "../metautils/lib/metatypes.h"

# define CODE_SRVTYPE_NOTMANAGED 440

#define CONTAINER_STATUS_ENABLED 0x00000000
#define CONTAINER_STATUS_FROZEN  (guint32)-1
#define CONTAINER_STATUS_DISABLED (guint32)-2

#define VERSIONS_ENABLED(max_versions) (max_versions > 1)
#define VERSIONS_SUSPENDED(max_versions) (max_versions == 1)
#define VERSIONS_DISABLED(max_versions) (max_versions == 0)
#define VERSIONS_UNLIMITED(max_versions) (max_versions < 0)

struct storage_policy_s;
struct hc_url_s;
struct grid_lb_iterator_s;

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

/*!
 * @param db
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_max_versions(sqlite3 *db, gint64 def);

/*!
 * @param db
 * @param max
 */
void m2db_set_max_versions(sqlite3 *db, gint64 max);

/*!
 * @param db
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_quota(sqlite3 *db, gint64 def);

/*!
 * @param db
 * @param max
 */
void m2db_set_quota(sqlite3 *db, gint64 quota);

/*!
 * @param db
 * @param def default value if not found in the DB
 * @return
 */
gint64 m2db_get_size(sqlite3 *db);

/*!
 * @param db
 * @param max
 */
void m2db_set_size(sqlite3 *db, gint64 size);

/*!
 * @param db
 * @return
 */
gint64 m2db_get_version(sqlite3 *db);

/*!
 * @param db
 */
void m2db_increment_version(sqlite3 *db);

/*!
 *
 * @param db
 * @param flags
 * @param cb_data
 * @param cb
 * @return
 */
GError* m2db_get_container_properties(sqlite3 *db, guint32 flags,
		gpointer cb_data, m2_onprop_cb cb);

/*!
 * @param db
 * @param url
 */
void m2db_set_container_name(sqlite3 *db, struct hc_url_s *url);

/*!
 *
 * @param db
 * @param props
 * @return
 */
GError* m2db_set_container_properties(sqlite3 *db, guint32 flags, GSList *props);

/*!
 * @param db
 * @param polname
 * @param repl
 * @return
 */
GError* m2db_set_storage_policy(sqlite3 *db, const gchar *polname, int repl);

/*!
 *
 * @param db
 * @param url
 * @param cb
 * @param u
 * @return
 */
GError* m2db_get_alias(sqlite3 *db, struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u);

/*!
 * @param db
 * @param flags
 * @param cb
 * @param u
 * @return
 */
GError* m2db_list_aliases(sqlite3 *db, guint32 flags, m2_onbean_cb cb,
		gpointer u);

/*!
 * @param db
 * @param url
 * @param flags
 * @param cb
 * @param u
 * @return
 */
GError* m2db_get_properties(sqlite3 *db, struct hc_url_s *url, guint32 flags,
		m2_onbean_cb cb, gpointer u);

/*!
 * @param db
 * @param k
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_get_all_properties(sqlite3 *db, const gchar *k, guint32 flags,
		m2_onbean_cb cb, gpointer u0);

/*!
 * @param db
 * @param url
 * @param prop_name
 * @param flags
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_get_property(sqlite3 *db, struct hc_url_s *url, const gchar *k,
		guint32 flags, m2_onbean_cb cb, gpointer u0);

/*!
 * @param db
 * @param url
 * @param k
 * @return
 */
GError* m2db_del_property(sqlite3 *db, struct hc_url_s *url, const gchar *k);

/*!
 * @param db
 * @param k
 * @return
 */
GError* m2db_flush_property(sqlite3 *db, const gchar *k);

/*!
 * @param db
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_set_properties(sqlite3 *db, gint64 max_versions,
		struct hc_url_s *url, GSList *beans,
		m2_onbean_cb cb, gpointer u0);

/*! Get an alias only
 *
 * @param db
 * @param url
 * @param result
 * @return
 */
GError* m2db_latest_alias(sqlite3 *db,  struct hc_url_s *url,
		gpointer *result);

/*!
 * @param db
 * @param url
 * @param alias
 * @return
 */
GError* m2db_get_versioned_alias(sqlite3 *db, struct hc_url_s *url,
		gpointer *result);

/*!
 * @param db
 * @param max_versions
 * @param url
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_delete_alias(sqlite3 *db, gint64 max_versions,
		struct hc_url_s *url, m2_onbean_cb cb, gpointer u0);

/*!
 *
 * @param src
 * @param dst
 * @param url
 * @return
 */
GError* m2db_get_alias_view(sqlite3 *src, sqlite3 **dst,
		struct hc_url_s *url, guint32 flags);

/**
 * @param db
 * @param list
 * @return
 */
GError* m2db_save_beans_list(sqlite3 *db, GSList *list);

/**
 * @param db
 * @param array
 * @return
 */
GError* m2db_save_beans_array(sqlite3 *db, GPtrArray *array);

/*!
 * @param res
 * @return
 */
GError* m2db_create_view(sqlite3 **res);

/*! Select the last bean 'url' from 'src', and insert a copy of it in 'dst'
 *
 * @param src
 * @param dst
 * @param url
 * @return
 */
GError* m2db_filter_alias(sqlite3 *src, sqlite3 *dst, struct hc_url_s *url,
		guint32 flags);

/*!
 * Check the last bean 'url' from 'db' is complete
 *
 * @param db
 * @param url
 * @return
 */
GError* m2db_check_alias(sqlite3 *db, struct hc_url_s *url);

/*!
 * Check the bean 'url' in a DB that should contain only its last version
 *
 * @param db
 * @param url
 * @return
 */
GError* m2db_check_alias_view(sqlite3 *db, struct hc_url_s *url);

/*!
 * @param beans
 * @return
 */
GError* m2db_check_alias_beans_list(struct hc_url_s *url, GSList *beans);

/*!
 *
 * @param db
 * @param url
 * @param flags
 * @param version
 * @return
 */
GError* m2db_get_alias_version(sqlite3 *db, struct hc_url_s *url,
		guint32 flags, gint64 *version);

struct m2db_put_args_s
{
	sqlite3 *db;
	gint64 max_versions;
	struct hc_url_s *url;
	struct namespace_info_s nsinfo;
};

/*!
 * @param db
 * @param max_versions
 * @param url
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
GError* m2db_force_alias(sqlite3 *db, struct hc_url_s *url, GSList *beans);

/*!
 * @param db
 * @param max_versions
 * @param url
 * @param beans
 * @param cb
 * @param u0
 * @return
 */
GError* m2db_append_to_alias(sqlite3 *db, gint64 max_versions,
		struct hc_url_s *url, GSList *beans,
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
 * @param db
 * @param url
 * @param nsinfo
 * @param result
 * @return
 */
GError* m2db_get_storage_policy(sqlite3 *db, struct hc_url_s *url,
		struct namespace_info_s *nsinfo, gboolean from_previous,
		struct storage_policy_s **result);

/*!
 * @param db
 * @param status
 * @return
 */
GError* m2db_get_container_status(sqlite3 *db, guint32 *status);

/*!
 * @param db
 * @param expected
 * @param r
 * @return
 */
GError* m2db_set_container_status(sqlite3 *db, guint32 *expected, guint32 r);

/*!
 * @param db
 * @param beans
 * @return
 */
GError* m2db_update_alias_header(sqlite3 *db, gint64 max_versions, 
		struct hc_url_s *url, GSList *beans);

/*!
 * @param db
 * @param content
 * @return
 */
GError* m2db_delete_content(sqlite3 *db, gpointer content);


/**
 * @param db
 * @param max_versions
 * @return
 */
GError* m2db_purge(sqlite3 *db, gint64 max_versions, GSList** del_chunks_list);

/**
 * Run a chunk deduplication cycle on the meta2 database.
 *
 * @param db The meta2 database object to search duplicate chunks in
 * @param url
 * @return A GError in case of error, NULL otherwise
 */
GError* m2db_deduplicate_chunks(sqlite3 *db, namespace_info_t *nsinfo,
		struct hc_url_s *url);

/**
 * Run a chunk deduplication cycle on a specific alias of the meta2 database.
 *
 * @param db The meta2 database object to search duplicate chunks in
 * @param url
 * @return A GError in case of error, NULL otherwise
 */
GError* m2db_deduplicate_alias_chunks(sqlite3 *db, namespace_info_t *nsinfo,
		struct hc_url_s *url);

GError* m2db_deduplicate_contents(sqlite3 *db, struct hc_url_s *url, GString **status_message);

/* --------- TYPE CONVERSION ---------- */

/*!
 * @param id
 * @param rc
 * @return
 */
GSList* m2v2_beans_from_raw_content(const char *id, meta2_raw_content_t *rc);

/*!
 * @param beans
 * @return
 */
meta2_raw_content_t* raw_content_from_m2v2_beans(const container_id_t cid, GSList *beans);

/*!
 * @param id
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
GSList* m2v2_beans_from_chunk_info_list(const char * id, const char *alias,
		GSList *chunks);

#endif
