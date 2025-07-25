/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2020-2025 OVH SAS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__sqliterepo__sqlite_utils_h
# define OIO_SDS__sqliterepo__sqlite_utils_h 1

# include <sqlite3.h>
# include <glib.h>

#ifndef SQLX_QUERY_DOMAIN
# define SQLX_QUERY_DOMAIN "sqlx.query"
#endif

#ifndef SQLX_ADMIN_PREFIX_SYS
#define SQLX_ADMIN_PREFIX_SYS "sys."
#endif

#ifndef SQLX_ADMIN_PREFIX_USER
#define SQLX_ADMIN_PREFIX_USER "user."
#endif

#ifndef SQLX_ADMIN_PEERS
#define SQLX_ADMIN_PEERS SQLX_ADMIN_PREFIX_SYS "peers"
#endif

#ifndef SQLX_ADMIN_INITFLAG
#define SQLX_ADMIN_INITFLAG SQLX_ADMIN_PREFIX_SYS "sqlx.init"
#endif

#ifndef SQLX_ADMIN_STATUS
#define SQLX_ADMIN_STATUS SQLX_ADMIN_PREFIX_SYS "status"
#endif

#ifndef SQLX_ADMIN_NAMESPACE
#define SQLX_ADMIN_NAMESPACE SQLX_ADMIN_PREFIX_SYS "ns"
#endif

#ifndef SQLX_ADMIN_ACCOUNT
#define SQLX_ADMIN_ACCOUNT SQLX_ADMIN_PREFIX_SYS "account"
#endif

#ifndef SQLX_ADMIN_USERNAME
#define SQLX_ADMIN_USERNAME SQLX_ADMIN_PREFIX_SYS "user.name"
#endif

// Deprecated since oio-sds 4.4.0
#ifndef SQLX_ADMIN_USERTYPE
#define SQLX_ADMIN_USERTYPE SQLX_ADMIN_PREFIX_SYS "user.type"
#endif

#ifndef SQLX_ADMIN_BASENAME
#define SQLX_ADMIN_BASENAME SQLX_ADMIN_PREFIX_SYS "name"
#endif

#ifndef SQLX_ADMIN_BASETYPE
#define SQLX_ADMIN_BASETYPE SQLX_ADMIN_PREFIX_SYS "type"
#endif

#ifndef SQLX_ADMIN_LAST_VACUUM
#define SQLX_ADMIN_LAST_VACUUM SQLX_ADMIN_PREFIX_SYS "last_vacuum"
#endif

/** Can read and write */
#define ADMIN_STATUS_ENABLED  0x00000000
/** Cannot write but can read */
#define ADMIN_STATUS_FROZEN   (guint32)-1
/** Can neither write nor read */
#define ADMIN_STATUS_DISABLED (guint32)-2

#define SQLITE_GERROR(db,RC) NEWERROR((RC), "(%s) %s", \
		sqlite_strerror(RC), ((db)?sqlite3_errmsg(db):"unknown error"))

#define SQLX_CORRUPT_SUFFIX ".corrupted"

static inline int
sqlx_code_good(const int rc)
{
	return rc == SQLITE_ROW || rc == SQLITE_DONE || rc == SQLITE_OK;
}

/** @see sqlite3_prepare_v2() */
# define sqlite3_prepare_debug(R,db,zSql,nByte,ppStmt,pzTail) do { \
	(R) = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail); \
	if (!sqlx_code_good(R) || GRID_TRACE_ENABLED()) \
		g_log(SQLX_QUERY_DOMAIN, \
				sqlx_code_good(R) ? GRID_LOGLVL_TRACE : GRID_LOGLVL_WARN, \
				"sqlite3_prepare_v2(%p,%p,\"%.*s\") = (%d/%s) %s", \
				db, ppStmt, 64, zSql, (R), sqlite_strerror(R), sqlite3_errmsg(db)); \
} while (0)

/** @see sqlite3_step() */
# define sqlite3_step_debug(R,S) do { \
	(R) = sqlite3_step(S); \
	if (!sqlx_code_good(R) || GRID_TRACE2_ENABLED()) \
		g_log(SQLX_QUERY_DOMAIN, \
				sqlx_code_good(R) ? GRID_LOGLVL_TRACE2 : GRID_LOGLVL_WARN, \
				"sqlite3_step() = %s (%d)", \
				sqlite_strerror(R), R); \
} while (0)

/** @see sqlite3_step_debug() */
# define sqlite3_step_debug_until_end(R,S) do { \
	sqlite3_step_debug((R),(S)); \
} while ((R) == SQLITE_ROW)

/** @see sqlite3_finalize() */
# define sqlite3_finalize_debug(R,S) do { \
	(R) = sqlite3_finalize(S); \
	if (!sqlx_code_good(R) || GRID_TRACE2_ENABLED()) \
		g_log(SQLX_QUERY_DOMAIN, \
				sqlx_code_good(R) ? GRID_LOGLVL_TRACE2 : GRID_LOGLVL_WARN, \
				"sqlite3_finalize() = %s (%d)", \
				sqlite_strerror(R), R); \
} while (0)

/** Return a string describing the error that occurred on the SQLite base */
const char * sqlite_strerror(const int rc);

int sqlx_exec(sqlite3 *handle, const gchar *sql);

/** Set sqlite's journal mode. Call this right after opening the database.
 * 0 = DELETE, 1 = TRUNCATE, 2 = PERSIST, 3 = MEMORY, 4 = WAL */
int sqlx_set_journal_mode(sqlite3 *handle, guint journal_mode);

/** Set sqlite's page size. Notice that this setting may not be applied
 * immediately, but only after a call to "vacuum". */
int sqlx_set_page_size(sqlite3 *handle, guint page_size);

struct sqlx_sqlite3_s;

int sqlx_sqlite3_finalize(struct sqlx_sqlite3_s *sq3, sqlite3_stmt *stmt,
		GError *err);

struct oio_url_s* sqlx_admin_get_url (struct sqlx_sqlite3_s *sq3);

/* load the whole internal cached from the <admin> table. */
void sqlx_admin_load(struct sqlx_sqlite3_s *sq3);

/* calls sqlx_admin_load(), set values for missing tables, etc */
void sqlx_admin_reload(struct sqlx_sqlite3_s *sq3);

void sqlx_admin_del(struct sqlx_sqlite3_s *sq3, const gchar *k);
void sqlx_admin_del_all_keys_with_prefix(struct sqlx_sqlite3_s *sq3,
		const gchar *prefix, GTraverseFunc func, gpointer data);
void sqlx_admin_del_all_user(struct sqlx_sqlite3_s *sq3, GTraverseFunc func,
		gpointer data);

int sqlx_admin_has(struct sqlx_sqlite3_s *sq3, const gchar *k);


void sqlx_admin_set_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v);
gboolean sqlx_admin_set_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v);
gboolean sqlx_admin_set_str_all_keys_with_prefix(struct sqlx_sqlite3_s *sq3,
		const gchar *prefix, const gchar *value);

gboolean sqlx_admin_init_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v);
gboolean sqlx_admin_init_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v);

void sqlx_admin_inc_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 delta);

gint64 sqlx_admin_get_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 def);
gchar* sqlx_admin_get_str(struct sqlx_sqlite3_s *sq3, const gchar *k);
gchar** sqlx_admin_get_keys(struct sqlx_sqlite3_s *sq3);
gchar** sqlx_admin_get_keyvalues(struct sqlx_sqlite3_s *sq3,
		gboolean (*filter)(const gchar *k));

void sqlx_admin_inc_version(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 d);
void sqlx_admin_inc_all_versions(struct sqlx_sqlite3_s *sq3, const gint64 delta);

void sqlx_admin_ensure_versions (struct sqlx_sqlite3_s *sq3);

/* Check if peers have been saved in the database, save them if needed.
 * Returns TRUE if peers have just been saved,
 * FALSE if they were already there */
gboolean sqlx_admin_ensure_peers(struct sqlx_sqlite3_s *sq3, gchar **peers);

/* calls sqlx_admin_save() if the handle is dirty */
guint sqlx_admin_save_lazy (struct sqlx_sqlite3_s *sq3);

/* if the handle is dirty, it calls sqlx_admin_save() in a transaction */
guint sqlx_admin_save_lazy_tnx (struct sqlx_sqlite3_s *sq3);

/* application-level */
void sqlx_admin_set_status(struct sqlx_sqlite3_s *sq3, gint64 status);
gint64 sqlx_admin_get_status(struct sqlx_sqlite3_s *sq3);

/* Get a (static) string representing the status of the database. */
const gchar* sqlx_admin_status2str(gint64 status);

void sqlx_alert_dirty_base(struct sqlx_sqlite3_s *sq3, const char *msg);

/* database properties */
struct db_properties_s;

struct db_properties_s *db_properties_new(void);

void db_properties_free(
		struct db_properties_s *db_properties);

void db_properties_add(
		struct db_properties_s *db_properties,
		gchar *key, gchar *value);

GString * db_properties_to_json(
		struct db_properties_s *db_properties, GString *json);

GPtrArray * db_properties_system_to_gpa(struct db_properties_s *db_properties,
		GPtrArray *gpa);

gboolean db_properties_has_system_property(
		struct db_properties_s *db_properties, gchar **properties);

/* database stats */

GPtrArray* sqlx_admin_get_usage(struct sqlx_sqlite3_s *sq3);

/* Extra counters (can be more resource-intensive).
 * Specific metaX counters can be returned.
 */
GPtrArray* sqlx_admin_get_extra_counters(struct sqlx_sqlite3_s *sq3);

#endif /*OIO_SDS__sqliterepo__sqlite_utils_h*/
