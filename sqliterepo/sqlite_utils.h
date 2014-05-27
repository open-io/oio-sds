#ifndef SQLITEREPO_utils__h
# define SQLITEREPO_utils__h 1
# include <sqlite3.h>
# include <glib.h>

#ifndef SQLX_QUERY_DOMAIN
# define SQLX_QUERY_DOMAIN "sqlx.query"
#endif

#define SQLX_INIT_FLAG "sqlx:init"

/** For compatibility with m2v2 */
#define ADMIN_STATUS_KEY "flags"

/** Can read and write */
#define ADMIN_STATUS_ENABLED  0x00000000
/** Cannot write but can read */
#define ADMIN_STATUS_FROZEN   (guint32)-1
/** Can neither write nor read */
#define ADMIN_STATUS_DISABLED (guint32)-2

/**
 * @param db
 * @param RC
 */
#define SQLITE_GERROR(db,RC) NEWERROR((RC), "(%s) %s", \
		sqlite_strerror(RC), ((db)?sqlite3_errmsg(db):"unknown error"))

static inline int
sqlx_code_good(const int rc)
{
	return rc == SQLITE_ROW || rc == SQLITE_DONE || rc == SQLITE_OK;
}

/**
 * @param R
 * @param db
 * @param zSql
 * @param nByte
 * @param ppStmt
 * @param pzTail
 */
# define sqlite3_prepare_debug(R,db,zSql,nByte,ppStmt,pzTail) do { \
	(R) = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail); \
	g_log(SQLX_QUERY_DOMAIN, \
			sqlx_code_good(R) ? GRID_LOGLVL_TRACE : GRID_LOGLVL_WARN, \
			"sqlite3_prepare_v2(%p,%p,\"%s\") = (%d/%s) %s", \
			db, ppStmt, zSql, (R), sqlite_strerror(R), sqlite3_errmsg(db)); \
} while (0)


/**
 * @param R
 * @param S
 */
# define sqlite3_step_debug(R,S) do { \
	(R) = sqlite3_step(S); \
	g_log(SQLX_QUERY_DOMAIN, \
			sqlx_code_good(R) ? GRID_LOGLVL_TRACE2 : GRID_LOGLVL_WARN, \
			"sqlite3_step() = %s (%d)", \
			sqlite_strerror(R), R); \
} while (0)

# define sqlite3_step_debug_until_end(R,S) do { \
	sqlite3_step_debug((R),(S)); \
} while ((R) == SQLITE_ROW)

/**
 * @param R
 * @param S
 */
# define sqlite3_finalize_debug(R,S) do { \
	(R) = sqlite3_finalize(S); \
	g_log(SQLX_QUERY_DOMAIN, \
			sqlx_code_good(R) ? GRID_LOGLVL_TRACE2 : GRID_LOGLVL_WARN, \
			"sqlite3_finalize() = %s (%d)", \
			sqlite_strerror(R), R); \
} while (0)

/**
 * @param rc an SQLite error code
 * @return a string describing the error that occured on the SQLite base
 */
const char * sqlite_strerror(const int rc);

/**
 * @param handle
 * @param sql
 * @return
 */
int sqlx_exec(sqlite3 *handle, const gchar *sql);

GError* sqlite_admin_entry_set(sqlite3 *db, const int repl, const gchar *k,
		const guint8 *v, gsize vlen);

struct sqlx_sqlite3_s;

void sqlx_admin_reload(struct sqlx_sqlite3_s *sq3);

void sqlx_admin_del(struct sqlx_sqlite3_s *sq3, const gchar *k);

int sqlx_admin_has(struct sqlx_sqlite3_s *sq3, const gchar *k);

void sqlx_admin_init_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v);

void sqlx_admin_set_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v);

void sqlx_admin_inc_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 delta);

void sqlx_admin_inc_version(struct sqlx_sqlite3_s *sq3, const gchar *k, const int delta);

void sqlx_admin_inc_all_versions(struct sqlx_sqlite3_s *sq3, const int delta);

void sqlx_admin_set_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v);

void sqlx_admin_init_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v);

void sqlx_admin_set_gba(struct sqlx_sqlite3_s *sq3, const gchar *k, GByteArray *gba);

gint64 sqlx_admin_get_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 def);

gchar* sqlx_admin_get_str(struct sqlx_sqlite3_s *sq3, const gchar *k);

GByteArray* sqlx_admin_get_gba(struct sqlx_sqlite3_s *sq3, const gchar *k);

/** Set an application-level status in admin table */
void sqlx_admin_set_status(struct sqlx_sqlite3_s *sq3, gint64 status);

/** Get an application-level status from admin table */
gint64 sqlx_admin_get_status(struct sqlx_sqlite3_s *sq3);

#endif /* SQLITEREPO_utils__h */
