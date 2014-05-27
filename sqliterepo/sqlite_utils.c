#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <string.h>

#include "sqliterepo.h"

int
sqlx_exec(sqlite3 *handle, const gchar *sql)
{
	int rc, grc = SQLITE_OK;
	const gchar *next;
	sqlite3_stmt *stmt = NULL;

	while ((grc == SQLITE_OK) && sql && *sql) {
		next = NULL;
		sqlite3_prepare_debug(rc, handle, sql, -1, &stmt, &next);
		sql = next;
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			grc = rc;
		else if (stmt) {
			sqlite3_step_debug_until_end(rc, stmt);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				grc = rc;
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
	}

	return grc;
}

GError*
sqlite_admin_entry_set(sqlite3 *db, const int repl, const gchar *k,
		const guint8 *v, gsize vlen)
{
	int rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);
	g_assert(k != NULL);
	g_assert(*k != '\0');

	sqlite3_prepare_debug(rc, db, repl
			? "INSERT OR REPLACE INTO admin (k,v) VALUES (?,?)"
			: "INSERT OR IGNORE  INTO admin (k,v) VALUES (?,?)"
			, -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
	else {
		sqlite3_bind_text(stmt, 1, k, -1, NULL);
		if (v && vlen)
			sqlite3_bind_blob(stmt, 2, v, vlen, NULL);
		else
			sqlite3_bind_text(stmt, 2, "", 0, NULL);
		sqlite3_step_debug_until_end(rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
		(void) sqlite3_finalize(stmt);
	}

	return err;
}

static void
_admin_entry_set_gba_noerror(sqlite3 *db, const gchar *k, GByteArray *v)
{
	GError *e = sqlite_admin_entry_set(db, 1, k, v?v->data:NULL, v?v->len:0);
	if (e) {
		GRID_WARN("SQLX failed to set admin [%s]", k);
		g_clear_error(&e);
	}
}

static GError*
_admin_entry_del(sqlite3 *db, const gchar *k)
{
	int rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);
	g_assert(k != NULL);
	g_assert(*k != '\0');

	sqlite3_prepare_debug(rc, db, "DELETE FROM admin WHERE k = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
	else {
		sqlite3_bind_text(stmt, 1, k, -1, NULL);
		sqlite3_step_debug_until_end(rc, stmt);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
		(void) sqlite3_finalize(stmt);
	}

	return err;
}

static void
_admin_entry_del_noerror(sqlite3 *db, const gchar *k)
{
	GError *e = _admin_entry_del(db, k);
	if (e) {
		GRID_WARN("SQLX failed to del admin [%s]", k);
		g_clear_error(&e);
	}
}

void
sqlx_admin_set_gba(struct sqlx_sqlite3_s *sq3, const gchar *k, GByteArray *gba)
{
	GByteArray *prev;

	// Avoid replacing the value if the same is already present
	if (NULL != (prev = g_tree_lookup(sq3->admin, k))) {
		if (gba->len == prev->len) {
			if (!memcmp(gba->data, prev->data, prev->len)) {
				g_byte_array_free(gba, TRUE);
				return;
			}
		}
	}

	_admin_entry_set_gba_noerror(sq3->db, k, gba);
	g_tree_replace(sq3->admin, g_strdup(k), gba);
}

void
sqlx_admin_set_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	sqlx_admin_set_gba(sq3, k, metautils_gba_from_string(v));
}

void
sqlx_admin_init_str(struct sqlx_sqlite3_s *sq3, const gchar *k, const gchar *v)
{
	if (!g_tree_lookup(sq3->admin, k))
		sqlx_admin_set_str(sq3, k, v);
}

void
sqlx_admin_del(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	_admin_entry_del_noerror(sq3->db, k);
	g_tree_remove(sq3->admin, k);
}

int
sqlx_admin_has(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	return NULL != g_tree_lookup(sq3->admin, k);
}

gchar*
sqlx_admin_get_str(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	GByteArray *v = g_tree_lookup(sq3->admin, k);
	return v ? g_strndup((gchar*)v->data, v->len) : NULL;
}

GByteArray*
sqlx_admin_get_gba(struct sqlx_sqlite3_s *sq3, const gchar *k)
{
	GByteArray *v = g_tree_lookup(sq3->admin, k);
	return v ? metautils_gba_dup(v) : NULL;
}

gint64
sqlx_admin_get_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 def)
{
	gchar *s = sqlx_admin_get_str(sq3, k);
	if (!s)
		return def;
	gint64 i64 = g_ascii_strtoll(s, NULL, 10);
	g_free(s);
	return i64;
}

void
sqlx_admin_set_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v)
{
	gchar buf[64];
	g_snprintf(buf, 64, "%"G_GINT64_FORMAT, v);
	sqlx_admin_set_str(sq3, k, buf);
}

void
sqlx_admin_init_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 v)
{
	if (!g_tree_lookup(sq3->admin, k))
		sqlx_admin_set_i64(sq3, k, v);
}

void
sqlx_admin_inc_i64(struct sqlx_sqlite3_s *sq3, const gchar *k, const gint64 delta)
{
	gchar *s = sqlx_admin_get_str(sq3, k);
	if (!s)
		sqlx_admin_set_i64(sq3, k, delta);
	else {
		sqlx_admin_set_i64(sq3, k, delta + g_ascii_strtoll(s, NULL, 10));
		g_free(s);
	}
}

void
sqlx_admin_inc_version(struct sqlx_sqlite3_s *sq3, const gchar *k, const int delta)
{
	gchar buf[128], *p, *prev;

	if (!(prev = sqlx_admin_get_str(sq3, k)))
		return;
	if (!(p = strchr(prev, ':')))
		return;

	*(p++) = '\0';
	g_snprintf(buf, sizeof(buf), "%"G_GINT64_FORMAT":%"G_GINT64_FORMAT,
			g_ascii_strtoll(prev, NULL, 10) + delta,
			g_ascii_strtoll(p, NULL, 10));
	g_free(prev);
	sqlx_admin_set_str(sq3, k, buf);
}

void
sqlx_admin_inc_all_versions(struct sqlx_sqlite3_s *sq3, const int delta)
{
	gboolean runner(gchar *k0, GByteArray *v, gpointer ignored) {
		(void) ignored;
		if (!g_str_has_prefix(k0, "version:"))
			return FALSE;

		gchar *p, *prev;
		prev = g_alloca(v->len+3);
		memset(prev, 0, v->len+3);
		memcpy(prev, v->data, v->len);

		// Build the new version string
		p = strchr(prev, ':');
		if (!p)
			return FALSE;
		*(p++) = '\0';
		gint64 v0 = g_ascii_strtoll(prev, NULL, 10) + delta;
		gint64 v1 = g_ascii_strtoll(p, NULL, 10);
		g_snprintf(prev, v->len+3, "%"G_GINT64_FORMAT":%"G_GINT64_FORMAT, v0, v1);

		// Change in place
		g_byte_array_set_size(v, 0);
		g_byte_array_append(v, (guint8*)prev, strlen(prev));

		// Change in the DB
		sqlite_admin_entry_set(sq3->db, 1/*replace*/, k0, v->data, v->len);
		return FALSE;
	}

	g_tree_foreach(sq3->admin, (GTraverseFunc)runner, NULL);
}

void sqlx_admin_set_status(struct sqlx_sqlite3_s *sq3, gint64 status)
{
	sqlx_admin_set_i64(sq3, ADMIN_STATUS_KEY, status);
}

gint64 sqlx_admin_get_status(struct sqlx_sqlite3_s *sq3)
{
	return sqlx_admin_get_i64(sq3, ADMIN_STATUS_KEY,
			(gint64)ADMIN_STATUS_ENABLED);
}

