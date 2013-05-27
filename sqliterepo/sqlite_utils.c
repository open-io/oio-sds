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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqlx.utils"
#endif

#include "../metautils/lib/metautils.h"

#include "./sqlite_utils.h"
#include "./sqliterepo.h"

GError*
sqlx_set_admin_entry(sqlite3 *db, const gchar *k, const gchar *v, int replace)
{
	int rc;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	g_assert(db != NULL);
	g_assert(k != NULL);
	g_assert(*k != '\0');

	sqlite3_prepare_debug(rc, db, replace
			? "INSERT OR REPLACE INTO admin (k,v) VALUES (?,?)"
			: "INSERT OR IGNORE  INTO admin (k,v) VALUES (?,?)"
			, -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
	else {
		sqlite3_bind_text(stmt, 1, k, -1, NULL);
		if (v)
			sqlite3_bind_text(stmt, 2, v, -1, NULL);
		else
			sqlite3_bind_text(stmt, 2, "", 0, NULL);
		while (SQLITE_ROW == (rc == sqlite3_step(stmt))) { }
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
		(void) sqlite3_finalize(stmt);
	}

	return err;
}

GError*
sqlx_get_admin_entry(sqlite3 *db, const gchar *k, gchar **out)
{
	int rc;
	sqlite3_stmt *stmt = NULL;
	GError *err = NULL;
	gchar *result = NULL;

	g_assert(out != NULL);
	sqlite3_prepare_debug(rc, db, "SELECT v FROM admin WHERE k = ?",
			-1, &stmt, NULL);

	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = NEWERROR(500, "DB error: (%d) %s", rc, sqlite3_errmsg(db));
	else {
		g_assert(stmt != NULL);
		sqlite3_bind_text(stmt, 1, k, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			if (result) {
				g_free(result);
				result = NULL;
			}
			if (sqlite3_column_text(stmt, 0))
				result = g_strdup((gchar*) sqlite3_column_text(stmt, 0));
			else
				result = g_strdup("");
		}
		sqlite3_finalize(stmt);
	}

	if (err) {
		if (result)
			g_free(result);
	}
	else {
		*out = result;
	}

	return err;
}

void
sqlx_set_admin_entry_noerror(sqlite3 *db, const gchar *k, const gchar *v)
{
	GError *e;

	e = sqlx_set_admin_entry(db, k, v, 1);
	if (e) {
		GRID_WARN("SQLX failed to set admin [%s] to [%s]", k, v);
		g_clear_error(&e);
	}
}

gchar*
sqlx_get_admin_entry_noerror(sqlite3 *db, const gchar *k)
{
	GError *e;
	gchar *out = NULL;

	e = sqlx_get_admin_entry(db, k, &out);
	if (e) {
		GRID_WARN("SQLX failed to get admin [%s]", k);
		g_clear_error(&e);
		if (out)
			g_free(out);
		return NULL;
	}

	return out;
}

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
			while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {}
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				grc = rc;
			rc = sqlite3_finalize(stmt);
		}

		stmt = NULL;
	}

	return grc;
}

void
sqlx_set_int64_admin_value(sqlite3 *db, const gchar *n, gint64 v)
{
	int rc;
	sqlite3_stmt *stmt = NULL;

	if (!db || !n)
		return ;

	sqlite3_prepare_debug(rc, db, "REPLACE INTO admin (k,v) VALUES (?,?)",
			-1, &stmt, NULL);

	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to set [%s] in the admin table : %s", n, sqlite3_errmsg(db));
	}
	else {
		(void) sqlite3_bind_text(stmt, 1, n, -1, NULL);
		(void) sqlite3_bind_int64(stmt, 2, v);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("Failed to set [%s] in the admin table : %s", n, sqlite3_errmsg(db));
		(void) sqlite3_finalize(stmt);
	}
}

gint64
sqlx_get_int64_admin_value(sqlite3 *db, const gchar *n, gint64 def)
{
	int rc;
	gint64 v;
	sqlite3_stmt *stmt = NULL;

	if (!db || !n)
		return def;

	v = def;
	sqlite3_prepare_debug(rc, db, "SELECT v FROM admin WHERE k = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to get [%s] from the admin table : %s",
				n, sqlite3_errmsg(db));
	}
	else {
		(void) sqlite3_bind_text(stmt, 1, n, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			v = sqlite3_column_int64(stmt, 0);
		}
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			GRID_WARN("Failed to get [%s] from the admin table : %s",
					n, sqlite3_errmsg(db));
		(void) sqlite3_finalize(stmt);
	}

	return v;
}

void
sqlx_increment_admin_int64(sqlite3 *db, const gchar *n)
{
	int rc;
	sqlite3_stmt *stmt;

	g_assert(db != NULL);

	sqlite3_prepare_debug(rc, db, "UPDATE admin SET v = v + 1 WHERE k = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		GRID_WARN("Failed to increment [%s] in the admin table : %s",
				n, sqlite3_errmsg(db));
	}
	else {
		(void) sqlite3_bind_text(stmt, 1, n, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) { }
		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			GRID_WARN("Failed to increment [%s] in the admin table : %s",
					n, sqlite3_errmsg(db));
		}
		(void) sqlite3_finalize(stmt);
	}
}

