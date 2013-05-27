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

#ifndef SQLITEREPO_utils__h
# define SQLITEREPO_utils__h 1
# include  <sqlite3.h>
# include  <glib.h>


/**
 * @param db
 * @param RC
 */
#define SQLITE_GERROR(db,RC) g_error_new(gquark_log, (RC), "(%s) %s", \
		sqlite_strerror(RC), ((db)?sqlite3_errmsg(db):"unknown error"))


/**
 * @param R
 * @param db
 * @param zSql
 * @param nByte
 * @param ppStmt
 * @param pzTail
 */
# define sqlite3_prepare_debug(R,db,zSql,nByte,ppStmt,pzTail) do { \
	R = sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail); \
	(void)(R);\
	GRID_TRACE2("sqlite3_prepare_v2(%p,%p,\"%s\") = (%d/%s) %s", \
			db, ppStmt, zSql, (R), sqlite_strerror(R), sqlite3_errmsg(db)); \
} while (0)


/**
 * @param R
 * @param S
 */
# define sqlite3_step_debug(R,S) do { \
	R = sqlite3_step(S); \
	(void)(R);\
	GRID_TRACE2("sqlite3_step() = %s (%d)", sqlite_strerror(R), R); \
} while (0)


/**
 * @param R
 * @param S
 */
# define sqlite3_finalize_debug(R,S) do { \
	R = sqlite3_finalize(S); \
	(void)(R);\
	GRID_TRACE2("sqlite3_finalize() = %s (%d)", sqlite_strerror(R), R); \
} while (0)

/**
 * @param rc an SQLite error code
 * @return a string describing the error that occured on the SQLite base
 */
const char * sqlite_strerror(int rc);

/**
 * @param rc an sqliterepo error code
 * @return a string describing the error that occured upon the sqliterepo 
 * operation
 */
const char * sqlx_strerror(int rc);


GError* sqlx_set_admin_entry(sqlite3 *db, const gchar *k, const gchar *v,
		int replace);

void sqlx_set_admin_entry_noerror(sqlite3 *db, const gchar *k, const gchar *v);


GError* sqlx_get_admin_entry(sqlite3 *db, const gchar *k, gchar **v);

gchar* sqlx_get_admin_entry_noerror(sqlite3 *db, const gchar *k);

int sqlx_exec(sqlite3 *handle, const gchar *sql);

void sqlx_set_int64_admin_value(sqlite3 *db, const gchar *n, gint64 v);

gint64 sqlx_get_int64_admin_value(sqlite3 *db, const gchar *n, gint64 def);

void sqlx_increment_admin_int64(sqlite3 *db, const gchar *n);

#endif /* SQLITEREPO_utils__h */
