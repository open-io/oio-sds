/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1.backend"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <sqliterepo/sqliterepo.h>

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

static GError * __check_property_format(gchar **strv);

static GError * __del_container_properties(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, gchar **names);

static GError * __set_container_properties(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, gchar **props);

static GError * __get_container_properties(struct sqlx_sqlite3_s *sq3,
		struct hc_url_s *url, gchar **names, gchar ***result);

/* ------------------------------------------------------------------------- */

static GError *
__del_container_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gchar **names)
{
	GError *err = NULL;
	gchar **p_name;
	struct sqlx_repctx_s *repctx = NULL;

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	if (!names || !*names)
		__exec_cid(sq3->db, "DELETE FROM properties WHERE cid = ?", hc_url_get_id(url));
	else {
		for (p_name=names; !err && p_name && *p_name ;p_name++) {
			sqlite3_stmt *stmt = NULL;
			gint rc;

			sqlite3_prepare_debug(rc, sq3->db, "DELETE FROM properties WHERE cid = ? AND name = ?", -1, &stmt, NULL);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = M1_SQLITE_GERROR(sq3->db, rc);
			else {
				(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
				(void) sqlite3_bind_text(stmt, 2, *p_name, strlen(*p_name), NULL);
				sqlite3_step_debug_until_end (rc, stmt);
				if (rc != SQLITE_DONE)
					GRID_WARN("SQLite error rc=%d", rc);
				sqlite3_finalize_debug(rc, stmt);
			}
		}
	}

	return sqlx_transaction_end(repctx, err);
}

static GError *
__replace_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const gchar *name, const gchar *value)
{
	GError *err = NULL;
	gint rc;
	sqlite3_stmt *stmt = NULL;

	EXTRA_ASSERT(name != NULL && *name != '\0');
	EXTRA_ASSERT(value != NULL && *value != '\0');
	GRID_TRACE("%s(n=%s,v=%s)", __FUNCTION__, name, value);

	sqlite3_prepare_debug(rc, sq3->db,
			"REPLACE INTO properties (name,value,cid) VALUES (?,?,?)", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_text(stmt, 1, name, -1, NULL);
		(void) sqlite3_bind_text(stmt, 2, value, -1, NULL);
		(void) sqlite3_bind_blob(stmt, 3, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__set_container_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gchar **props)
{
	struct sqlx_repctx_s *repctx = NULL;
	GError *err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;
	for (gchar *p; !err && (p = *props) ;props++) {
		gchar *name, *eq, *value;

		name = p;
		eq = strchr(name, '=');
		value = eq + 1;
		*eq = '\0';
		err = __replace_property(sq3, url, name, value);
	}

	return sqlx_transaction_end(repctx, err);
}

static gchar *
__pack_property(const unsigned char *n, int n_size,
		const unsigned char *v, int v_size)
{
	GString *gstr = g_string_sized_new(n_size + v_size + 2);
	g_string_append_len(gstr, (gchar*)n, n_size);
	g_string_append_c(gstr, '=');
	g_string_append_len(gstr, (gchar*)v, v_size);
	return g_string_free(gstr, FALSE);
}

static GError *
__get_all_container_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, GPtrArray *gpa)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	/* prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT name,value FROM properties WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			gchar *prop = __pack_property(
					sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0),
					sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));
			g_ptr_array_add(gpa, prop);
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_one_property(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, const gchar *name, GPtrArray *gpa)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	GRID_TRACE("%s(n=%s)", __FUNCTION__, name);

	sqlite3_prepare_debug(rc, sq3->db,
			"SELECT name,value FROM properties WHERE cid = ? AND name = ?",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id(url), hc_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, name, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			gchar *prop = __pack_property(
					sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0),
					sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));
			g_ptr_array_add(gpa, prop);
		}
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_container_properties(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url, gchar **names, gchar ***result)
{
	GError *err = NULL;
	GPtrArray *gpa;

	gpa = g_ptr_array_new();

	if (!names || !*names)
		err = __get_all_container_properties(sq3, url, gpa);
	else {
		gchar **p;
		for (p=names; !err && *p ;p++)
			err = __get_one_property(sq3, url, *p, gpa);
	}

	if (err) {
		gpa_str_free(gpa);
		return err;
	}

	g_ptr_array_add(gpa, NULL);
	*result = (gchar**) g_ptr_array_free(gpa, FALSE);
	return NULL;
}

static GError *
__check_property_format(gchar **strv)
{
	guint line = 1;
	gchar *p_eq;

	if (!strv)
		return NEWERROR(CODE_BAD_REQUEST, "NULL array");

	for (; *strv ; strv++, line++) {
		if (!(p_eq = strchr(*strv, '=')))
			return NEWERROR(CODE_BAD_REQUEST, "line %u : no equal symbol", line);
		if (p_eq == *strv)
			return NEWERROR(CODE_BAD_REQUEST, "line %u : no name", line);
		if (!*(p_eq+1))
			return NEWERROR(CODE_BAD_REQUEST, "line %u : no value", line);
	}

	return NULL;
}

/* ------------------------------------------------------------------------- */

GError *
meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **props)
{
	EXTRA_ASSERT(props != NULL);
 
	GError *err;
	if ((err = __check_property_format(props)) != NULL) {
		g_prefix_error(&err, "Malformed properties: ");
		return err;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, url, NULL))) {
			err = __set_container_properties(sq3, url, props);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **names)
{
	EXTRA_ASSERT(names != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, url, NULL))) {
			err = __del_container_properties(sq3, url, names);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar **names, gchar ***result)
{
	EXTRA_ASSERT(result != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, url, NULL))) {
			err = __get_container_properties(sq3, url, names, result);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

