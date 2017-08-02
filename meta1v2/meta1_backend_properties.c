/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>

#include "./internals.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

static GError *
__del_container_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
		gchar **names)
{
	GError *err = NULL;
	gchar **p_name;

	if (!names || !*names)
		__exec_cid(sq3->db, "DELETE FROM properties WHERE cid = ?", oio_url_get_id(url));
	else {
		for (p_name=names; !err && p_name && *p_name ;p_name++) {
			sqlite3_stmt *stmt = NULL;
			gint rc;

			sqlite3_prepare_debug(rc, sq3->db, "DELETE FROM properties WHERE cid = ? AND name = ?", -1, &stmt, NULL);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = M1_SQLITE_GERROR(sq3->db, rc);
			else {
				(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
				(void) sqlite3_bind_text(stmt, 2, *p_name, strlen(*p_name), NULL);
				sqlite3_step_debug_until_end (rc, stmt);
				if (rc != SQLITE_DONE)
					GRID_WARN("SQLite error rc=%d", rc);
				sqlite3_finalize_debug(rc, stmt);
			}
		}
	}

	return err;
}

static GError *
__replace_property(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url,
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
		(void) sqlite3_bind_blob(stmt, 3, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		sqlite3_step_debug_until_end (rc, stmt);
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

GError *__set_container_properties(struct sqlx_sqlite3_s *sq3,
		struct oio_url_s *url, gchar **props) {
	if (!props)
		return NULL;
	for (gchar **p = props; *p && *(p + 1); p += 2) {
		GError *err = NULL;
		err = __replace_property(sq3, url, *p, *(p + 1));
		if (NULL != err)
			return err;
	}
	return NULL;
}

static gchar* item(struct sqlite3_stmt *stmt, int i) {
	return g_strndup((gchar*)sqlite3_column_text(stmt, i),
					 sqlite3_column_bytes(stmt, i));
}

static GError *
__get_all_container_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, GPtrArray *gpa)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	/* prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT name,value FROM properties WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			g_ptr_array_add(gpa, item(stmt, 0));
			g_ptr_array_add(gpa, item(stmt, 1));
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_one_property(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, const gchar *name, GPtrArray *gpa)
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
		(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		(void) sqlite3_bind_text(stmt, 2, name, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			g_ptr_array_add(gpa, item(stmt, 0));
			g_ptr_array_add(gpa, item(stmt, 1));
		}
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_container_properties(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, gchar **names, gchar ***result)
{
	GError *err = NULL;
	GPtrArray *gpa = g_ptr_array_new();

	if (!names || !*names)
		err = __get_all_container_properties(sq3, url, gpa);
	else {
		for (gchar **p=names; !err && *p ;p++)
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
__check_property_format(gchar **kv)
{
	for (; *kv && *(kv+1); kv+=2) {
		if (!oio_str_is_set(*kv))
			return NEWERROR(CODE_BAD_REQUEST, "empty key");
	}
	return NULL;
}

/* ------------------------------------------------------------------------- */

GError *
meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **props, gboolean flush)
{
	EXTRA_ASSERT(props != NULL);

	GError *err;
	if (NULL != (err = __check_property_format(props))) {
		g_prefix_error(&err, "Malformed properties: ");
		return err;
	}

	struct sqlx_sqlite3_s *sq3 = NULL;
	err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			if (flush) {
				err = __del_container_properties(sq3, url, NULL);
				if (err) g_prefix_error(&err, "Flush error: ");
			}
			if (!err) {
				err = __set_container_properties(sq3, url, props);
				if (err) g_prefix_error(&err, "Set error: ");
			}
		}
		err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError *
meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **names)
{
	EXTRA_ASSERT(names != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			err = __del_container_properties(sq3, url, names);
			if (err) g_prefix_error(&err, "Delete error: ");
		}
		err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

GError *
meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		struct oio_url_s *url, gchar **names, gchar ***result)
{
	EXTRA_ASSERT(result != NULL);

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (err) return err;

	struct sqlx_repctx_s *repctx = NULL;
	if (!(err = sqlx_transaction_begin(sq3, &repctx))) {
		if (!(err = __info_user(sq3, url, FALSE, NULL))) {
			err = __get_container_properties(sq3, url, names, result);
			if (err) g_prefix_error(&err, "Lookup error: ");
		}
		err = sqlx_transaction_end(repctx, err);
	}

	sqlx_repository_unlock_and_close_noerror(sq3);
	return err;
}

