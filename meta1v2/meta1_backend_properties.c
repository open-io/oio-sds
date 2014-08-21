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
		const container_id_t cid, gchar **names);

static GError * __set_container_properties(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gchar **props);

static GError * __get_container_properties(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gchar **names, gchar ***result);

/* ------------------------------------------------------------------------- */

static GError *
__del_container_properties(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gchar **names)
{
	GError *err = NULL;
	gchar **p_name;
	struct sqlx_repctx_s *repctx = NULL;

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	if (!names || !*names) {
		__exec_cid(sq3->db, "DELETE FROM properties WHERE cid = ?", cid);
	}
	else {
		for (p_name=names; !err && p_name && *p_name ;p_name++) {
			sqlite3_stmt *stmt = NULL;
			gint rc;

			sqlite3_prepare_debug(rc, sq3->db, "DELETE FROM properties WHERE cid = ? AND name = ?", -1, &stmt, NULL);
			if (rc != SQLITE_OK && rc != SQLITE_DONE)
				err = M1_SQLITE_GERROR(sq3->db, rc);
			else {
				(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
					(void) sqlite3_bind_text(stmt, 2, *p_name, strlen(*p_name), NULL);
				rc = sqlite3_step(stmt);
				if (rc != SQLITE_DONE)
					GRID_WARN("SQLite error rc=%d", rc);
				sqlite3_finalize_debug(rc, stmt);
			}
		}
	}

	return sqlx_transaction_end(repctx, err);
}



static GError *
__replace_property(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
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
		(void) sqlite3_bind_blob(stmt, 3, cid, sizeof(container_id_t), NULL);
		do {
			rc = sqlite3_step(stmt);
		} while (rc == SQLITE_ROW);
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__set_container_properties(struct sqlx_sqlite3_s *sq3,
		const container_id_t cid, gchar **props)
{
	gchar *p;
	GError *err = NULL;
	struct sqlx_repctx_s *repctx = NULL;

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	for (; !err && (p = *props) ;props++) {
		gchar *name, *eq, *value;

		name = p;
		eq = strchr(name, '=');
		value = eq + 1;
		*eq = '\0';
		err = __replace_property(sq3, cid, name, value);
	}

	return sqlx_transaction_end(repctx, err);
}

static gchar *
__pack_property(const unsigned char *n, int n_size,
		const unsigned char *v, int v_size)
{
	GString *gstr;

	gstr = g_string_sized_new(n_size + v_size + 2);
	g_string_append_len(gstr, (gchar*)n, n_size);
	g_string_append_c(gstr, '=');
	g_string_append_len(gstr, (gchar*)v, v_size);

	return g_string_free(gstr, FALSE);
}

static GError *
__get_all_container_properties(struct sqlx_sqlite3_s *sq3, const container_id_t cid, GPtrArray *gpa)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	/* prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT name,value FROM properties WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		do {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_ROW) {
				gchar *prop = __pack_property(
						sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0),
						sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));
				g_ptr_array_add(gpa, prop);
			}
		} while (rc == SQLITE_ROW);
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_one_property(struct sqlx_sqlite3_s *sq3, const container_id_t cid, const gchar *name, GPtrArray *gpa)
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
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, name, -1, NULL);

		do {
			rc = sqlite3_step(stmt);
			if (rc == SQLITE_ROW) {
				gchar *prop = __pack_property(
						sqlite3_column_text(stmt, 0), sqlite3_column_bytes(stmt, 0),
						sqlite3_column_text(stmt, 1), sqlite3_column_bytes(stmt, 1));
				g_ptr_array_add(gpa, prop);
			}
		} while (rc == SQLITE_ROW);
		if (rc != SQLITE_OK && rc != SQLITE_DONE)
			err = M1_SQLITE_GERROR(sq3->db, rc);
		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_container_properties(struct sqlx_sqlite3_s *sq3, const container_id_t cid, gchar **names, gchar ***result)
{
	GError *err = NULL;
	GPtrArray *gpa;

	gpa = g_ptr_array_new();

	if (!names || !*names)
		err = __get_all_container_properties(sq3, cid, gpa);
	else {
		gchar **p;
		for (p=names; !err && *p ;p++)
			err = __get_one_property(sq3, cid, *p, gpa);
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
		return NEWERROR(400, "NULL array");

	for (; *strv ; strv++, line++) {
		if (!(p_eq = strchr(*strv, '=')))
			return NEWERROR(400, "line %u : no equal symbol", line);
		if (p_eq == *strv)
			return NEWERROR(400, "line %u : no name", line);
		if (!*(p_eq+1))
			return NEWERROR(400, "line %u : no value", line);
	}

	return NULL;
}

/* ------------------------------------------------------------------------- */

GError *
meta1_backend_set_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **props)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(props != NULL);

	if ((err = __check_property_format(props)) != NULL) {
		g_prefix_error(&err, "Malformed properties: ");
		return err;
	}

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __set_container_properties(sq3, cid, props);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_del_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **names)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(names != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __del_container_properties(sq3, cid, names);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}



GError *
meta1_backend_get_container_properties(struct meta1_backend_s *m1,
		const container_id_t cid, gchar **names, gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(result != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		if (!(err = __info_container(sq3, cid, NULL))) {
			err = __get_container_properties(sq3, cid, names, result);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}
