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

static GError*
__create_container(struct sqlx_sqlite3_s *sq3, const gchar *vns,
		const gchar *cname, const container_id_t cid)
{
	static const gchar *sql = "INSERT INTO containers "
		"('cid','vns','cname') VALUES (?,?,?)";

	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	struct sqlx_repctx_s *repctx = NULL;
	int rc;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	/* Prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);
		(void) sqlite3_bind_text(stmt, 2, vns, -1, NULL);
		(void) sqlite3_bind_text(stmt, 3, cname, -1, NULL);

		/* Run the results */
		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);

		if (rc != SQLITE_OK && rc != SQLITE_DONE) {
			err = M1_SQLITE_GERROR(sq3->db, rc);
			if (rc == SQLITE_CONSTRAINT) {
				g_prefix_error(&err, "Already created? ");
				err->code = CODE_CONTAINER_EXISTS;
			}
		}

		sqlite3_finalize_debug(rc, stmt);
	}

	if (err)
		GRID_DEBUG("Container creation failed : (%d) %s", err->code, err->message);

	return sqlx_transaction_end(repctx, err);
}

static GError*
__count_services(struct sqlx_sqlite3_s *sq3, const container_id_t cid, guint *count)
{
	gint rc;
	guint _count = 0;
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT COUNT(*) FROM services WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);

	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		_count += sqlite3_column_int(stmt, 0);

	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	if (err)
		return err;

	*count = _count;
	return NULL;
}

GError*
__destroy_container(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		gboolean flush, gboolean *done)
{
	GError *err = NULL;
	gint count_actions = 0;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	if (flush) {
		__exec_cid(sq3->db, "DELETE FROM services WHERE cid = ?", cid);
		count_actions += sqlite3_changes(sq3->db);
	}
	else {
		guint count_services = 0;

		/* No flush, we count the services belonging to the container. */
		err = __count_services(sq3, cid, &count_services);

		/* If any service is found, this is an error. */
		if (!err && count_services > 0)
			err = NEWERROR(CODE_CONTAINER_INUSE, "container in use");
	}

	if (!err) {
		__exec_cid(sq3->db, "DELETE FROM properties WHERE cid = ?", cid);
		count_actions += sqlite3_changes(sq3->db);

		__exec_cid(sq3->db, "DELETE FROM containers WHERE cid = ?", cid);
		count_actions += sqlite3_changes(sq3->db);
	}

	*done = !err && (count_actions > 0);

	if (!err && !*done)
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Container not found");

	return sqlx_transaction_end(repctx, err);
}

/* ------------------------------------------------------------------------- */

GError *
meta1_backend_create_container(struct meta1_backend_s *m1,
		const gchar *vns, const gchar *cname, container_id_t *_cid)
{
	GError *err = NULL;
	container_id_t cid;
	struct sqlx_sqlite3_s *sq3 = NULL;

	GRID_TRACE2("%s(%p,%s,%s,%p)", __FUNCTION__, m1, vns, cname, _cid);

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cname != NULL);

	if (vns && *vns && !g_str_has_prefix(vns, m1->ns_name))
		return NEWERROR(400, "Invalid NS/VNS, [%s] not a prefix of [%s]",
				m1->ns_name, vns);

	meta1_name2hash(cid, vns, cname);

	err = _open_and_lock(m1, cid, SQLX_OPEN_MASTERONLY, &sq3);
	if (!err) {
		err = __info_container(sq3, cid, NULL);
		if (!err) {
			err = NEWERROR(CODE_CONTAINER_EXISTS,
					"Container already created");
		}
		else {
			g_clear_error(&err);
			err = __create_container(sq3, (vns && *vns ? vns : m1->ns_name),
					cname, cid);
			if (NULL != err)
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	if (!err) {
		if (_cid)
			memcpy(_cid, cid, sizeof(container_id_t));
	}

	return err;
}

GError *
meta1_backend_destroy_container(struct meta1_backend_s *m1,
		const container_id_t cid, gboolean flush)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, SQLX_OPEN_MASTERONLY, &sq3);
	if (!err) {
		gboolean done = FALSE;
		if (!(err = __info_container(sq3, cid, NULL)))
			err = __destroy_container(sq3, cid, flush, &done);
		if (NULL != err)
			g_prefix_error(&err, "Query error: ");  
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_info_container(struct meta1_backend_s *m1,
		const container_id_t cid, gchar ***result)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, SQLX_OPEN_MASTERSLAVE, &sq3);
	if (!err) {
		err = __info_container(sq3, cid, result);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

static GError *
__get_references_by_prefix(struct sqlx_sqlite3_s *sq3,
		m1b_ref_hook ref_hook, gpointer ref_hook_data)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT vns, cname FROM containers",
			-1, &stmt, NULL);
	if (rc != SQLITE_OK) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
		g_prefix_error(&err, "SQLITE error: ");
	}
	else {
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const unsigned char *ns, *ref;
			ns = sqlite3_column_text(stmt, 0);
			ref = sqlite3_column_text(stmt, 1);
			(*ref_hook)(ref_hook_data, (gchar*)ns, (gchar*)ref);
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);

		sqlite3_finalize_debug(rc, stmt);
	}

	return err;
}

static GError *
__get_references_by_service(struct sqlx_sqlite3_s *sq3,
		const gchar *type, const gchar *url,
		m1b_ref_hook ref_hook, gpointer ref_hook_data)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	sqlite3_prepare_debug(rc, sq3->db, "SELECT c.vns, c.cname "
			"FROM containers AS c, services AS s "
			"WHERE c.cid = s.cid "
			"AND s.srvtype = ? "
			"AND s.url LIKE ?", -1,
			&stmt, NULL);
	if (rc != SQLITE_OK) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
		g_prefix_error(&err, "SQLITE error: ");
	}
	else {
		gchar *urlfull = g_strdup_printf("%%%s%%",url);
		sqlite3_bind_text(stmt, 1, type, -1, NULL);
		sqlite3_bind_text(stmt, 2, urlfull, -1, NULL);
		while (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
			const unsigned char *ns, *ref;
			ns = sqlite3_column_text(stmt, 0);
			ref = sqlite3_column_text(stmt, 1);
			(*ref_hook)(ref_hook_data, (gchar*)ns, (gchar*)ref);
		}
		if (rc != SQLITE_DONE && rc != SQLITE_OK)
			err = M1_SQLITE_GERROR(sq3->db, rc);

		sqlite3_finalize_debug(rc, stmt);
		g_free(urlfull);
	}

	return err;
}

GError*
meta1_backend_list_references(struct meta1_backend_s *m1,
		const container_id_t cid,
		m1b_ref_hook ref_hook, gpointer ref_hook_data)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		err = __get_references_by_prefix(sq3, ref_hook, ref_hook_data);
		if (NULL != err)
			g_prefix_error(&err, "Query error: ");
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError*
meta1_backend_list_references_by_service(struct meta1_backend_s *m1,
		const container_id_t cid, const gchar *srvtype, const gchar *url,
		m1b_ref_hook ref_h, gpointer ref_hdata)
{
	GError *err = NULL;
	struct sqlx_sqlite3_s *sq3 = NULL;

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(cid != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(url != NULL);

	err = _open_and_lock(m1, cid, M1V2_OPENBASE_MASTERSLAVE, &sq3);
	if (!err) {
		err = __get_references_by_service(sq3, srvtype, url, ref_h, ref_hdata);
		if (NULL != err)
			g_prefix_error(&err, "Query error: ");
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

