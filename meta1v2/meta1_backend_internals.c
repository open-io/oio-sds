/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

static gboolean
m1b_check_ns_url (struct meta1_backend_s *m1, struct oio_url_s *url)
{
	if (!url || !m1 || !oio_url_has(url, OIOURL_NS))
		return FALSE;
	return !strcmp(m1->ns_name, oio_url_get (url, OIOURL_NS));
}

void
__exec_cid(sqlite3 *handle, const gchar *sql, const container_id_t cid)
{
	int rc;
	const char *next;
	sqlite3_stmt *stmt = NULL;

	while (sql && *sql) {

		sqlite3_prepare_debug(rc, handle, sql, -1, &stmt, &next);
		if (rc != SQLITE_OK)
			continue;
		sql = next;

		(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);

		do { rc = sqlite3_step(stmt); } while (rc == SQLITE_ROW);

		sqlite3_finalize_debug(rc, stmt);
	}
}

static int
m1_to_sqlx(enum m1v2_open_type_e t)
{
	switch (t & 0x03) {
		case M1V2_OPENBASE_LOCAL:
			return SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL;
		case M1V2_OPENBASE_MASTERONLY:
			return SQLX_OPEN_CREATE|SQLX_OPEN_MASTERONLY;
		case M1V2_OPENBASE_SLAVEONLY:
			return SQLX_OPEN_CREATE|SQLX_OPEN_SLAVEONLY;
		case M1V2_OPENBASE_MASTERSLAVE:
			return SQLX_OPEN_CREATE|SQLX_OPEN_MASTERSLAVE;
	}

	g_assert_not_reached();
	return SQLX_OPEN_CREATE|SQLX_OPEN_LOCAL;
}

GError *
__check_backend_events (struct meta1_backend_s *m1)
{
	EXTRA_ASSERT(m1 != NULL);
	if (m1->notifier && oio_events_queue__is_stalled (m1->notifier))
		return BUSY("Too many pending events");
	return NULL;
}

GError*
_open_and_lock(struct meta1_backend_s *m1, struct oio_url_s *url,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **handle)
{
	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(handle != NULL);

	GRID_TRACE2("%s(%p,%s,%d,%p)", __FUNCTION__, (void*)m1,
			oio_url_get (url, OIOURL_HEXID), how, (void*)handle);

	if (!oio_url_has (url, OIOURL_HEXID))
		return NEWERROR (CODE_BAD_REQUEST, "Partial URL (missing HEXID)");
	if (!m1b_check_ns_url (m1, url))
		return NEWERROR(CODE_NAMESPACE_NOTMANAGED, "Invalid NS");

	gchar base[5];
	const guint8 *cid = oio_url_get_id(url);
	meta1_backend_basename(m1, cid, base, sizeof(base));

	if (!meta1_prefixes_is_managed(m1->prefixes, cid))
		return NEWERROR(CODE_RANGE_NOTFOUND, "prefix [%s] not managed", base);

	/* Now open/lock the base in a way suitable for our op */
	struct sqlx_name_s n = {.base=base, .type=NAME_SRVTYPE_META1, .ns=m1->ns_name};
	GError *err = sqlx_repository_open_and_lock(m1->repo, &n, m1_to_sqlx(how), handle, NULL);

	if (err != NULL) {
		if (!CODE_IS_REDIRECT(err->code))
			g_prefix_error(&err, "Open/Lock error: ");
		return err;
	}

	EXTRA_ASSERT(*handle != NULL);
	GRID_TRACE("Opened and locked [%s][%s] -> [%s][%s]",
			base, NAME_SRVTYPE_META1,
			(*handle)->name.base, (*handle)->name.type);
	return NULL;
}

GError*
__create_user(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url)
{
	if (!oio_url_has_fq_container (url))
		return NEWERROR(CODE_BAD_REQUEST, "Partial URL");

	static const gchar *sql = "INSERT INTO users ('cid','account','user') VALUES (?,?,?)";

	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	int rc;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

	/* Prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	else {
		sqlite3_bind_blob(stmt, 1, oio_url_get_id(url), oio_url_get_id_size(url), NULL);
		sqlite3_bind_text(stmt, 2, oio_url_get(url, OIOURL_ACCOUNT), -1, NULL);
		sqlite3_bind_text(stmt, 3, oio_url_get(url, OIOURL_USER), -1, NULL);

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
		GRID_DEBUG("User creation failed : (%d) %s", err->code, err->message);

	return err;
}

GError*
__info_user(struct sqlx_sqlite3_s *sq3, struct oio_url_s *url, gboolean ac,
		struct oio_url_s ***result)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *gpa;
	int rc;
	gboolean found;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);
	EXTRA_ASSERT(url != NULL);

retry:
	/* Prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT account,user FROM users WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);
	(void) sqlite3_bind_blob(stmt, 1, oio_url_get_id (url), oio_url_get_id_size (url), NULL);

	/* Run the results */
	found = FALSE;
	gpa = result ? g_ptr_array_new() : NULL;
	do { if (SQLITE_ROW == (rc = sqlite3_step(stmt))) {
		found = TRUE;
		if (!gpa) continue;
		struct oio_url_s *u = oio_url_empty ();
		oio_url_set (u, OIOURL_NS, oio_url_get (url, OIOURL_NS));
		oio_url_set (u, OIOURL_ACCOUNT, (char*)sqlite3_column_text(stmt, 0));
		oio_url_set (u, OIOURL_USER, (char*)sqlite3_column_text(stmt, 1));
		oio_url_set (u, OIOURL_HEXID, oio_url_get (url, OIOURL_HEXID));
		g_ptr_array_add(gpa, u);
	} } while (rc == SQLITE_ROW);

	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
		g_prefix_error(&err, "DB error: ");
	}

	sqlite3_finalize_debug(rc,stmt);
	stmt = NULL;

	if (err) {
		if (gpa) {
			g_ptr_array_set_free_func (gpa, (GDestroyNotify)oio_url_clean);
			g_ptr_array_free (gpa, TRUE);
		}
		return err;
	}

	if (!found) {
		if (gpa) g_ptr_array_free (gpa, TRUE);
		if (ac) {
			ac = FALSE; /* do not retry */
			err = __create_user (sq3, url);
			if (!err) goto retry;
		}
		return NEWERROR(CODE_USER_NOTFOUND, "no such user");
	}
	if (gpa)
		*result = (struct oio_url_s**) metautils_gpa_to_array(gpa, TRUE);
	return NULL;
}

void
gpa_str_free(GPtrArray *gpa)
{
	if (!gpa)
		return;
	g_ptr_array_set_free_func (gpa, g_free);
	g_ptr_array_free(gpa, TRUE);
}

