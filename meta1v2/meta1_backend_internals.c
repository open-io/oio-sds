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
# define G_LOG_DOMAIN "grid.meta1"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include <glib.h>
#include <sqlite3.h>

#include "../metautils/lib/metacomm.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/svc_policy.h"
#include "../sqliterepo/sqliterepo.h"

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"
#include "./meta1_backend_internals.h"

GQuark m1b_gquark_log = 0;

int meta1_backend_log_level = 0;

static inline GError*
_range_not_managed(const container_id_t cid)
{
	return g_error_new(m1b_gquark_log, CODE_RANGE_NOTFOUND,
			"prefix [%02X%02X] not managed",
			((guint8*)cid)[0], ((guint8*)cid)[1]);
}

static inline int
m1_to_sqlx(enum m1v2_open_type_e t)
{
	switch (t) {
		case M1V2_OPENBASE_LOCAL:
			return SQLX_OPEN_LOCAL;
		case M1V2_OPENBASE_MASTERONLY:
			return SQLX_OPEN_MASTERONLY;
		case M1V2_OPENBASE_MASTERSLAVE:
			return SQLX_OPEN_MASTERSLAVE;
		case M1V2_OPENBASE_SLAVEONLY:
			return SQLX_OPEN_SLAVEONLY;
	}

	g_assert_not_reached();
	return SQLX_OPEN_LOCAL;
}

GError*
_open_and_lock(struct meta1_backend_s *m1, const container_id_t cid,
		enum m1v2_open_type_e how, struct sqlx_sqlite3_s **handle)
{
	gchar base[5];
	GError *err = NULL;

	GRID_TRACE2("%s(%p,%p,%d,%p)", __FUNCTION__, (void*)m1,
			(void*)cid, how, (void*)handle);

	META1_ASSERT(m1 != NULL);
	META1_ASSERT(handle != NULL);

	if (!meta1_prefixes_is_managed(m1->prefixes, cid))
		return _range_not_managed(cid);

	/* Get the Hexa representation of the prefix */
	g_snprintf(base, sizeof(base), "%02X%02X",
			((guint8*)cid)[0], ((guint8*)cid)[1]);

	/* Wait for a final status whatever the read/write op */
	if (how != M1V2_OPENBASE_LOCAL) {
		err = sqlx_repository_status_base(m1->repository, META1_TYPE_NAME, base);
		if (!err) { /* MASTER */
			if (how == M1V2_OPENBASE_SLAVEONLY)
				return g_error_new(m1b_gquark_log, CODE_BADOPFORSLAVE, "Not slave!");
		}
		else {
			if (err->code == CODE_REDIRECT) { /* SLAVE */
				if (how == M1V2_OPENBASE_MASTERONLY) 
					return err;
				g_clear_error(&err);
			}
			else { /* real error */
				GRID_TRACE("STATUS error [%s][%s]: (%d) %s",
						base, META1_TYPE_NAME,
						err->code, err->message);
				return err;
			}
		}
	}

	/* Now open/lock the base in a way suitable for our op */
	err = sqlx_repository_open_and_lock(m1->repository,
			META1_TYPE_NAME, base, m1_to_sqlx(how), handle, NULL);

	if (err != NULL) {
		if (err->code < 300 || err->code > 399)
			g_prefix_error(&err, "Open/Lock error: ");  
		return err;
	}

	META1_ASSERT(*handle != NULL);
	GRID_TRACE("Opened and locked [%s][%s] -> [%s][%s]",
			base, META1_TYPE_NAME,
			(*handle)->logical_name, (*handle)->logical_type);
	return NULL;
}

GError*
__info_container(struct sqlx_sqlite3_s *sq3, const container_id_t cid,
		gchar ***result)
{
	GError *err = NULL;
	sqlite3_stmt *stmt = NULL;
	GPtrArray *gpa = NULL;
	int rc;

	META1_ASSERT(sq3 != NULL);
	META1_ASSERT(sq3->db != NULL);

	/* Prepare the statement */
	sqlite3_prepare_debug(rc, sq3->db, "SELECT vns,cname FROM containers WHERE cid = ?", -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);
	(void) sqlite3_bind_blob(stmt, 1, cid, sizeof(container_id_t), NULL);

	/* Run the results */
	gpa = g_ptr_array_new();
	do {
		rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW) {
			gchar *value = g_strdup_printf("%.*s/%.*s",
				 sqlite3_column_bytes(stmt, 0), sqlite3_column_text(stmt, 0),
				 sqlite3_column_bytes(stmt, 1), sqlite3_column_text(stmt, 1));
			g_ptr_array_add(gpa, value);
		}
	} while (rc == SQLITE_ROW);

	if (rc != SQLITE_DONE && rc != SQLITE_OK) {
		err = M1_SQLITE_GERROR(sq3->db, rc);
		g_prefix_error(&err, "DB error: ");
	}

	sqlite3_finalize_debug(rc,stmt);

	/* an error occured */
	if (err) {
		gpa_str_free(gpa);
		return err;
	}

	/* empty result */
	if (gpa->len <= 0) {
		g_ptr_array_free(gpa, TRUE);
		return g_error_new(m1b_gquark_log, CODE_CONTAINER_NOTFOUND, "no such container");
	}

	/* success */
	if (!result)
		gpa_str_free(gpa);
	else {
		g_ptr_array_add(gpa, NULL);
		*result = (gchar**) g_ptr_array_free(gpa, FALSE);
	}
		
	return NULL;
}

void
gpa_str_free(GPtrArray *gpa)
{
	guint i;
	if (!gpa)
		return;
	for (i=0; i<gpa->len ;i++) {
		if (gpa->pdata[i])
			g_free(gpa->pdata[i]);
	}
	g_ptr_array_free(gpa, TRUE);
}

