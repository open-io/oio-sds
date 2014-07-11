#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1"
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

int meta1_backend_log_level = 0;

static inline GError*
_range_not_managed(const container_id_t cid)
{
	return NEWERROR(CODE_RANGE_NOTFOUND,
			"prefix [%02X%02X] not managed",
			((guint8*)cid)[0], ((guint8*)cid)[1]);
}

static inline int
m1_to_sqlx(enum m1v2_open_type_e t)
{
	switch (t & 0x03) {
		case M1V2_OPENBASE_LOCAL:
			return SQLX_OPEN_LOCAL;
		case M1V2_OPENBASE_MASTERONLY:
			return SQLX_OPEN_MASTERONLY;
		case M1V2_OPENBASE_SLAVEONLY:
			return SQLX_OPEN_SLAVEONLY;
		case M1V2_OPENBASE_MASTERSLAVE:
			return SQLX_OPEN_MASTERSLAVE;
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

	EXTRA_ASSERT(m1 != NULL);
	EXTRA_ASSERT(handle != NULL);

	if (!meta1_prefixes_is_managed(m1->prefixes, cid))
		return _range_not_managed(cid);

	/* Get the Hexa representation of the prefix */
	g_snprintf(base, sizeof(base), "%02X%02X",
			((guint8*)cid)[0], ((guint8*)cid)[1]);

	/* Now open/lock the base in a way suitable for our op */
	err = sqlx_repository_open_and_lock(m1->repository,
			META1_TYPE_NAME, base, m1_to_sqlx(how), handle, NULL);

	if (err != NULL) {
		if (err->code < 300 || err->code > 399)
			g_prefix_error(&err, "Open/Lock error: ");  
		return err;
	}

	EXTRA_ASSERT(*handle != NULL);
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

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

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
		return NEWERROR(CODE_CONTAINER_NOTFOUND, "no such container");
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

