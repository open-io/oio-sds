#ifndef GRID__META1_INTERNALS_SQLITE__H
# define GRID__META1_INTERNALS_SQLITE__H 1

# include <sqlite3.h>

static inline void
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

#endif /* GRID__META1_INTERNALS_SQLITE__H */
