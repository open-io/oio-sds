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

#define FMT_COUNT "SELECT COUNT(*) FROM %s WHERE cid = ?"

static GError*
__count_FK (struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		const char *table, guint *count)
{
	gint rc;
	sqlite3_stmt *stmt = NULL;

	gchar sql[sizeof(FMT_COUNT)+32];
	g_snprintf (sql, sizeof(sql), FMT_COUNT, table);

	sqlite3_prepare_debug(rc, sq3->db, sql, -1, &stmt, NULL);
	if (rc != SQLITE_OK)
		return M1_SQLITE_GERROR(sq3->db, rc);

	(void) sqlite3_bind_blob(stmt, 1, hc_url_get_id (url), hc_url_get_id_size (url), NULL);

	guint _count = 0;
	while (SQLITE_ROW == (rc = sqlite3_step(stmt)))
		_count += sqlite3_column_int(stmt, 0);

	GError *err = NULL;
	if (rc != SQLITE_OK && rc != SQLITE_DONE)
		err = M1_SQLITE_GERROR(sq3->db, rc);
	sqlite3_finalize_debug(rc, stmt);

	if (err)
		return err;
	*count = _count;
	return NULL;
}

GError*
__destroy_container(struct sqlx_sqlite3_s *sq3, struct hc_url_s *url,
		gboolean force, gboolean *done)
{
	GError *err = NULL;
	gint count_actions = 0;
	struct sqlx_repctx_s *repctx = NULL;

	EXTRA_ASSERT(sq3 != NULL);
	EXTRA_ASSERT(sq3->db != NULL);

	err = sqlx_transaction_begin(sq3, &repctx);
	if (NULL != err)
		return err;

	if (force) {
		__exec_cid (sq3->db, "DELETE FROM services WHERE cid = ?", hc_url_get_id (url));
		count_actions += sqlite3_changes(sq3->db);
		__exec_cid (sq3->db, "DELETE FROM properties WHERE cid = ?", hc_url_get_id (url));
		count_actions += sqlite3_changes(sq3->db);
	} else {
		guint count_services = 0, count_properties = 0;

		/* No forced op, we count the services belonging to the container. */
		err = __count_FK(sq3, url, "services", &count_services);
		if (!err)
			err = __count_FK(sq3, url, "properties", &count_properties);

		/* If any service is found, this is an error. */
		if (!err && count_services > 0)
			err = NEWERROR(CODE_USER_INUSE, "User still linked to services");
		if (!err && count_properties > 0)
			err = NEWERROR(CODE_USER_INUSE, "User still has properties");
	}

	if (!err) {
		__exec_cid(sq3->db, "DELETE FROM users WHERE cid = ?", hc_url_get_id (url));
		count_actions += sqlite3_changes(sq3->db);
	}

	*done = !err && (count_actions > 0);

	if (!err && !*done)
		err = NEWERROR(CODE_USER_NOTFOUND, "User not found");

	return sqlx_transaction_end(repctx, err);
}

/* ------------------------------------------------------------------------- */

GError *
meta1_backend_user_create(struct meta1_backend_s *m1,
		struct hc_url_s *url)
{
	EXTRA_ASSERT(url != NULL);
	if (!hc_url_has_fq_container (url))
		return NEWERROR(CODE_BAD_REQUEST, "Partial URL");

	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, SQLX_OPEN_MASTERONLY, &sq3);
	if (!err) {
		if (!(err = __info_user(sq3, url, FALSE, NULL)))
			err = NEWERROR(CODE_CONTAINER_EXISTS, "User already created");
		else {
			g_clear_error(&err);
			if (NULL != (err = __create_user(sq3, url)))
				g_prefix_error(&err, "Query error: ");
		}
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_user_destroy(struct meta1_backend_s *m1,
		struct hc_url_s *url, gboolean force)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, SQLX_OPEN_MASTERONLY, &sq3);
	if (!err) {
		gboolean done = FALSE;
		if (!(err = __info_user(sq3, url, FALSE, NULL)))
			err = __destroy_container(sq3, url, force, &done);
		if (NULL != err)
			g_prefix_error(&err, "Query error: ");  
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

GError *
meta1_backend_user_info(struct meta1_backend_s *m1,
		struct hc_url_s *url, gchar ***result)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError *err = _open_and_lock(m1, url, SQLX_OPEN_MASTERSLAVE, &sq3);
	if (!err) {
		struct hc_url_s **urls = NULL;
		if (!(err = __info_user(sq3, url, FALSE, &urls))) {
			if (result) {
				if (!urls)
					*result = g_malloc0(sizeof(struct hc_url_s*));
				else {
					*result = g_malloc0(sizeof(gchar*) * (1+g_strv_length((gchar**)urls)));
					for (int i=0; urls[i] ;++i)
						(*result)[i] = g_strdup(hc_url_get(urls[i], HCURL_WHOLE));
				}
			}
		}
		hc_url_cleanv (urls);
		sqlx_repository_unlock_and_close_noerror(sq3);
	}

	return err;
}

