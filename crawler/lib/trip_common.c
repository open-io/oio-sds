/*
OpenIO SDS crawler
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
#define G_LOG_DOMAIN "grid.crawler.trip_common"
#endif //G_LOG_DOMAIN

#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/sqlite_utils.h>

#include <glib.h>

#include "trip_common.h"

// FIX TODO: source code to move in sqliterepo ?!??! common trip_prefix/trip_sqlx

//=============================================================================
/**
 * \brief function call automatically, build bdd file name
 * n: realy bdd name
 * t: ="meta1"
 */
static void
tc_sqliterepo_file_locator(gpointer ignored, struct sqlx_name_s *n, GString *result)
{
	(void) ignored;
	g_string_truncate(result, 0);
	g_string_append(result, n->base);
}

/**
 * \brief initialize repository structure
 *
 * basedir:  path base
 * svc_type: SQLX_TYPE / MITA1_TYPE.... 
 * repo:     the final structur initalised
 */
GError*
tc_sqliterepo_initRepository(const gchar* basedir, gchar* svc_type, sqlx_repository_t **repo)
{
	GError* err = NULL;
	struct sqlx_repo_config_s cfg;

	memset(&cfg, 0, sizeof(struct sqlx_repo_config_s));
	cfg.flags = SQLX_REPO_NOCACHE|SQLX_REPO_NOLOCK;
	/*cfg.lock.ns = ns_name;
	  cfg.lock.type = SQLX_TYPE;
	  cfg.lock.srv = url->str;
	  */

	err = sqlx_repository_init(basedir, &cfg, repo);
	if (err != NULL)
		return err;

	err = sqlx_repository_configure_type(*repo, svc_type, NULL, "");
	if (err != NULL) {
	  	g_prefix_error(&err, "sqlx schema error: ");
	 	GRID_WARN("Failed on repository init [%s]: %s", basedir, err->message);
		sqlx_repository_clean(*repo);
		return err;
	}

	sqlx_repository_set_locator(*repo, tc_sqliterepo_file_locator, NULL);

	return NULL;
}

/**
 * \brief extract admin properties field from bdd file
 *
 * repo: repository
 * type_: type of bdd
 * bddnameWithExtension: name of bdd file (not absolute path--> repo)
 * key: the field name to returned value
 *
 * return value or NULL
 *
 *  OBLIGATOIRE: g_free(returnedValue) i en retoiur
 */
gchar*
tc_sqliterepo_admget(sqlx_repository_t* repo, gchar* type_, gchar* bddnameWithExtension, gchar* key)
{
	struct sqlx_sqlite3_s *sq3 = NULL;
	GError* err = NULL;
	gchar *value = NULL;

	/* Now open/lock the base in a way suitable for our op */
	struct sqlx_name_s n = {.base=bddnameWithExtension, .type=type_, .ns=""};
	err = sqlx_repository_open_and_lock(repo, &n, SQLX_OPEN_LOCAL, &sq3, NULL);

	if (err != NULL) {
		if (!CODE_IS_REDIRECT(err->code))
			g_prefix_error(&err, "Open/Lock error: ");

		GRID_WARN("not open and lock: [%s]: %s", bddnameWithExtension,  err->message);
		g_clear_error(&err);
		return NULL;
	}

	/* Now read field from admin table which contained prefix container */
	value = sqlx_admin_get_str(sq3, key);
	GRID_TRACE("get %s=[%s]", key, value);

	if (!value)
		GRID_WARN("Unknown field \"%s\" on db \"%s\"", key, bddnameWithExtension);

	/* unlock, close and clear... */
	err = sqlx_repository_unlock_and_close(sq3);
	if (err != NULL)
		GRID_WARN("close bdd: [%s]: %s", bddnameWithExtension,  err->message);
	if (err) g_clear_error(&err);

	return value;
}

void tc_sqliterepo_free(sqlx_repository_t** repo)
{
	if (!repo)
		return;

	sqlx_repository_clean(*repo);
	*repo = NULL;
}

