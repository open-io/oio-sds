/*
OpenIO SDS sqlx
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

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <resolver/hc_resolver.h>
#include <server/transport_gridd.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/sqliterepo.h>
#include "sqlx_service.h"

# ifndef SQLX_DIR_SCHEMAS
#  define SQLX_DIR_SCHEMAS NULL
# endif

#define SQLX_TYPE "sqlx"

#define SQLX_SCHEMA \
	"INSERT INTO admin(k,v) VALUES (\"schema_version\",\"1.0\");"\
	"INSERT INTO admin(k,v) VALUES (\"version:main.admin\",\"1:0\")"

static GString *dir_schemas = NULL;

static GError *
_load_schema_directory (struct sqlx_service_s *ss, const char *dir)
{
	GError *err = NULL;
	GDir *gdir = g_dir_open (dir, 0, &err);
	if (err)
		return err;

	const char * filename;
	while (!err && NULL != (filename = g_dir_read_name (gdir))) {
		if (filename[0] == '.')
			continue;
		gsize len = 0;
		gchar *content = NULL;
		gchar *fullpath = g_strjoin (G_DIR_SEPARATOR_S, dir, filename, NULL);
		if (g_file_get_contents (fullpath, &content, &len, &err)) {
			err = sqlx_repository_configure_type (ss->repository,
					filename, content);
			g_free (content);
		}
		g_free0(fullpath);
	}

	g_dir_close (gdir);
	return err;
}

static gboolean
_post_config(struct sqlx_service_s *ss)
{
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			sqlx_sql_gridd_get_requests(), ss->repository);

	if (dir_schemas && dir_schemas->len) {
		if (!g_file_test (dir_schemas->str, G_FILE_TEST_IS_DIR)) {
			GRID_WARN ("Invalid directory for schemas descriptions: (%d) %s",
					ENOENT, "Not a directory");
			return FALSE;
		}
		GError *err = _load_schema_directory (ss, dir_schemas->str);
		if (NULL != err) {
			GRID_ERROR ("Cannot load schema directory %s: (%d) %s",
				dir_schemas->str, err->code, err->message);
			g_clear_error (&err);
			return FALSE;
		}
	}

	/* XXX(jfs): maybe initiate a events context */
	return TRUE;
}

static void
_set_defaults(struct sqlx_service_s *ss)
{
	ss->flag_cached_bases = FALSE;
	const char *def = SQLX_DIR_SCHEMAS;
	if (def)
		dir_schemas = g_string_new (def);
}

int
main(int argc, char ** argv)
{
	static struct grid_main_option_s custom_options[] = {
		{"DirectorySchemas", OT_STRING, {.str = &dir_schemas},
			"Override the default directory where application schemas "
			"are configured." },
		{NULL, 0, {.i=0}, NULL}
	};
	static struct sqlx_service_config_s cfg = {
		NAME_SRVTYPE_SQLX, "sqlxv1",
		"el/"NAME_SRVTYPE_SQLX, 1, 3,
		SQLX_SCHEMA, 1, 3,
		sqlx_service_resolve_peers, _post_config, _set_defaults
	};
	sqlx_service_set_custom_options (custom_options);
	return sqlite_service_main(argc, argv, &cfg);
}

