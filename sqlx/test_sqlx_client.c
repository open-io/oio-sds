/*
OpenIO SDS sqlx
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <core/oiourl.h>
#include <metautils/lib/metautils.h>
#include "sqlx_client.h"

static void
test_query_success (struct oio_sqlx_client_s *client,
		const char *query, gchar **params)
{
	GError *err = NULL;
	gchar **out = NULL;
	struct oio_sqlx_output_ctx_s context = {0,0,0};

	g_printerr("\n");
	err = oio_sqlx_client__execute_statement (client,
			query, params, &context, &out);
	g_assert_no_error (err);
	g_assert_nonnull (out);
	g_printerr("#CTX total:%"G_GINT64_FORMAT
			" changes:%"G_GINT64_FORMAT
			" rowid:%"G_GINT64_FORMAT"\n",
			context.changes, context.total_changes, context.last_rowid);
	for (gchar **p=out; *p ;++p)
		g_printerr("%s\n", *p);
	g_strfreev (out);
	out = NULL;
}

static void
test_local (void)
{
	struct oio_sqlx_client_factory_s *factory = NULL;	
	struct oio_sqlx_client_s *client = NULL;
	GError *err = NULL;

	factory = oio_sqlx_client_factory__create_local ("NS",
			"CREATE TABLE IF NOT EXISTS admin (k TEXT PRIMARY KEY, v TEXT NOT NULL);"
			"CREATE TABLE IF NOT EXISTS sequence (i INT PRIMARY KEY, v TEXT NOT NULL)");

	struct oio_url_s *url = oio_url_empty ();
	oio_url_set (url, OIOURL_NS, "MyNamespace");
	oio_url_set (url, OIOURL_ACCOUNT, "MyAccount");
	oio_url_set (url, OIOURL_USER, "MyUser");
	err = oio_sqlx_client_factory__open (factory, url, &client);
	g_assert_no_error (err);

	test_query_success(client, "SELECT * FROM sqlite_master", NULL);
	test_query_success(client, "INSERT INTO sequence ('v') VALUES ('coin')", NULL);
	test_query_success(client, "INSERT INTO sequence ('v') VALUES ('coin')", NULL);
	test_query_success(client, "INSERT INTO sequence ('v') VALUES ('coin')", NULL);
	test_query_success(client, "INSERT INTO sequence ('v') VALUES ('coin')", NULL);
	test_query_success(client, "SELECT rowid,v FROM sequence", NULL);
	test_query_success(client, "REPLACE INTO admin ('k','v') VALUES ('k0','v0')", NULL);
	test_query_success(client, "REPLACE INTO admin ('k','v') VALUES ('k0','v0')", NULL);
	test_query_success(client, "REPLACE INTO admin ('k','v') VALUES ('k0','v0')", NULL);
	test_query_success(client, "SELECT rowid,k,v FROM admin", NULL);

	oio_sqlx_client__destroy (client);
	client = NULL;

	oio_url_pclean (&url);
	oio_sqlx_client_factory__destroy (factory);
	factory = NULL;
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/sqlx/client/local", test_local);
	return g_test_run();
}
