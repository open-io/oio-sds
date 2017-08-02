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

#include <errno.h>

#include <metautils/lib/metautils.h>
#include <core/oiodir.h>
#include <sqlx/sqlx_client.h>
#include <sqlx/sqlx_client_direct.h>

static struct oio_directory_s *dir = NULL;
static struct oio_sqlx_client_s *sqlx_client = NULL;
static struct oio_sqlx_client_factory_s *sqlx_factory = NULL;
static struct oio_url_s *url = NULL;
static gchar **query = NULL;
static gboolean autocreate = FALSE;

static void
cli_action (void)
{
	if (autocreate) {
		GError *err = oio_sqlx_client__create_db (sqlx_client);
		if (NULL != err) {
			g_printerr ("DB creation failed: (%d) %s\n", err->code, err->message);
			g_clear_error (&err);
			grid_main_set_status (1);
			return;
		}
	}
	struct oio_sqlx_output_ctx_s ctx = {0, 0, 0};
	gchar **out = NULL;
	GRID_DEBUG("Query with %u params: %s", g_strv_length(query+1), query[0]);
	GError *err = oio_sqlx_client__execute_statement (
			sqlx_client, query[0], query+1, &ctx, &out);
	if (err) {
		g_printerr ("# QUERY ERROR: %s\n", query[0]);
		g_printerr ("(%d) %s\n", err->code, err->message);
		g_clear_error (&err);
	} else {
		for (gchar **po = out; *po ;++po) {
			g_print("%s\n", *po);
		}
		g_strfreev (out);
	}
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{"Autocreate", OT_BOOL, {.b=&autocreate},
			"Issue a DB creation before querying"},
		{NULL, 0, {.i=0}, NULL}
	};

	return cli_options;
}

static void
cli_set_defaults(void)
{
	GRID_DEBUG("Setting defaults");
	query = NULL;
	url = NULL;
	dir = NULL;
	sqlx_client = NULL;
	sqlx_factory = NULL;
}

static void
cli_specific_fini(void)
{
	GRID_DEBUG("Exiting");
	g_free0 (query);
	if (sqlx_client)
		oio_sqlx_client__destroy (sqlx_client);
	if (sqlx_factory)
		oio_sqlx_client_factory__destroy (sqlx_factory);
	if (dir)
		oio_directory__destroy (dir);
	oio_url_pclean(&url);
}

static void cli_specific_stop(void) { /* no op */ }

static const gchar *
cli_usage(void)
{
	return
		"NS/ACCOUNT/REF[/TYPE] QUERY [QUERY...]\n"
		"NS/ACCOUNT/REF[/TYPE] 'destroy'";
}

static gboolean
cli_configure(int argc, char **argv)
{
	GRID_DEBUG("Configuration");

	if (argc < 2) {
		g_printerr("Invalid arguments number");
		return FALSE;
	}

	if (!(url = oio_url_init(argv[0]))) {
		g_printerr("Invalid hc URL (%s)\n", strerror(errno));
		return FALSE;
	}

	query = g_strdupv_inline(argv+1);
	if (!query) {
		g_printerr("Missing query (as positional arguments)\n");
		return FALSE;
	}

	GRID_DEBUG("Executing %u requests", g_strv_length(query));

	dir = oio_directory__create_proxy (oio_url_get(url, OIOURL_NS));

	sqlx_factory = oio_sqlx_client_factory__create_sds (
			oio_url_get(url, OIOURL_NS), dir);

	GError *err = oio_sqlx_client_factory__open (sqlx_factory, url, &sqlx_client);
	if (err) {
		g_printerr ("SQLX client init error: (%d) %s\n",
				err->code, err->message);
		g_clear_error (&err);
		return FALSE;
	}

	return TRUE;
}

struct grid_main_callbacks cli_callbacks =
{
	.options = cli_get_options,
	.action = cli_action,
	.set_defaults = cli_set_defaults,
	.specific_fini = cli_specific_fini,
	.configure = cli_configure,
	.usage = cli_usage,
	.specific_stop = cli_specific_stop,
};

int
main(int argc, char **args)
{
	return grid_main_cli(argc, args, &cli_callbacks);
}

