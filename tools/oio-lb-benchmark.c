/*
OpenIO SDS oio-lb-benchmark
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oiolb.h>
#include <metautils/lib/metautils.h>


static guint iterations = 50000;
static const char *input_path = NULL;
static const char *pool_descr = NULL;

static void
cli_action(void)
{
	struct oio_lb_world_s *world = oio_lb_local__create_world();
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(world, "main");
	GError *err = oio_lb_world__feed_from_file(world, "rawx", input_path);
	if (!err) {
		oio_lb_world__add_pool_targets(pool, pool_descr);
		GString *pool_dump = oio_lb_world__dump_pool_options(pool);
		GRID_NOTICE("Will do %u iterations with pool: %s",
				iterations, pool_dump->str);
		g_string_free(pool_dump, TRUE);

		oio_lb_world__debug(world);

		int unbalanced = 0;
		GHashTable *counts = g_hash_table_new_full(
				g_str_hash, g_str_equal, g_free, NULL);
		gint64 start = oio_ext_monotonic_time();
		oio_lb_pool__poll_many(pool, iterations, counts, &unbalanced);
		gint64 end = oio_ext_monotonic_time();
		GRID_INFO("%d unbalanced situations on %d shots",
				unbalanced, iterations);
		int targets = oio_lb_world__count_pool_targets(pool);
		oio_lb_world__check_repartition(world, targets, iterations, counts);
		g_hash_table_destroy(counts);
		double duration_seconds = (end - start) / (double) G_TIME_SPAN_SECOND;
		GRID_NOTICE("%.3fs, %"G_GINT64_FORMAT"us per iteration",
				duration_seconds, (end - start) / iterations);
	}
	g_clear_error(&err);
	oio_lb_pool__destroy(pool);
	oio_lb_world__destroy(world);
}

static struct grid_main_option_s *
cli_get_options(void)
{
	static struct grid_main_option_s cli_options[] = {
		{"iterations", OT_UINT, {.u=&iterations},
			"Number of iterations for the benchmark."},
		{NULL, 0, {.i=0}, NULL}
	};

	return cli_options;
}

static void
cli_set_defaults(void)
{
	oio_log_init_level(GRID_LOGLVL_NOTICE);
}

static void
cli_specific_fini(void)
{
	/* no op */
}

static void
cli_specific_stop(void)
{
	/* no op */
}

static const gchar *
cli_usage(void)
{
	return "SERVICE_FILE POOL_DESCR\n\n"
			"    SERVICE_FILE\n"
			"        A file with one service description per line.\n"
			"        Each line must have 1 to 4 fields:\n"
			"            ID [LOC [SCORE [SLOT]]]\n\n"
			"    POOL_DESCR\n"
			"        The description of the service pool to test.\n"
			"        Example:\n"
			"            '3,rawx;min_dist=2'\n";
}

static gboolean
cli_configure(int argc, char **argv)
{
	if (argc < 2) {
		GRID_ERROR("Expected service file and pool description");
		return FALSE;
	}
	if (!oio_var_value_with_files(g_getenv("OIO_NS"), TRUE, NULL)) {
		g_printerr("Unknown NS [%s]\n", g_getenv("OIO_NS"));
		return FALSE;
	}
	input_path = argv[0];
	pool_descr = argv[1];
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
