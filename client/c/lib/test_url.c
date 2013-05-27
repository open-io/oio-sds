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

#include <glib.h>

#include "../../../metautils/lib/loggers.h"

#include "./grid_client.h"
#include "./gs_internals.h"

struct test_data_s {
	const char *ns;
	const char *pns;
	const char *vns;
	const char *refname;
	const char *refhexa;
};

struct test_data_s data[] = 
{
	{"NS", "NS", NULL,
		"JFS", "C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},
	{NULL, NULL, NULL, NULL, NULL}
};

static void
check_strings(const char *src, const char *s2)
{
	if (!src)
		g_assert(s2 == NULL);
	else {
		g_assert(s2 != NULL);
		g_assert(0 == strcmp(src, s2));
	}
}

static void
test_data(struct test_data_s *pdata)
{
	gs_error_t *gse = NULL;
	struct gs_grid_storage_s *gs = NULL;
	struct gs_container_s *container = NULL;

	gs = gs_grid_storage_init_flags(pdata->ns, GSCLIENT_NOINIT, 60, 60, &gse);
	if (!gs) {
		g_assert(gse != NULL);
		abort();
	}
	g_assert(gse == NULL);

	check_strings(pdata->ns, gs->ni.name);
	check_strings(pdata->pns, gs->physical_namespace);
	check_strings(pdata->vns, gs->virtual_namespace);

	container = gs_init_container(gs, pdata->refname, 0, &gse);
	if (!container) {
		g_assert(gse != NULL);
		abort();
	}
	
	check_strings(pdata->refname, container->info.name);
	check_strings(pdata->refhexa, container->str_cID);

	gs_container_free(container);
	gs_grid_storage_free(gs);
}

static void
test_init(void)
{
	struct test_data_s *td;

	for (td=data; td->ns ;td++)
		test_data(td);
}

int
main(int argc, char **argv)
{
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_set_prgname(argv[0]);
	g_log_set_default_handler(logger_stderr, NULL);
	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/client/lib/url/init", test_init);

	return g_test_run();
}

