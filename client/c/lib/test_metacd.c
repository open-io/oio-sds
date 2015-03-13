/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

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
	{"AMONS", "AMONS",
		NULL, "test_cache",
		"0868B624A0434AE3B9D73727DE10857CFC67FADEB3AA30CAC8C7DA7C9A27D872"},
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

	gs = gs_grid_storage_init2(pdata->ns, 60, 60, &gse);
	if (!gs) {
		g_assert(gse != NULL);
		g_print("%s\n", gs_error_get_message(gse));
		abort();
	}
	g_assert(gse == NULL);

	check_strings(pdata->pns, gs->ni.name);
	check_strings(pdata->pns, gs->physical_namespace);
	check_strings(pdata->ns, gs->full_vns);

	container = gs_get_container(gs, pdata->refname, 1, &gse);
	if (!container) {
		g_assert(gse != NULL);
		g_print("%s\n", gs_error_get_message(gse));
		abort();
	}

	check_strings(pdata->refname, container->info.name);
	check_strings(pdata->refhexa, container->str_cID);

	gs_container_free(container);
	gs_grid_storage_free(gs);
}

static void
test_get_container(void)
{
	struct test_data_s *td;

	for (td=data; td->ns ;td++)
		test_data(td);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/client/lib/cache/get_container", test_get_container);
	return g_test_run();
}

