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
	/* without VNS */
	{"NS", "NS", NULL, "JFS",
		"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},
	{"NS0", "NS0", NULL, "JFS",
		"C3F36084054557E6DBA6F001C41DAFBFEF50FCC83DB2B3F782AE414A07BB3A7A"},
	/* with VNS */
	{"NS.VNS0", "NS", "VNS0", "JFS",
		"D44F8C6088724472AE630C5E14DFBD747323307644B5B432314E77FA9DB7D24C"},
	{"NS0.VNS0", "NS0", "VNS0", "JFS",
		"E6193C9E18E3B88AC94C4065575C9F4A336D22860F5A6FA4FD17D12C0A789865"},
	{NULL, NULL, NULL, NULL, NULL}
};

static void
check_strings(const char *src, const char *s2)
{
	if (!src)
		g_assert(s2 == NULL);
	else {
		g_assert(s2 != NULL);
		if (0 != strcmp(src, s2)) {
			g_printerr("CID mismatch [%s] [%s]\n", src, s2);
			g_assert_not_reached();
		}
	}
}

static void
test_data(struct test_data_s *pdata)
{
	gs_error_t *gse = NULL;
	struct gs_grid_storage_s *gs = NULL;
	struct gs_container_s *container = NULL;

	gs = gs_grid_storage_init_flags(pdata->ns, GSCLIENT_NOINIT, 60, 60, &gse);
	g_assert((gs != NULL) ^ (gse != NULL));
	if (!gs)
		g_debug("gs_grid_storage_init_flags failed : (%d) %s\n",
				gse->code, gse->msg);
	g_assert(gse == NULL);

	check_strings(pdata->pns, gs->ni.name);
	check_strings(pdata->ns, gs->full_vns);
	check_strings(pdata->pns, gs->physical_namespace);
	check_strings(pdata->vns, gs_get_virtual_namespace(gs));

	container = gs_init_container(gs, pdata->refname, 0, &gse);
	g_assert((container != NULL) ^ (gse != NULL));
	if (!container)
		g_debug("gs_init_container failed : (%d) %s\n",
				gse->code, gse->msg);
	g_assert(gse == NULL);

	check_strings(pdata->refname, container->info.name);
	check_strings(pdata->refhexa, container->str_cID);

	gs_container_free(container);
	gs_grid_storage_free(gs);
}

static void
test_init(void)
{
	for (struct test_data_s *td=data; td->ns ;td++)
		test_data(td);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/client/lib/url/init", test_init);
	return g_test_run();
}

