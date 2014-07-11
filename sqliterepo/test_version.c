#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "sqliterepo.test"
#endif

#include <metautils/lib/metautils.h>

#include "./version.h"

#define GQD(D) g_quark_from_static_string(D)

struct cfg_s {
	const gchar *name;
	gint64 v;
	gint64 t;
};

static GTree*
build_version(struct cfg_s *cfg)
{
	GTree *v = version_empty();
	for (; cfg->name ;++cfg) {
		struct object_version_s o;
		o.version = cfg->v;
		o.when = cfg->t;
		g_tree_insert(v, hashstr_create(cfg->name),
				g_memdup(&o, sizeof(o)));
	}
	return v;
}

//------------------------------------------------------------------------------

static void
test_noerror_version(struct cfg_s *c0, struct cfg_s *c1, gint64 r)
{
	gint64 worst = 0;
	GTree *v0 = build_version(c0);
	GTree *v1 = build_version(c1);
	GError *err = version_validate_diff(v0, v1, &worst);
	g_assert_no_error(err);
	g_assert(worst == r);
	g_tree_destroy(v0);
	g_tree_destroy(v1);
}

static void
test_pipeto_version(struct cfg_s *cfg0, struct cfg_s *cfg1, gint64 r)
{
	gint64 worst = 0;
	GTree *v0 = build_version(cfg0);
	GTree *v1 = build_version(cfg1);
	GError *err = version_validate_diff(v0, v1, &worst);
	g_assert_error(err, GQD("sqliterepo"), CODE_PIPETO);
	g_assert(r == worst);
	g_tree_destroy(v0);
	g_tree_destroy(v1);
}

static void
test_pipefrom_version(struct cfg_s *cfg0, struct cfg_s *cfg1, gint64 r)
{
	gint64 worst = 0;
	GTree *v0 = build_version(cfg0);
	GTree *v1 = build_version(cfg1);
	GError *err = version_validate_diff(v0, v1, &worst);
	g_assert_error(err, GQD("sqliterepo"), CODE_PIPEFROM);
	g_assert(r == worst);
	g_tree_destroy(v0);
	g_tree_destroy(v1);
}

static void
test_concurrent_version(struct cfg_s *cfg0, struct cfg_s *cfg1)
{
	gint64 worst = 0;
	GTree *v0 = build_version(cfg0);
	GTree *v1 = build_version(cfg1);
	GError *err = version_validate_diff(v0, v1, &worst);
	g_assert_error(err, GQD("sqliterepo"), CODE_CONCURRENT);
	g_assert(0 == worst);
	g_tree_destroy(v0);
	g_tree_destroy(v1);
}

//------------------------------------------------------------------------------

static void
test_equal(void)
{
	struct cfg_s cfg_empty[] = {
		{NULL, -1, -1}
	};
	test_noerror_version(cfg_empty, cfg_empty, 0);

	struct cfg_s cfg_admin[] = {
		{"main.admin", 0, 0},
		{NULL, -1, -1}
	};
	test_noerror_version(cfg_admin, cfg_admin, 0);
}

static void
test_diff_normal(void)
{
	struct cfg_s cfg0[] = {
		{"main.admin", 0, 0},
		{"main.test", 1, 0},
		{NULL, -1, -1}
	};
	struct cfg_s cfg1[] = {
		{"main.admin", 0, 0},
		{"main.test", 0, 0},
		{NULL, -1, -1}
	};
	test_noerror_version(cfg0, cfg1, 1);
	test_noerror_version(cfg1, cfg0, -1);
}

static void
test_diff_big(void)
{
	struct cfg_s cfg0[] = {
		{"main.admin", 0, 0},
		{"main.test", 2, 0},
		{NULL, -1, -1}
	};
	struct cfg_s cfg1[] = {
		{"main.admin", 0, 0},
		{"main.test", 0, 0},
		{NULL, -1, -1}
	};
	test_pipeto_version(cfg0, cfg1, 2);
	test_pipefrom_version(cfg1, cfg0, -2);
}

static void
test_schema_equal(void)
{
	struct cfg_s cfg0[] = {
		{"main.admin", 0, 0},
		{"main.test", 2, 0},
		{NULL, -1, -1}
	};
	struct cfg_s cfg1[] = {
		{"main.admin", 0, 0},
		{"main.test", 2, 0},
		{"main.test2", 2, 0},
		{NULL, -1, -1}
	};
	// If the schema change, this is an indication of a big change,
	// but not an indication on which side changed. This "main" table's
	// version is the clue.
	test_noerror_version(cfg0, cfg1, 0);
	test_noerror_version(cfg1, cfg0, 0);
}

static void
test_schema_diff(void)
{
	struct cfg_s cfg0[] = {
		{"main.admin", 0, 0},
		{"main.test", 2, 0},
		{NULL, -1, -1}
	};
	struct cfg_s cfg1[] = {
		{"main.admin", 1, 0},
		{"main.test", 2, 0},
		{"main.test2", 2, 0},
		{NULL, -1, -1}
	};
	test_pipefrom_version(cfg0, cfg1, -1);
	test_pipeto_version(cfg1, cfg0, 1);
}

static void
test_schema_concurrent(void)
{
	struct cfg_s cfg0[] = {
		{"main.admin", 3, 0},
		{"main.test", 2, 0},
		{NULL, -1, -1}
	};
	struct cfg_s cfg1[] = {
		{"main.admin", 2, 0},
		{"main.test", 3, 0},
		{NULL, -1, -1}
	};
	test_concurrent_version(cfg0, cfg1);
	test_concurrent_version(cfg1, cfg0);
}

//------------------------------------------------------------------------------

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);

	g_test_add_func("/sqliterepo/version/equal",
			test_equal);
	g_test_add_func("/sqliterepo/version/content/normal",
			test_diff_normal);
	g_test_add_func("/sqliterepo/version/content/big",
			test_diff_big);
	g_test_add_func("/sqliterepo/version/schema/equal",
			test_schema_equal);
	g_test_add_func("/sqliterepo/version/schema/diff",
			test_schema_diff);
	g_test_add_func("/sqliterepo/version/schema/concurrent",
			test_schema_concurrent);
	return g_test_run();
}

