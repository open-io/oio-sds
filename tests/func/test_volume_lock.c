/*
OpenIO SDS functional tests
Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>

#include <metautils/lib/metautils.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.utils")

gchar *basedir = NULL;

static gchar * tmpdir(void) {
	gchar *path = g_strconcat(basedir, "/", "XXXXXX", NULL);
	gchar *out = g_mkdtemp_full(path, 0700);
	g_assert_nonnull(out);
	return out;
}

#define FAILING_CALL(tmp, ...) do { \
	if (g_test_subprocess()) { \
		volume_service_lock(tmp, ##__VA_ARGS__); \
	} else { \
		g_test_trap_subprocess (NULL, 0, 0); \
		g_test_trap_assert_failed (); \
	} \
} while (0)

static void
test_wrong_args (void)
{
	gchar *tmp = tmpdir();

	FAILING_CALL(NULL, "type0", "id0", "ns0");
	FAILING_CALL(tmp, NULL, "id0", "ns0");
	FAILING_CALL(tmp, "type0", NULL, "ns0");
	FAILING_CALL(tmp, "type0", "id0", NULL);

	g_assert_cmpint(0, ==, g_remove(tmp));
	g_free(tmp);
}

static void
test_lock_cycle (void)
{
	GError *err;
	gchar *tmp = tmpdir();

	err = volume_service_lock(tmp, "type0", "id0", "ns0");
	g_assert_no_error(err);

	/* the same service might also lock */
	for (int i=0; i<8 ;++i) {
		err = volume_service_lock(tmp, "type0", "id0", "ns0");
		g_assert_no_error(err);
	}

	/* Any varying parameter causes a fail */
	for (int i=0; i<8 ;++i) {
		err = volume_service_lock(tmp, "type1", "id0", "ns0");
		g_assert_error(err, GQ(), CODE_INTERNAL_ERROR);
		g_clear_error(&err);
		err = volume_service_lock(tmp, "type0", "id1", "ns0");
		g_assert_error(err, GQ(), CODE_INTERNAL_ERROR);
		g_clear_error(&err);
		err = volume_service_lock(tmp, "type0", "id0", "ns1");
		g_assert_error(err, GQ(), CODE_INTERNAL_ERROR);
		g_clear_error(&err);
	}

	g_assert_cmpint(0, ==, g_remove(tmp));
	g_free(tmp);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	basedir = g_strdup(g_getenv ("TEST_DIR"));
	if (!basedir)
		basedir = g_strdup(g_get_tmp_dir());
	if (!basedir)
		basedir = g_strdup("/tmp");

	g_test_add_func("/metautils/lock/args", test_wrong_args);
	g_test_add_func("/metautils/lock/cycle", test_lock_cycle);

	gint rc = g_test_run();
	g_free(basedir);
	basedir = NULL;
	return rc;
}


