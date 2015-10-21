/*
OpenIO SDS cache
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <metautils/lib/lrutree.h>
#include <core/oiolog.h>
#include <cache/cache.h>

static void
test_found (struct oio_cache_s *c, const char *k, const char *v)
{
	gchar *value = NULL;
	enum oio_cache_status_e rc = oio_cache_get (c, k, &value);
	g_assert_cmpint (rc, ==, OIO_CACHE_OK);
	g_assert_nonnull (value);
	g_assert_cmpstr (value, ==, v);
	g_free (value);
}

static void
test_not_found (struct oio_cache_s *c, const char *k)
{
	enum oio_cache_status_e rc;
	gchar *value = NULL;

	rc = oio_cache_get (c, k, &value);
	g_assert_null (value);
	g_assert_cmpint (rc, ==, OIO_CACHE_NOTFOUND);
}

static void
test_cache_cycle (struct oio_cache_s *c)
{
	const char *k = "NOTFOUND";
	const char *v = "plop";

	g_assert_nonnull (c);
	test_not_found (c, k);

	enum oio_cache_status_e rc = oio_cache_put (c, k, v);
	if (rc == OIO_CACHE_OK) {
		test_found (c, k, v);
		rc = oio_cache_del (c, k);
		g_assert_cmpint (rc, ==, OIO_CACHE_OK);
	} else {
		g_assert_cmpint (rc, ==, OIO_CACHE_DISCONNECTED);
	}

	test_not_found (c, k);
}

static void
test_cache_cycle_noop (void)
{
	struct oio_cache_s *c = oio_cache_make_NOOP ();
	test_cache_cycle (c);
	oio_cache_destroy (c);
}

static void
test_cache_cycle_lru (void)
{
	struct lru_tree_s *lru = lru_tree_create (
			(GCompareFunc)g_strcmp0, g_free, g_free, 0);
	g_assert_nonnull (lru);

	struct oio_cache_s *c = oio_cache_make_LRU (lru);

	test_cache_cycle (c);
	oio_cache_destroy (c);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);
	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(oio_log_stderr, NULL);

	g_test_add_func("/cache/cycle/noop", test_cache_cycle_noop);
	g_test_add_func("/cache/cycle/lru", test_cache_cycle_lru);
	return g_test_run();
}

