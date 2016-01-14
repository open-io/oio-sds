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

#include <glib.h>
#include <core/oio_core.h>
#include <metautils/lib/lrutree.h>

#include "tests/common/test_cache_abstract.c"

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

static void
test_cache_cycle_multilayer (void)
{
	struct lru_tree_s *lru = lru_tree_create (
	        (GCompareFunc)g_strcmp0, g_free, g_free, 0);
	g_assert_nonnull (lru);

	struct oio_cache_s *c1 = oio_cache_make_LRU (lru);
	struct oio_cache_s *c2 = oio_cache_make_NOOP ();

	struct oio_cache_s *c = oio_cache_make_multilayer_var (c1,c2,NULL);

	test_cache_cycle (c);
	oio_cache_destroy (c);
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/cache/cycle/noop", test_cache_cycle_noop);
	g_test_add_func("/cache/cycle/lru", test_cache_cycle_lru);
	g_test_add_func("/cache/cycle/multilayer", test_cache_cycle_multilayer);
	return g_test_run();
}

