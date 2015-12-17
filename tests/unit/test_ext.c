/*
OpenIO SDS metautils
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
#include <core/oiolog.h>
#include <core/oioext.h>
#include <metautils/lib/metautils.h>

static void
test_shuffle_array (void)
{
	void *tab[10];
	for (guint i=0; i<10 ;++i)
		tab[i] = NULL;
	for (gulong i=1; i<9 ;i++)
		tab[i] = (void*)i;
	oio_ext_array_shuffle (tab+1, 8);
	g_assert_null (tab[0]);
	g_assert_null (tab[9]);
}

static void
test_partition (void)
{
	gboolean _is_even (gconstpointer p) {
		return 0 != (((gulong)p) % 2);
	}

	void *tab[8];
	for (guint i=0; i<8 ;++i)
		tab[i] = NULL;
	for (gulong i=0; i<8 ;++i)
		tab[i] = (void*)i;

	/* tab = {0,1,2,3,4,5,6,7} */
	gsize pivot = oio_ext_array_partition (tab, 8, _is_even);
	/* tab = {1,3,5,7} :: {0,2,4,6} */

	g_assert (pivot == 4);
	for (guint i=0; i<pivot ;++i)
		g_assert_true (_is_even (tab[i]));
	for (guint i=pivot; i<8 ;++i)
		g_assert_false (_is_even (tab[i]));
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/ext/shuffle", test_shuffle_array);
	g_test_add_func("/core/ext/partition", test_partition);
	return g_test_run();
}

