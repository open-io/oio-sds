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
	for (int i=0; i<10 ;++i)
		tab[i] = NULL;
	for (long unsigned int i=0; i<8 ;i++)
		tab[i+1] = (void*)i;
	oio_ext_array_shuffle (tab+1, 8);
	g_assert_null (tab[0]);
	g_assert_null (tab[9]);
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/shuffle/array", test_shuffle_array);
	return g_test_run();
}

