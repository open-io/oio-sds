/*
OpenIO SDS core test
Copyright (C) 2016 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <core/oioext.h>
#include <core/oiostr.h>

#define ASSERT_EQFLOAT(V0,V1) do { \
	gdouble _v0 = (V0), _v1 = (V1); \
	/* Using '<=' and '>=' instead of '==' avoids gcc complaining about
	 * unsafe comparisons. */ \
	g_assert_cmpfloat(_v0, <=, _v1); \
	g_assert_cmpfloat(_v0, >=, _v1); \
} while (0)

#define PREFIX "/x/y/z/"

static void test_ok (void) {
	g_assert_cmpfloat(0.0, <=, oio_sys_cpu_idle());
	g_assert_cmpfloat(0.0, <=, oio_sys_io_idle("/"));
	g_assert_cmpfloat(0.0, <=, oio_sys_space_idle("/"));
}

static void test_ko (void) {
	gchar notfound[64 + sizeof(PREFIX)] = PREFIX;
	oio_str_randomize(
			notfound + (sizeof(PREFIX) - 1),
			sizeof(notfound) - (sizeof(PREFIX) - 1),
			"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ");
	ASSERT_EQFLOAT(0.01, oio_sys_io_idle(notfound));
	ASSERT_EQFLOAT(0.0, oio_sys_space_idle(notfound));
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/stat/ok", test_ok);
	g_test_add_func("/core/stat/ko", test_ko);
	return g_test_run();
}
