/*
OpenIO SDS unit tests
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <core/oio_core.h>
#include <core/internals.h>

/* zero means always skip, aka never do */
static void test_zero(void) {
	volatile gint period = 0;
	VARIABLE_PERIOD_DECLARE();
	for (guint i=0; i<8 ;++i) {
		g_assert_true(VARIABLE_PERIOD_SKIP(period));
	}
	g_assert_cmpuint(tick, ==, 0);
}

/* negative means zero */
static void test_negative(void) {
	volatile gint period = -1;
	VARIABLE_PERIOD_DECLARE();
	for (guint i=0; i<8 ;++i) {
		g_assert_true(VARIABLE_PERIOD_SKIP(period));
	}
	g_assert_cmpuint(tick, ==, 0);
}

static void test_positive(void) {
	volatile gint period = 3;
	VARIABLE_PERIOD_DECLARE();
	for (guint i=0; i<8 ;++i) {
		g_assert_false(VARIABLE_PERIOD_SKIP(period));
		g_assert_true(VARIABLE_PERIOD_SKIP(period));
		g_assert_true(VARIABLE_PERIOD_SKIP(period));
	}
	g_assert_cmpuint(tick, ==, 24);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/core/variable_period/zero", test_zero);
	g_test_add_func("/core/variable_period/positive", test_positive);
	g_test_add_func("/core/variable_period/negative", test_negative);
	return g_test_run();
}

