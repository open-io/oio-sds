/*
OpenIO SDS metautils
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

#include "./metautils.h"

static void
test_transform(gchar* (*T) (const gchar*), const gchar *s0, const gchar *sN)
{
	gchar *s = T(s0);
	g_assert(0 == g_strcmp0(sN,s));
	g_free(s);
}

/* ------------------------------------------------------------------------- */

static void
test_reuse(void)
{
	gchar *s0 = g_strdup("");
	gchar *s1 = g_strdup("");
	oio_str_reuse(&s0, s1);
	g_assert(s0 == s1);
	g_free(s1);
}

static void
test_replace(void)
{
	gchar *s0 = g_strdup("");
	gchar *s1 = g_strdup("");
	oio_str_replace(&s0, s1);
	g_assert(0 == g_strcmp0(s0, s1));
	g_free(s0);
	g_free(s1);
}

static void
test_clean(void)
{
	gchar *s0 = g_strdup("");
	oio_str_clean(&s0);
	g_assert(NULL == s0);
}

static void
test_strlcpy_pns(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_strlcpy_physical_ns(s, s0, strlen(s0)+1);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "....", "");
	test_transform(_trans, "N", "N");
	test_transform(_trans, "N.P", "N");
}

static void
test_upper(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_str_upper(s);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "a", "A");
	test_transform(_trans, "A", "A");
	test_transform(_trans, "Aa", "AA");
}

static void
test_lower(void)
{
	gchar * _trans(const gchar *s0) {
		gchar *s = g_strdup(s0);
		metautils_str_lower(s);
		return s;
	}
	test_transform(_trans, "", "");
	test_transform(_trans, "a", "a");
	test_transform(_trans, "A", "a");
	test_transform(_trans, "Aa", "aa");
}

static void
test_prefix (void)
{
	g_assert (metautils_str_has_caseprefix ("X", "X"));
	g_assert (metautils_str_has_caseprefix ("X", "x"));
	g_assert (metautils_str_has_caseprefix ("Xa", "X"));
	g_assert (metautils_str_has_caseprefix ("Xa", "x"));

	g_assert (!metautils_str_has_caseprefix ("X", "Y"));
	g_assert (!metautils_str_has_caseprefix ("X", "y"));
	g_assert (!metautils_str_has_caseprefix ("Xa", "Y"));
	g_assert (!metautils_str_has_caseprefix ("Xa", "y"));

	g_assert (!metautils_str_has_caseprefix ("X", "Xa"));
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/str/reuse", test_reuse);
	g_test_add_func("/metautils/str/replace", test_replace);
	g_test_add_func("/metautils/str/clean", test_clean);
	g_test_add_func("/metautils/str/strlcpy_pns", test_strlcpy_pns);
	g_test_add_func("/metautils/str/upper", test_upper);
	g_test_add_func("/metautils/str/lower", test_lower);
	g_test_add_func("/metautils/str/prefix", test_prefix);
	return g_test_run();
}

