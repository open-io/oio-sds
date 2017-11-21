/*
OpenIO SDS metautils
Copyright (C) 2017 OpenIO, original work as part of OpenIO SDS

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

static void
test_create_destroy(void)
{
	for (guint i=0; i<512 ;i++) {
		MESSAGE msg;
		msg= metautils_message_create_named("jlkjsdqljqslkxcjqlkcxkjq", 1);
		metautils_message_destroy(msg);
	}
}

static void
test_set_get(void)
{
	gchar tmp[1024];

	MESSAGE msg = metautils_message_create_named("mklmkmlk", 0);
	metautils_message_add_field_struint(msg, "xxx", 1);

	gboolean rc = metautils_message_extract_string_noerror(msg, "xxx", tmp, sizeof(tmp));
	g_assert_true(rc);

	GError *e = metautils_message_extract_string(msg, "xxx", tmp, sizeof(tmp));
	g_assert_no_error(e);
	g_assert_cmpstr(tmp, ==, "1");

	gchar *s = metautils_message_extract_string_copy(msg, "xxx");
	g_assert_nonnull(s);
	g_assert_cmpstr(s, ==, "1");
	g_free(s);

	gint64 i64 = 0;
	e = metautils_message_extract_strint64(msg, "xxx", &i64);
	g_assert_no_error(e);
	g_assert_cmpint(i64, ==, 1);

	metautils_message_destroy(msg);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/message/create_destroy", test_create_destroy);
	g_test_add_func("/metautils/message/set_get", test_set_get);
	return g_test_run();
}
