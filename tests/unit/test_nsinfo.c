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

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>

static void
test_decode(namespace_info_t *ns0)
{
	for (int i=0; i<32 ;++i) {
		GError *err = NULL;
		GByteArray *encoded = namespace_info_marshall(ns0, &err);
		g_assert_no_error(err);
		g_assert_nonnull(encoded);

		namespace_info_t *ns1 = namespace_info_unmarshall(
				encoded->data, encoded->len, &err);
		g_assert_no_error(err);
		g_assert_nonnull(ns1);

		g_assert_cmpstr(ns0->name, ==, ns1->name);

		namespace_info_free(ns1);

		g_byte_array_free(encoded, TRUE);
	}
}

static void
test_codec(void)
{
	for (int i=0; i<32 ;++i) {
		namespace_info_t *ns0 = g_malloc0(sizeof(*ns0));
		namespace_info_init(ns0);
		g_strlcpy(ns0->name, "XxXxXx", sizeof(ns0->name));
		test_decode(ns0);
		namespace_info_free(ns0);
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/nsinfo/codec", test_codec);
	return g_test_run();
}
