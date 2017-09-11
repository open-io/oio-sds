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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <metautils/lib/metautils.h>
#include "test_addr.h"

static void
test_bad_connect_address(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		gboolean rc = metautils_url_valid_for_connect(url);
		URL_ASSERT(rc == FALSE);
	}
	test_on_urlv(bad_urls, test);
}

static void
test_good_connect_address(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		gboolean rc = metautils_url_valid_for_connect(url);
		URL_ASSERT(rc != FALSE);
	}
	test_on_urlv(good_urls, test);
}

#define SRV_NS "NAMESPACE"
#define SRV_TYPE "meta2"

#define TEST_IDGEN(URL) do { \
	struct service_info_s si = {}; \
	g_strlcpy(si.ns_name, SRV_NS, sizeof(si.ns_name)); \
	g_strlcpy(si.type, SRV_TYPE, sizeof(si.type)); \
	g_assert_true(grid_string_to_addrinfo(URL, &si.addr)); \
	si.score.value = si.score.timestamp = 1; \
	gchar *id = service_info_key(&si); \
	g_assert_nonnull(id); \
	g_assert_cmpstr(id, ==, SRV_NS "|" SRV_TYPE "|" URL); \
	g_free(id); \
} while (0)

static void
test_srvinfo_id(void)
{
	TEST_IDGEN("1.2.3.4:1");
	TEST_IDGEN("127.0.0.1:6000");
	TEST_IDGEN("254.254.254.254:60000");
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/addr/connect/ko", test_bad_connect_address);
	g_test_add_func("/metautils/addr/connect/ok", test_good_connect_address);
	g_test_add_func("/metautils/srvinfo/id", test_srvinfo_id);
	return g_test_run();
}

