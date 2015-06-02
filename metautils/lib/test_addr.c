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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "metautils.h"
#include "test_addr.h"

static void
test_codec (void)
{
	gint rc;
	struct addr_info_s addr;
	const char *original = "127.0.0.1:6000";
	char resolved[128];
	rc = l4_address_init_with_url (&addr, original, NULL);
	g_assert (BOOL(rc));

	GSList *singleton = g_slist_prepend (NULL, &addr);
	GByteArray *gba = addr_info_marshall_gba (singleton, NULL);
	g_assert (gba != NULL);
	GSList *decoded = NULL;
	gsize len = gba->len;
	rc = addr_info_unmarshall (&decoded, gba->data, &len, NULL);
	g_assert (BOOL(rc));
	g_assert (decoded != NULL);

	for (GSList *l=decoded; l ;l=l->next) {
		grid_addrinfo_to_string (l->data, resolved, sizeof(resolved));
		g_print("> %s\n", resolved);
	}

	g_slist_free_full (decoded, addr_info_clean);
	g_slist_free (singleton);
	g_byte_array_free (gba, TRUE);
}

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

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/addr/codec", test_codec);
	g_test_add_func("/metautils/addr/bad_connect", test_bad_connect_address);
	g_test_add_func("/metautils/gridd_client/good_address", test_good_connect_address);
	return g_test_run();
}

