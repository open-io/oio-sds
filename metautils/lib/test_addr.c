#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "metautils_loggers.h"
#include "metautils_resolv.h"
#include "metautils_bits.h"
#include "common_main.h"
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

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/addr/bad_connect",
			test_bad_connect_address);
	g_test_add_func("/metautils/gridd_client/good_address",
			test_good_connect_address);
	return g_test_run();
}

