#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "metautils_loggers.h"
#include "hc_url.h"
#include "gridd_client.h"
#include "common_main.h"
#include "test_addr.h"

static GByteArray *
_generate_request(void)
{
	static guint8 c = 0;
	GByteArray *encoded = g_byte_array_new();
	encoded = g_byte_array_append(encoded, &c, 1);
	return encoded;
}

static void
test_bad_addresses(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		URL_ASSERT(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		URL_ASSERT(err == NULL);

		err = gridd_client_connect_url(client, url);
		URL_ASSERT(err != NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

static void
test_good_addresses(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		URL_ASSERT(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		URL_ASSERT(err == NULL);

		err = gridd_client_connect_url(client, url);
		URL_ASSERT(err == NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test_on_urlv(good_urls, test);
}

static void
test_failed_start_on_ignored_connect_error(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		URL_ASSERT(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		URL_ASSERT(err == NULL);

		err = gridd_client_connect_url(client, url);
		URL_ASSERT(err != NULL);
		g_clear_error(&err); // Ignore!

		gboolean started = gridd_client_start(client);
		URL_ASSERT(!started);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

static void
test_loop_on_ignored_start_error(void)
{
	static const gchar *pProc = __FUNCTION__;
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		URL_ASSERT(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		URL_ASSERT(err == NULL);

		err = gridd_client_connect_url(client, url);
		URL_ASSERT(err != NULL);
		g_clear_error(&err);

		gboolean started = gridd_client_start(client);
		URL_ASSERT(!started);

		err = gridd_client_loop(client);
		URL_ASSERT(err == NULL);

		err = gridd_client_error(client);
		URL_ASSERT(err != NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

int
main(int argc, char **argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_test_init (&argc, &argv, NULL);
	g_test_add_func("/metautils/gridd_client/bad_address",
			test_bad_addresses);
	g_test_add_func("/metautils/gridd_client/good_address",
			test_good_addresses);
	g_test_add_func("/metautils/gridd_client/ignored_connect/fail_start",
			test_failed_start_on_ignored_connect_error);
	g_test_add_func("/metautils/gridd_client/ignored_connect/fail_start",
			test_loop_on_ignored_start_error);
	return g_test_run();
}

