#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.url"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "metautils_loggers.h"
#include "hc_url.h"
#include "common_main.h"
#include "test_addr.h"
#include "gridd_client.h"
#include "gridd_client_ext.h"

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
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert(err == NULL);

		err = gridd_client_connect_url(client, url);
		g_assert(err != NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

static void
test_good_addresses(void)
{
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert(err == NULL);

		err = gridd_client_connect_url(client, url);
		g_assert(err == NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test_on_urlv(good_urls, test);
}

static void
test_failed_start_on_ignored_connect_error(void)
{
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert(err == NULL);

		err = gridd_client_connect_url(client, url);
		g_assert(err != NULL);
		g_clear_error(&err); // Ignore!

		gboolean started = gridd_client_start(client);
		g_assert(!started);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

static void
test_loop_on_ignored_start_error(void)
{
	void test(const gchar *url) {
		GByteArray *req;
		struct client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert(err == NULL);

		err = gridd_client_connect_url(client, url);
		g_assert(err != NULL);
		g_clear_error(&err);

		gboolean started = gridd_client_start(client);
		g_assert(!started);

		err = gridd_client_loop(client);
		g_assert(err == NULL);

		err = gridd_client_error(client);
		g_assert(err != NULL);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
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

