/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <metautils/lib/metautils.h>

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
	void test(const gchar *url) {
		GByteArray *req;
		struct gridd_client_s *client;
		GError *err;

		req = _generate_request();
		client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert(err == NULL);

		err = gridd_client_connect_url(client, url);
		g_assert(err != NULL);
		g_clear_error (&err);

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
		struct gridd_client_s *client;
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
		struct gridd_client_s *client;
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
		struct gridd_client_s *client;
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
		g_assert (err != NULL);
		g_clear_error (&err);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	test(NULL);
	test_on_urlv(bad_urls, test);
}

static void
test_down_peer(void)
{
	gchar url_down[STRLEN_ADDRINFO] = "127.0.0.1:0";
	GError *err = NULL;

	/* bind a service to a random port */
	struct sockaddr_storage ss = {};
	socklen_t ss_len = sizeof(ss);
	gsize sz = sizeof(ss);
	int rc, fd;

    fd = sock_build_for_url(url_down, &err, &ss, &sz);
	g_assert_no_error(err);
	g_assert_cmpint(fd, >=, 0);
	rc = bind(fd, (struct sockaddr*)&ss, sz);
	g_assert_cmpint(rc, ==, 0);
	rc = listen(fd, 8192);
	g_assert_cmpint(rc, ==, 0);

	rc = getsockname(fd, (struct sockaddr*)&ss, &ss_len);
	g_assert_cmpint(rc, ==, 0);
	rc = grid_sockaddr_to_string((struct sockaddr*)&ss, url_down, sizeof(url_down));
	g_assert_cmpint(rc, >, 0);

	void test_ok(void) {
		GByteArray *req = _generate_request();
		struct gridd_client_s *client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert_no_error(err);
		err = gridd_client_connect_url(client, url_down);
		g_assert_no_error(err);

		const gboolean started = gridd_client_start(client);
		g_assert(started);
		g_assert_no_error(gridd_client_error(client));

		g_byte_array_unref(req);
		gridd_client_free(client);
	}
	void test_ko(void) {
		GByteArray *req = _generate_request();
		struct gridd_client_s *client = gridd_client_create_empty();
		g_assert(client != NULL);

		err = gridd_client_request(client, req, NULL, NULL);
		g_assert_no_error(err);
		err = gridd_client_connect_url(client, url_down);
		g_assert_no_error(err);

		const gboolean started = gridd_client_start(client);
		g_assert(!started);
		g_assert_error(gridd_client_error(client), g_quark_from_static_string("oio.utils"), CODE_AVOIDED);

		g_byte_array_unref(req);
		gridd_client_free(client);
	}

	gchar *peerv[] = {NULL, NULL};

	/* First attempt that must succeed, no filtering has been set */
	oio_var_value_one("client.down_cache.avoid", "false");
	gridd_client_learn_peers_down(NULL);
	gridd_client_learn_peers_down((const char * const *) peerv);
	test_ok();

	/* Second batch of attempts that must succeed, filtering set but no URL */
	oio_var_value_one("client.down_cache.avoid", "true");
	gridd_client_learn_peers_down(NULL);
	test_ok();
	gridd_client_learn_peers_down((const char * const *) peerv);
	test_ok();

	/* second attempt that must succeed, a peer down has been announced but
	 * the feature is not activated. */
	oio_var_value_one("client.down_cache.avoid", "false");
	peerv[0] = url_down;
	gridd_client_learn_peers_down((const char * const *) peerv);
	test_ok();

	/* Now we turn the feature on and the test must fail */
	oio_var_value_one("client.down_cache.avoid", "true");
	test_ko();

	metautils_pclose(&fd);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/gridd_client/down_peer",
			test_down_peer);
	g_test_add_func("/metautils/gridd_client/bad_address",
			test_bad_addresses);
	g_test_add_func("/metautils/gridd_client/good_address",
			test_good_addresses);
	g_test_add_func("/metautils/gridd_client/ignored_connect_fail_start",
			test_failed_start_on_ignored_connect_error);
	g_test_add_func("/metautils/gridd_client/ignored_connect_loop",
			test_loop_on_ignored_start_error);
	return g_test_run();
}

