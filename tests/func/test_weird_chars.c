/*
OpenIO SDS tests library
Copyright (C) 2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <glib.h>

#include <core/oio_sds.h>
#include <core/oio_core.h>

static const char *ns_name = NULL;
static const char *account = NULL;
static struct oio_sds_s *client = NULL;


static void
test_create_delete_container(gconstpointer user_data)
{
	const gchar *cname = user_data;

	struct oio_url_s *url = oio_url_empty();
	g_assert_nonnull(url);

	oio_url_set(url, OIOURL_NS, ns_name);
	oio_url_set(url, OIOURL_ACCOUNT, account);
	oio_url_set(url, OIOURL_USER, cname);

	const gchar *cname_parsed = oio_url_get(url, OIOURL_USER);
	g_assert_cmpstr(cname_parsed, ==, cname);

	struct oio_error_s *err = NULL;
	err = oio_sds_create(client, url);
	g_assert_no_error((GError*)err);

	// TODO(FVE): check container exists

	err = oio_sds_delete_container(client, url);
	g_assert_no_error((GError*)err);

	oio_url_clean(url);
}


static void
_add_creation_test(const char *name, const char *cname)
{
	gchar *cname_copy = g_strdup(cname);
	g_test_add_data_func_full(
			name,
			cname_copy,
			test_create_delete_container,
			g_free);
}

int
main(int argc, char **argv)
{
	OIO_TEST_INIT(argc, argv);

	oio_log_flags |= LOG_FLAG_PRETTYTIME;

	ns_name = g_getenv("OIO_NS");
	account = g_getenv("OIO_ACCOUNT");

	if (!ns_name) {
		g_printerr("Missing env var OIO_NS\n");
		return 1;
	} else if (!account) {
		g_printerr("Missing env var OIO_ACCOUNT\n");
		return 1;
	}

	struct oio_error_s *err = NULL;
	err = oio_sds_init(&client, ns_name);
	if (err) {
		g_printerr("Client init error: (%d) %s\n",
				oio_error_code(err), oio_error_message(err));
		oio_error_pfree(&err);
		return 2;
	}
	GRID_DEBUG("Client to [%s] ready", ns_name);

	_add_creation_test("/create/percent", "%");
	_add_creation_test("/create/percent_twenty_five", "%25");
	_add_creation_test("/create/percent_percent", "%%");

	_add_creation_test("/create/space", " ");
	_add_creation_test("/create/percent_twenty", "%20");

	_add_creation_test("/create/plus", "+");
	_add_creation_test("/create/percent_two_b", "%2B");

	_add_creation_test("/create/dollar", "$");
	_add_creation_test("/create/percent_twenty_four", "%24");

	int rc = g_test_run();

	oio_sds_pfree(&client);

	return rc;
}
