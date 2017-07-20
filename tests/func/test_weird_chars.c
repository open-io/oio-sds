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
#include <string.h>

#include <glib.h>

#include <core/oio_sds.h>
#include <core/oio_core.h>

static const char *ns_name = NULL;
static const char *account = NULL;
static struct oio_sds_s *client = NULL;
static const char *source_file = "/etc/fstab";

const char *weirdos = "!#$&'()*+,/:;=?@[]\r\n\"%-.<>\\^_`{}|~";

static void
test_create_upload_delete_destroy(struct oio_url_s *url, const gchar *obj)
{
	g_assert_nonnull(url);
	GRID_DEBUG("Testing URL [%s]", oio_url_get(url, OIOURL_WHOLE));

	struct oio_error_s *err = NULL;
	err = oio_sds_create(client, url);
	g_assert_no_error((GError*)err);

	struct oio_sds_ul_dst_s dst = {0};
	dst.url = oio_url_dup(url);

	if (obj) {
		oio_url_set(dst.url, OIOURL_PATH, obj);
		g_assert_true(oio_url_check(dst.url, NULL, NULL));
    }
	err = oio_sds_upload_from_file(client, &dst, source_file, 0, -1);
	g_assert_no_error((GError*)err);

	err = oio_sds_delete(client, dst.url);
	g_assert_no_error((GError*)err);
	oio_url_clean(dst.url);

	err = oio_sds_delete_container(client, url);
	g_assert_no_error((GError*)err);
}

static void
test_create_upload_delete_destroy_cname(gconstpointer user_data)
{
	const gchar *cname = user_data;

	struct oio_url_s *url = oio_url_empty();
	g_assert_nonnull(url);

	oio_url_set(url, OIOURL_NS, ns_name);
	oio_url_set(url, OIOURL_ACCOUNT, account);
	oio_url_set(url, OIOURL_USER, cname);

	const gchar *cname_parsed = oio_url_get(url, OIOURL_USER);
	g_assert_cmpstr(cname_parsed, ==, cname);

	test_create_upload_delete_destroy(url, "object");

	oio_url_clean(url);
}

static void
_add_cname_test(const char *name, const char *cname)
{
	g_test_add_data_func_full(
			name,
			g_strdup(cname),
			test_create_upload_delete_destroy_cname,
			g_free);
}

static void
test_create_upload_delete_destroy_objname(gconstpointer user_data)
{
	const char *obj_name = user_data;

	struct oio_url_s *url = oio_url_empty();
	g_assert_nonnull(url);

	oio_url_set(url, OIOURL_NS, ns_name);
	oio_url_set(url, OIOURL_ACCOUNT, account);
	oio_url_set(url, OIOURL_USER, "container");
	oio_url_set(url, OIOURL_PATH, obj_name);
	g_assert_true(oio_url_check(url, ns_name, NULL));

	const gchar *obj_name_parsed = oio_url_get(url, OIOURL_PATH);
	g_assert_cmpstr(obj_name_parsed, ==, obj_name);

	test_create_upload_delete_destroy(url, NULL);

	oio_url_clean(url);
}

static void
_add_object_test(const char *name, const char *obj_name)
{
	g_test_add_data_func_full(
			name,
			g_strdup(obj_name),
			test_create_upload_delete_destroy_objname,
			g_free);
}

int
main(int argc, char **argv)
{
	OIO_TEST_INIT(argc, argv);

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

	char test_name[32] = {0}, data[2] = {0};
	for (const char *cur = weirdos; cur && *cur; cur++) {
		data[0] = *cur;
		g_snprintf(test_name, sizeof(test_name),
				"/cname/%ld", (long)(cur-weirdos));
		_add_cname_test(test_name, data);

		memset(test_name, 0, sizeof(test_name));
		g_snprintf(test_name, sizeof(test_name),
				"/obj/%ld", (long)(cur-weirdos));
		_add_object_test(test_name, data);
	}

	int rc = g_test_run();

	oio_sds_pfree(&client);

	return rc;
}
