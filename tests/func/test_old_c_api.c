/*
OpenIO SDS core library
Copyright (C) 2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_core.h>
#include <core/oio_sds.h>
#include <core/internals.h>

#include <core/client_variables.h>
#include <metautils/lib/common_variables.h>

#include <metautils/lib/metautils.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.core")
#include <glib.h>

static gchar *buffer_base = NULL;
static gsize buffer_length = 0;

#define _url_set_from_env(url,env_key,url_key) do { \
	g_assert_nonnull(env_key); \
	g_assert_nonnull(g_getenv(env_key)); \
	g_assert_nonnull(oio_url_set(url, url_key, g_getenv(env_key))); \
} while (0)

#define _assert_no_error(err) do { \
	if (err != NULL) { \
		g_printerr("ERROR (%d) %s\n", oio_error_code(err), oio_error_message(err)); \
		g_assert_null(err); \
	} \
} while (0)

static void
_url_set_random(struct oio_url_s *url, int url_key)
{
	gchar value[32];
	oio_str_randomize(value, sizeof(value), "0123456789ABCDEF");
	g_assert_nonnull(oio_url_set(url, url_key, value));
}

static struct oio_url_s *
_url_prepare(void)
{
	struct oio_url_s *url = oio_url_empty();
	g_assert_nonnull(url);
	_url_set_from_env(url, "OIO_NS", OIOURL_NS);
	_url_set_random(url, OIOURL_ACCOUNT);
	_url_set_random(url, OIOURL_USER);
	_url_set_random(url, OIOURL_PATH);
	g_printerr("\n%s\n", oio_url_get(url, OIOURL_WHOLE));
	g_printerr("( export OIO_NS=%s OIO_ACCOUNT=%s ; openio object locate %s %s )\n",
			oio_url_get(url, OIOURL_NS),
			oio_url_get(url, OIOURL_ACCOUNT),
			oio_url_get(url, OIOURL_USER),
			oio_url_get(url, OIOURL_PATH));
	return url;
}

static void
_content_check(struct oio_sds_s *sds, struct oio_url_s *url)
{
	volatile gboolean last_seen = FALSE;
	void _on_metachunk (void *cb_data UNUSED,
		unsigned int seq , size_t offset UNUSED, size_t length) {
		g_printerr("seq = %u metachunk_size = %ld min = %ld max = %ld\n",
				seq, length, oio_chunk_size_minimum, oio_chunk_size_maximum);
		g_assert_false(last_seen);
		if ((gint64)length == 7) {
			last_seen = TRUE;
		} else {
			g_assert((gint64)length >= oio_chunk_size_minimum);
			g_assert((gint64)length <= oio_chunk_size_maximum);
		}
	}
	struct oio_error_s *err = oio_sds_show_content(
			sds, url, NULL, NULL, _on_metachunk, NULL);
	_assert_no_error(err);
}

/* ------------------------------------------------------------------------- */

/* We simulate trash code 
struct oio_sds_ul_dst_1704_s
{
	struct oio_url_s *url;
	unsigned int autocreate : 1;
	unsigned int append : 1;
	unsigned int partial : 1;
	size_t out_size;
	const char *content_id;
	const char * const * properties;
	int meta_pos;
	size_t offset;
};
*/

static void
test_upload(size_t chunk_size)
{
	const guint64 magic = g_random_int();
	struct oio_url_s *url = NULL;
	struct oio_error_s *err = NULL;
	struct oio_sds_s *sds = NULL;

	guint64 pre = magic;
	struct oio_sds_ul_dst_s dst = {};
	guint64 post = magic;

	/* perform the upload */
	url = _url_prepare();

	err = oio_sds_init(&sds, oio_url_get(url, OIOURL_NS));
	_assert_no_error(err);
	g_assert_nonnull(sds);

	oio_sds_configure(sds, OIOSDS_CFG_FLAG_CHUNKSIZE,
			&oio_ns_chunk_size, sizeof(oio_ns_chunk_size));

	g_assert_nonnull(buffer_base);
	g_assert(buffer_length > 0);

	dst.url = url;
	dst.autocreate = 1;
	dst.chunk_size = chunk_size;
	err = oio_sds_upload_from_buffer(sds, &dst, buffer_base, buffer_length);
	_assert_no_error(err);
	g_assert(pre == magic);
	g_assert(post == magic);

	/* Check the metachunk sizes that must be bounded */
	_content_check(sds, url);

	/* Cleanup */
	oio_sds_pfree(&sds);
	g_assert_null(sds);
}

static void
test_upload_1704(void)
{
	test_upload(0);
	test_upload(oio_chunk_size_minimum - 1);
	test_upload(oio_chunk_size_minimum);
	test_upload(oio_chunk_size_maximum);
	test_upload(oio_chunk_size_maximum + 1);
	test_upload((size_t)-1);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	oio_ns_chunk_size = 1027;
	oio_chunk_size_minimum = 1024 * 1024;
	oio_chunk_size_maximum = 2 * 1024 * 1024;
	buffer_length = 10 * 1024 * 1024 + 7;
	buffer_base = g_malloc(buffer_length);
	/* metachunks must be <oio_chunk_size_minimum> because the NS
	 * configuration is smaller than the minimum */

	g_test_add_func("/core/sds/old/upload/17.04", test_upload_1704);

	return g_test_run();
}
