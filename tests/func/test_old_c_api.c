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
test_upload_2cs(gint64 explicit_chunk_size, gint64 config_chunk_size)
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

	if (config_chunk_size > 0) {
		oio_sds_configure(sds, OIOSDS_CFG_FLAG_CHUNKSIZE,
				&config_chunk_size, sizeof(config_chunk_size));
	}

	g_assert_nonnull(buffer_base);
	g_assert(buffer_length > 0);

	dst.url = url;
	dst.autocreate = 1;
	dst.chunk_size = explicit_chunk_size >= 0 ? explicit_chunk_size : 0;
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
test_upload_3cs(gint64 explicit_chunk_size,
				gint64 global_chunk_size,
				gint64 config_chunk_size)
{
	g_printerr("\n### chunk_size:"
			   " explicit=%" G_GINT64_FORMAT
			   " global=%" G_GINT64_FORMAT
			   " config=%"G_GINT64_FORMAT "\n",
			  explicit_chunk_size, global_chunk_size, config_chunk_size);
	const gint64 old_ns_chunk_size = oio_ns_chunk_size;
	if (global_chunk_size >= 0)
		oio_ns_chunk_size = global_chunk_size;
	test_upload_2cs(explicit_chunk_size, config_chunk_size);
	oio_ns_chunk_size = old_ns_chunk_size;
}

struct _test_context_s {
	gint64 explicit, global, config;
	gboolean thorough;
};

static void
_fixture_1704(gconstpointer data)
{
	const struct _test_context_s *ctx = (struct _test_context_s*) data;
	if (ctx->thorough && !g_test_thorough()) {
		g_test_skip("Use '-m thorough' to activate");
	} else {
		test_upload_3cs(ctx->explicit, ctx->global, ctx->config);
	}
}

static void
_add_tests(gint64 *tab, size_t tablen, gboolean thorough)
{
	for (size_t i0=0; i0 < tablen ;i0++) {
		for (size_t i1=0; i1 < tablen ;i1++) {
			for (size_t i2=0; i2 < tablen ;i2++) {
				struct _test_context_s ctx = {
					tab[i0], tab[i1], tab[i2],
					thorough
				};
				gchar *name = g_strdup_printf(
						"/core/sds/old/upload/17.04/%d/%ld/%ld/%ld",
						ctx.thorough, ctx.explicit, ctx.global, ctx.config);
				g_test_add_data_func_full(
						name, g_memdup(&ctx, sizeof(ctx)), _fixture_1704, g_free);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	/* metachunks must be either <oio_chunk_size_minimum> or
	 * <oio_chunk_size_maximum> because the NS configuration is either
	 * smaller or greater than the minimum */
	oio_sds_client_patch_metachunk_size = FALSE;
	oio_chunk_size_minimum = 1024 * 1024;
	oio_chunk_size_maximum = 2 * 1024 * 1024;
	buffer_length = 10 * 1024 * 1024 + 7;
	buffer_base = g_malloc(buffer_length);

	/* Add fixtures for the 17.04 */
	gint64 _quick[] = { 0, 64};
	gint64 _slow[] = {
		-1, 0, 64, 1027,
		oio_chunk_size_minimum-1,
		oio_chunk_size_maximum+1};
	_add_tests(_quick, sizeof(_quick) / sizeof(gint64), FALSE);
	_add_tests(_slow, sizeof(_slow) / sizeof(gint64), TRUE);

	return g_test_run();
}
