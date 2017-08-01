/*
OpenIO SDS core library
Copyright (C) 2017 OpenIO, as part of OpenIO Software Defined Storage

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

#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <glib.h>

#include <core/oiocfg.h>
#include <core/oioext.h>
#include <core/oiostr.h>
#include <core/oio_sds.h>

/**
 * One configuration entry is always mandatory for any client: the URL of the
 * oio-proxy (that manages only metadata). Currently (and this is subject to
 * change soon), the client sometimes needs a side daemon that simplifies the
 * management of erasure-coded data.
 */
static void _preconfigure(const char *ns, const char *proxy, const char *ecd) {
	assert(ns != NULL);
	assert(proxy != NULL);

	GString *cfg = g_string_new("");
	g_string_printf(cfg, "[%s]\n", ns);
	g_string_append_printf(cfg, "proxy=%s\n", proxy);
	if (ecd)
		g_string_append_printf(cfg, "ecd=%s\n", ecd);

	GString *path = g_string_new("");
	g_string_printf(path, "%s/plop-XXXXXX", g_get_tmp_dir());

	int fd = g_mkstemp_full(path->str, O_RDWR, 0600);
	assert(fd >= 0);
	int written = write(fd, cfg->str, cfg->len);
	g_assert_cmpint(written, ==, cfg->len);

	oio_cfg_set_handle(oio_cfg_cache_create_fragment(path->str));

	unlink(path->str);
	close(fd), fd = -1;

	g_string_free(cfg, TRUE);
	g_string_free(path, TRUE);
}

static void _upload(struct oio_sds_s *sds, struct oio_url_s *url) {
	gsize size = oio_ext_rand_int_range(1024, 1024*1024);
	gsize sent = 0;

	/* generate random bytes */
	size_t _gen (void *i, unsigned char *p, size_t s) {
		(void) i;
		gsize remaining = size - sent;
		if (remaining <= 0)
			return OIO_SDS_UL__DONE;
		remaining = MIN(s,remaining);
		oio_buf_randomize(p, remaining);
		sent = sent + remaining;
		return remaining;
	}

	struct oio_sds_ul_src_s src = OIO_SDS_UPLOAD_SRC_INIT;
	src.type = OIO_UL_SRC_HOOK_SEQUENTIAL;
	src.data.hook.cb = _gen;
	src.data.hook.ctx = NULL;
	src.data.hook.size = size;
	struct oio_sds_ul_dst_s dst = OIO_SDS_UPLOAD_DST_INIT;
	dst.url = url;
	dst.autocreate = 1;
	dst.out_size = 0;
	dst.append = 0;
	dst.partial = 0;
	dst.meta_pos = 0;

	struct oio_error_s *err = oio_sds_upload(sds, &src, &dst);
	if (err != NULL) {
		g_printerr("upload() failed: (%d) %s", oio_error_code(err), oio_error_message(err));
		g_assert(err == NULL);
	}
}

#define FIELD(K,F) do { \
	const char *v = g_getenv(K); \
	if (v) oio_url_set(url,(F),v); \
} while (0)

static struct oio_url_s * _load_url_from_env (void) {
	struct oio_url_s *url = oio_url_empty();
	FIELD("OIO_NS", OIOURL_NS);
	FIELD("OIO_ACCOUNT", OIOURL_ACCOUNT);
	FIELD("OIO_USER", OIOURL_USER);
	FIELD("OIO_PATH", OIOURL_PATH);
	return url;
}

int main(int argc, char **argv) {
	(void) argc, (void) argv;
	struct oio_url_s *url = _load_url_from_env();

	struct oio_error_s *err;
	struct oio_sds_s *sds = NULL;

	_preconfigure(oio_url_get(url, OIOURL_NS),
			g_getenv("OIO_PROXY"), g_getenv("OIO_ECD"));

	err = oio_sds_init (&sds, oio_url_get(url, OIOURL_NS));
	assert(err == NULL);
	assert(sds != NULL);

	_upload(sds, url);

	oio_sds_pfree (&sds);
	oio_url_pclean(&url);
	return 0;
}
