/*
OpenIO SDS core library
Copyright (C) 2015-2017 OpenIO, as part of OpenIO Software Defined Storage

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

#include <string.h>
#include <stdlib.h>
#include <glib.h>

#include <core/oio_sds.h>
#include <core/oioext.h>
#include <core/oiostr.h>
#include <core/oiolog.h>

#include "internals.h"

#define GERROR(E) ((GError*)(E))

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

static int _upload (int argc, char **argv, gboolean append, int replace) {
	if (argc < 1) {
		g_printerr("Missing size\n");
		return 1;
	}

	const gsize size = g_ascii_strtoll(argv[0], NULL, 10);
	struct oio_sds_s *sds = NULL;
	struct oio_error_s *err = NULL;
	struct oio_url_s *url = _load_url_from_env();

	if (!oio_url_has_fq_path(url)) {
		g_printerr("Partial URL\n");
		oio_url_pclean(&url);
		return 1;
	}

	GRID_WARN("%s %"G_GSIZE_FORMAT, __FUNCTION__, size);
	err = oio_sds_init(&sds, oio_url_get(url, OIOURL_NS));
	g_assert_no_error(GERROR(err));

	gsize sent = 0;
	size_t _gen (void *i UNUSED, unsigned char *p, size_t s) {
		gsize remaining = size - sent;
		if (remaining <= 0)
			return OIO_SDS_UL__DONE;
		remaining = MIN(s,remaining);
		oio_buf_randomize(p, remaining);
		sent = sent + remaining;
		return remaining;
	}

	gchar *content_id = NULL;
	struct oio_sds_ul_src_s src = OIO_SDS_UPLOAD_SRC_INIT;
	src.type = OIO_UL_SRC_HOOK_SEQUENTIAL;
	src.data.hook.cb = _gen;
	src.data.hook.ctx = NULL;
	src.data.hook.size = size;
	struct oio_sds_ul_dst_s dst = OIO_SDS_UPLOAD_DST_INIT;
	dst.url = url;
	dst.autocreate = 1;
	dst.out_size = 0;
	dst.append = BOOL(append);
	dst.partial = BOOL(replace >= 0);
	dst.meta_pos = replace;

	if (dst.append || dst.partial) {
		void _cb(void *i UNUSED, enum oio_sds_content_key_e k, const char *v) {
			if (k == OIO_SDS_CONTENT_ID)
				content_id = g_strdup(v);
		}
		err = oio_sds_show_content (sds, url, NULL, _cb, NULL, NULL);
		g_assert_no_error(GERROR(err));
		dst.content_id = content_id;
	}

	err = oio_sds_upload(sds, &src, &dst);
	g_assert_no_error(GERROR(err));
	oio_str_clean (&content_id);
	oio_sds_pfree (&sds);
	oio_url_pclean(&url);
	return 0;
}

static int _put (int argc, char **argv) {
	return _upload(argc, argv, FALSE, -1);
}

static int _append (int argc, char **argv) {
	return _upload(argc, argv, TRUE, -1);
}

static int _replace (int argc, char **argv) {
	if (argc < 1) {
		g_printerr("Missing meta-position\n");
		return 1;
	}
	return _upload(argc-1, argv+1, TRUE, atoi(argv[0]));
}

int main(int argc, char **argv) {
	HC_TEST_INIT(argc,argv);
	g_assert (OIO_SDS_VERSION == oio_sds_version());

	if (argc < 2) {
		g_printerr("Missing argument\n");
		return 1;
	}

	struct {
		const char *word;
		int (*hook) (int, char**);
	} commands[] = {
		{"put", _put},
		{"append", _append},
		{"replace", _replace},
		{NULL, NULL}
	};
	for (int i=0; commands[i].word ;++i) {
		if (!g_ascii_strcasecmp(commands[i].word, argv[1]))
			return commands[i].hook(argc-2, argv+2);
	}

	g_printerr("Command not found\n");
	return 1;
}
