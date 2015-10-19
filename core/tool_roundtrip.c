/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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
#include <unistd.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "oio_core.h"
#include "oio_sds.h"

#define MAYBERETURN(E,T) do { \
	if (E) { \
		g_printerr ("%s: (%d) %s\n", (T), \
				oio_error_code((struct oio_error_s*)(E)), \
				oio_error_message((struct oio_error_s*)(E))); \
		return err; \
	} \
} while (0)

static const char random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789";

static const char hex_chars[] = "0123456789ABCDEF";

static GRand *prng = NULL;

static int
_on_item (void *ctx, const struct oio_sds_list_item_s *item)
{
	(void) ctx;
	g_print ("Listed item %s, size %"G_GSIZE_FORMAT" version %"G_GSIZE_FORMAT"\n",
			item->name, item->size, item->version);
	return 0;
}

struct file_info_s
{
	guint8 h[32];
	gsize hs;
	gsize fs;
};

static GError *
_checksum_file (const char *path, struct file_info_s *fi)
{
	GError *err = NULL;
	gchar *file_content = NULL;
	g_file_get_contents (path, &file_content, &fi->fs, &err);
	if (err) return err;

	fi->hs = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (guint8*)file_content, fi->fs);
	g_checksum_get_digest (checksum, fi->h, &fi->hs);
	g_checksum_free (checksum);
	g_free (file_content);

	return NULL;
}

static void
_append_random_chars (gchar *d, const char *chars, guint n)
{
	size_t len = strlen (chars);
	gchar *p = d + strlen(d);
	for (guint i=0; i<n ;i++)
		*(p++) = chars [g_rand_int_range (prng, 0, len)];
	*p = '\0';
}

static struct oio_error_s *
_roundtrip_common (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	struct file_info_s fi, fi0;
	struct oio_error_s *err = NULL;
	int has = 0;

	err = (struct oio_error_s*) _checksum_file (path, &fi0);
	MAYBERETURN(err, "Checksum error (original): ");

	gchar tmppath[256] = "";
	g_snprintf (tmppath, sizeof(tmppath), "/tmp/test-roundtrip-%d-%lu-", getpid(), time(0));
	_append_random_chars (tmppath, random_chars, 16);
	gchar content_id[65] = "";
	_append_random_chars (content_id, hex_chars, 64);

	GRID_INFO ("Roundtrip on local(%s) distant(%s) content_id(%s)", tmppath,
			oio_url_get (url, OIOURL_WHOLE), content_id);

	/* Check the content is not preset yet */
	err = oio_sds_has (client, url, &has);
	if (!err && has) err = (struct oio_error_s*) NEWERROR(0,"content already present");
	MAYBERETURN(err, "Check error");
	GRID_INFO("Content absent as expected");

	/* Then upload it */
	struct oio_sds_ul_src_s ul_src = {
		.type = OIO_UL_SRC_FILE,
		.data = { .file = { .path = path, .offset = 0, .size = 0, }, },
	};
	struct oio_sds_ul_dst_s ul_dst = {
		.url = url, .autocreate = 1, .out_size = 0, .content_id = content_id,
	};
	err = oio_sds_upload (client, &ul_src, &ul_dst);
	MAYBERETURN(err, "Upload error");
	GRID_INFO("Content uploaded");

	/* Check it is now present */
	has = 0;
	err = oio_sds_has (client, url, &has);
	if (!err && !has) err = (struct oio_error_s*) NEWERROR(0, "content not found");
	MAYBERETURN(err, "Check error");
	GRID_INFO("Content present as expected");

	/* Get it to validate the content is accessible */
	err = oio_sds_download_to_file (client, url, tmppath);
	MAYBERETURN(err, "Download error");
	GRID_INFO("Content downloaded to a file");

	/* Validate the original and the copy match */
	err = (struct oio_error_s*) _checksum_file (tmppath, &fi);
	MAYBERETURN(err, "Checksum error (copy): ");
	if (fi.fs != fi0.fs)
		MAYBERETURN(NEWERROR(0, "Copy sizes mismatch"), "Validation error");
	if (0 != memcmp(fi.h, fi0.h, fi.hs))
		MAYBERETURN(NEWERROR(0, "Copy hash mismatch"), "Validation error");
	GRID_INFO("The original file and its copy match");

	/* Get it an other way in a buffer. */
	guint8 buf[1024];
	struct oio_sds_dl_dst_s dl_dst = {
		.type = OIO_DL_DST_BUFFER,
		.data = {.buffer = {.ptr = buf, .length=1024}}
	};
	struct oio_sds_dl_src_s dl_src = {
		.url = url,
		.ranges = NULL,
	};
	err = oio_sds_download (client, &dl_src, &dl_dst);
	MAYBERETURN(err, "Download error");
	GRID_INFO("Content downloaded to a buffer");

	/* link the container */
	struct oio_url_s *url1 = oio_url_dup (url);
	oio_url_set (url1, OIOURL_PATH, tmppath);
	err = oio_sds_link (client, url1, content_id);
	oio_url_pclean (&url1);
	MAYBERETURN(err, "Link error: ");

	/* List the container, the content must appear */
	struct oio_sds_list_param_s list_in = {
		.url = url,
		.prefix = NULL, .marker = NULL, .end = NULL, .delimiter = 0,
		.flag_allversions = 0, .flag_nodeleted = 0,
	};
	struct oio_sds_list_listener_s list_out = {
		.ctx = NULL,
		.on_item = _on_item, .on_prefix = NULL, .on_bound = NULL,
	};
	err = oio_sds_list (client, &list_in, &list_out);
	MAYBERETURN(err, "List error");

	/* Remove the content from the content */
	err = oio_sds_delete (client, url);
	MAYBERETURN(err, "Delete error");
	GRID_INFO("Content removed");

	/* Check the content is not preset anymore */
	has = 0;
	err = oio_sds_has (client, url, &has);
	if (!err && has) err = (struct oio_error_s*) NEWERROR(0, "content still present");
	MAYBERETURN(err, "Check error");
	GRID_INFO("Content absent as expected");

	g_remove (tmppath);
	oio_error_pfree (&err);
	return NULL;
}

static struct oio_error_s *
_roundtrip_autocontainer (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	struct file_info_s fi;
	GError *err = _checksum_file (path, &fi);

	/* compute the autocontainer with the SHA1, consider only the first 17 bits */
	struct oio_str_autocontainer_config_s cfg = {
		.src_offset = 0, .src_size = 0,
		.dst_bits = 17,
	};
	char tmp[65];
	const char *auto_container = oio_str_autocontainer_hash (fi.h, fi.hs, tmp, &cfg);

	/* build a new URL with the computed container name */
	struct oio_url_s *url_auto = oio_url_dup (url);
	oio_url_set (url_auto, OIOURL_USER, auto_container);
	err = (GError*) _roundtrip_common (client, url_auto, path);
	oio_url_pclean (&url_auto);

	return (struct oio_error_s*) err;
}

int
main(int argc, char **argv)
{
	oio_log_to_stderr();
	oio_sds_default_autocreate = 1;
	for (int i=0; i<4 ;i++)
		oio_log_more ();

	prng = g_rand_new ();

	if (argc != 2) {
		g_printerr ("Usage: %s PATH\n", argv[0]);
		return 1;
	}

	const char *path = argv[1];

	struct oio_url_s *url = oio_url_empty ();
	oio_url_set (url, OIOURL_NS, g_getenv("OIO_NS"));
	oio_url_set (url, OIOURL_ACCOUNT, g_getenv("OIO_ACCOUNT"));
	oio_url_set (url, OIOURL_USER, g_getenv("OIO_USER"));
	oio_url_set (url, OIOURL_PATH, g_getenv("OIO_PATH"));

	if (!oio_url_has_fq_path(url)) {
		g_printerr ("Partial URL [%s]: requires a NS (%s), an ACCOUNT (%s),"
				" an USER (%s) and a PATH (%s)\n",
				oio_url_get (url, OIOURL_WHOLE),
				oio_url_has (url, OIOURL_NS)?"ok":"missing",
				oio_url_has (url, OIOURL_ACCOUNT)?"ok":"missing",
				oio_url_has (url, OIOURL_USER)?"ok":"missing",
				oio_url_has (url, OIOURL_PATH)?"ok":"missing");
		return 3;
	}
	GRID_INFO("URL valid [%s]", oio_url_get (url, OIOURL_WHOLE));

	struct oio_sds_s *client = NULL;
	struct oio_error_s *err = NULL;

	/* Initiate a client */
	err = oio_sds_init (&client, oio_url_get(url, OIOURL_NS));
	if (err) {
		g_printerr ("Client init error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 4;
	}
	GRID_INFO("Client ready to [%s]", oio_url_get (url, OIOURL_NS));

	err = _roundtrip_common (client, url, path);
	if (!err)
		err = _roundtrip_autocontainer (client, url, path);

	int rc = err != NULL;
	oio_error_pfree (&err);
	oio_sds_pfree (&client);
	oio_url_pclean (&url);
	return rc;
}

