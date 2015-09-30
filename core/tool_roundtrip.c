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

static const char random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"-_,";

static GRand *prng = NULL;

static const char *
_randomize_string (char *d, const char *chars, size_t dlen)
{
	size_t chars_len = strlen(chars);
	for (size_t i=0; i<dlen-1 ;i++)
		*(d++) = chars[ g_rand_int_range (prng, 0, chars_len) ];
	*d = 0;
	return d;
}

static struct oio_error_s *
_roundtrip_common (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	gchar tmppath[1024];
	struct oio_error_s *err = NULL;
	int has = 0;

	g_snprintf (tmppath, sizeof(tmppath), "/tmp/test-roundtrip-%d-%lu-",
			getpid(), time(0));
	size_t tmplen = strlen(tmppath);
	_randomize_string (tmppath+tmplen, random_chars, MIN(16,sizeof(tmppath)-tmplen));

	GRID_INFO ("Roundtrip on local(%s) distant(%s)", tmppath,
			oio_url_get (url, OIOURL_WHOLE));

	/* Check the presence of the targetd content */
	err = oio_sds_has (client, url, &has);
	if (err) {
		g_printerr ("Check error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return err;
	}
	if (has) {
		g_printerr ("File already present\n");
		return err;
	}
	GRID_INFO("Content absent as expected");

	/* Ok, the content was absent so we can upload it */
	err = oio_sds_upload_from_file (client, url, path);
	if (err) {
		g_printerr ("Upload error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return err;
	}
	GRID_INFO("Content uploaded");

	/*the upload succeeded, so the presence check should succeed */
	has = 0;
	err = oio_sds_has (client, url, &has);
	if (err) {
		g_printerr ("Check error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return err;
	}
	if (!has) {
		g_printerr ("File not present\n");
		return err;
	}
	GRID_INFO("Content present as expected");

	/* and it is also possible to download the file */
	err = oio_sds_download_to_file (client, url, tmppath);
	if (err) {
		g_printerr ("Download error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return err;
	}
	GRID_INFO("Content downloaded to a file");

	/* downloads just a portion of the file */
	guint8 buf[1024];
	struct oio_sds_dl_dst_s dst = {
		.type = OIO_DL_DST_BUFFER,
		.data = {.buffer = {.ptr = buf, .length=1024}}
	};
	struct oio_sds_dl_src_s src = {
		.url = url,
		.ranges = NULL,
	};
	err = oio_sds_download (client, &src, &dst);
	if (err) {
		g_printerr ("Download error: (%d) %s\n", oio_error_code(err),
				oio_error_message (err));
		return err;
	}
	GRID_INFO("Content downloaded to a buffer");

	/* and we let the container clean, we remove the blob in the container. */
	err = oio_sds_delete (client, url);
	if (err) {
		g_printerr ("Delete error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return err;
	}
	GRID_INFO("Content removed");

	g_remove (tmppath);
	oio_error_pfree (&err);
	return NULL;
}

static struct oio_error_s *
_roundtrip_autocontainer (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	GError *err = NULL;

	/* get the fle's content */
	gchar *file_content = NULL;
	gsize file_length = 0;
	if (!g_file_get_contents (path, &file_content, &file_length, &err)) {
		g_printerr ("Checksum error: file error (%d) %s\n", err->code, err->message);
		return (struct oio_error_s*) err;
	}
	
	/* hash it with SHA1 */
	gsize sha1_len = g_checksum_type_get_length (G_CHECKSUM_SHA1);
	guint8 sha1[sha1_len];
	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA1);
	g_checksum_update (checksum, (guint8*)file_content, file_length);
	g_checksum_get_digest (checksum, sha1, &sha1_len);
	g_checksum_free (checksum);
	g_free (file_content);
	
	/* compute the autocontainer with the SHA1, consider only the first 17 bits */
	struct oio_str_autocontainer_config_s cfg = {
		.src_offset = 0, .src_size = 0,
		.dst_bits = 17,
	};
	char tmp[65];
	const char *auto_container = oio_str_autocontainer_hash (sha1, sha1_len, tmp, &cfg);
	
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

