/*
OpenIO SDS client
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

int
main(int argc, char **argv)
{
	oio_log_to_stderr();
	oio_sds_default_autocreate = 1;
	for (int i=0; i<3 ;i++)
		oio_log_more ();

	prng = g_rand_new ();

	if (argc != 3) {
		g_printerr ("Usage: %s HCURL PATH\n", argv[0]);
		return 1;
	}

	gchar tmppath[1024], tmpblob[128] = "";
	const char *str_url = argv[1];
	const char *str_path = argv[2];
	struct hc_url_s *url;
	struct oio_sds_s *client = NULL;
	struct oio_error_s *err = NULL;
	int has = 0;

	g_snprintf (tmppath, sizeof(tmppath), "/tmp/test-roundtrip-%d-%lu-",
			getpid(), time(0));
	size_t tmplen = strlen(tmppath);
	_randomize_string (tmppath+tmplen, random_chars, MIN(16,sizeof(tmppath)-tmplen));
	_randomize_string (tmpblob, random_chars, sizeof(tmpblob));

	url = hc_url_init(str_url);
	if (!url) {
		g_printerr ("Invalid URL [%s]\n", str_url);
		return 2;
	}
	if (!hc_url_has_fq_path(url)) {
		g_printerr ("Partial URL [%s]: %s requires a NS (%s), an ACCOUNT (%s),"
				" an USER (%s) and a PATH (%s)\n", str_url, argv[0],
				hc_url_has (url, HCURL_NS)?"ok":"missing",
				hc_url_has (url, HCURL_ACCOUNT)?"ok":"missing",
				hc_url_has (url, HCURL_USER)?"ok":"missing",
				hc_url_has (url, HCURL_PATH)?"ok":"missing");
		return 3;
	}
	GRID_INFO("URL valid [%s]", hc_url_get (url, HCURL_WHOLE));

	/* Initiate a client */
	err = oio_sds_init (&client, hc_url_get(url, HCURL_NS));
	if (err) {
		g_printerr ("Client init error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 4;
	}
	GRID_INFO("Client ready to [%s]", hc_url_get (url, HCURL_NS));

	/* Check the presence of the targetd content */
	err = oio_sds_has (client, url, &has);
	if (err) {
		g_printerr ("Check error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 5;
	}
	if (has) {
		g_printerr ("File already present\n");
		return 6;
	}
	GRID_INFO("Content absent as expected");

	/* Ok, the content was absent so we can upload it */
	err = oio_sds_upload_from_file (client, url, str_path);
	if (err) {
		g_printerr ("Upload error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 7;
	}
	GRID_INFO("Content uploaded");

	/*the upload succeeded, so the presence check should succeed */
	has = 0;
	err = oio_sds_has (client, url, &has);
	if (err) {
		g_printerr ("Check error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 8;
	}
	if (!has) {
		g_printerr ("File not present\n");
		return 9;
	}
	GRID_INFO("Content present as expected");

	/* and it is also possible to download the file */
	err = oio_sds_download_to_file (client, url, tmppath);
	if (err) {
		g_printerr ("Download error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 10;
	}
	GRID_INFO("Content downloaded");

	/* and we let the container clean, we remove the blob in the container. */
	err = oio_sds_delete (client, url);
	if (err) {
		g_printerr ("Delete error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		return 11;
	}
	GRID_INFO("Content removed");

	g_remove (tmppath);
	hc_url_pclean (&url);
	oio_sds_pfree (&client);
	oio_error_pfree (&err);
	return 0;
}

