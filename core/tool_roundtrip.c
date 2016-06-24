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

#include "internals.h"
#include "oio_core.h"
#include "oio_sds.h"

#define NOERROR(E) g_assert_no_error((GError*)(E))

static const char random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789";

static const char hex_chars[] = "0123456789ABCDEF";

static int
_on_item (void *ctx UNUSED, const struct oio_sds_list_item_s *item)
{
	GRID_DEBUG ("Listed item %s, size %"G_GSIZE_FORMAT" version %"G_GSIZE_FORMAT"\n",
			item->name, item->size, item->version);
	return 0;
}

struct file_info_s
{
	guint8 h[32];
	gsize hs;
	gsize fs;
};

#define FILE_INFO_INIT {"",0,0}

static void
_checksum_file (const char *path, struct file_info_s *fi)
{
	GError *err = NULL;
	gchar *file_content = NULL;
	g_file_get_contents (path, &file_content, &fi->fs, &err);
	g_assert_no_error (err);

	fi->hs = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (guint8*)file_content, fi->fs);
	g_checksum_get_digest (checksum, fi->h, &fi->hs);
	g_checksum_free (checksum);
	g_free (file_content);
}

#define CHECK_ABSENT(client,url) do { \
	int has = FALSE; \
	err = oio_sds_has (client, url, &has); \
	if (!err && has) err = (struct oio_error_s*) NEWERROR(0,"content already present"); \
	NOERROR(err); \
	GRID_INFO("Content absent as expected"); \
} while (0)

#define CHECK_PRESENT(ckient,url) do { \
	int has = 0; \
	err = oio_sds_has (client, url, &has); \
	if (!err && !has) \
		err = (struct oio_error_s*) NEWERROR(0, "content not found"); \
	NOERROR(err); \
	GRID_INFO("Content present as expected"); \
} while (0)

static void
_roundtrip_tail (struct oio_sds_s *client, struct oio_url_s *url,
		struct file_info_s *fi0,
		const char * content_id, const char * const * properties)
{
	guint8 buf[1024];
	gchar tmppath[256];
	struct oio_error_s *err = NULL;
	struct file_info_s fi;
	struct oio_url_s *url1;

	g_snprintf (tmppath, sizeof(tmppath),
			"/tmp/test-roundtrip-%d-%"G_GINT64_FORMAT"-",
			getpid(), oio_ext_real_time());
	oio_str_randomize (tmppath+strlen(tmppath), 17, random_chars);
	url1 = oio_url_dup (url);
	oio_url_set (url1, OIOURL_PATH, tmppath);

	GRID_INFO ("Roundtrip on local(%s) distant(%s) content_id(%s)", tmppath,
			oio_url_get (url, OIOURL_WHOLE), content_id);

	CHECK_PRESENT(client,url);

	/* Get it to validate the content is accessible */
	err = oio_sds_download_to_file (client, url, tmppath);
	NOERROR(err);
	GRID_INFO("Content downloaded to a file");

	/* Validate the original and the copy match */
	_checksum_file (tmppath, &fi);

	if (fi.fs != fi0->fs)
		NOERROR(NEWERROR(0, "Copy sizes mismatch (expected %zu, got %zu)", fi0->fs, fi.fs));

	if (0 != memcmp(fi.h, fi0->h, fi.hs))
		NOERROR(NEWERROR(0, "Copy hash mismatch"));

	GRID_INFO("The original file and its copy match");

	/* Get it an other way in a buffer. */
	do {
		struct oio_sds_dl_dst_s dl_dst = {
			.type = OIO_DL_DST_BUFFER,
			.data = {.buffer = {.ptr = buf, .length = sizeof(buf)}}
		};
		struct oio_sds_dl_src_s dl_src = {
			.url = url,
			.ranges = NULL,
		};
		err = oio_sds_download (client, &dl_src, &dl_dst);
	} while (0);
	NOERROR(err);
	GRID_INFO("Content downloaded to a buffer");

	/* link the container */
	err = oio_sds_link (client, url1, content_id);
	NOERROR(err);

	/* List the container, the content must appear */
	do {
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
	} while (0);
	NOERROR(err);

	/* list the properties on the content */
	GPtrArray *val = g_ptr_array_new();
	void save_elements(void *ptrarray, const char *k, const char*v) {
		GPtrArray *array = (GPtrArray *) ptrarray;
		g_ptr_array_add(array,g_strdup(k));
		g_ptr_array_add(array,g_strdup(v));
	}
	err = oio_sds_get_content_properties(client, url, save_elements, val);
	NOERROR(err);
	if (val->len != 4)
		NOERROR(NEWERROR(0, "Wrong properties number"));

	g_ptr_array_add(val, NULL);
	gchar **elts = (gchar **) g_ptr_array_free(val, FALSE);
	if (GRID_TRACE2_ENABLED()) {
		for (gchar **prop=elts; *prop && *(prop+1) ;prop+=2)
			GRID_TRACE2("Property got: [%s] -> [%s]", *prop, *(prop+1));
		for (const char * const * prop=properties; *prop && *(prop+1) ;prop+=2)
			GRID_TRACE2("Property expected: [%s] -> [%s]", *prop, *(prop+1));
	}
	gboolean t00 = !g_strcmp0(elts [0], properties[0]) && !g_strcmp0(elts [1], properties[1]);
	gboolean t01 = !g_strcmp0(elts [2], properties[2]) && !g_strcmp0(elts [3], properties[3]);
	gboolean t10 = !g_strcmp0(elts [0], properties[2]) && !g_strcmp0(elts [1], properties[3]);
	gboolean t11 = !g_strcmp0(elts [2], properties[0]) && !g_strcmp0(elts [3], properties[1]);
	if (!(t00 && t01) && !(t10 && t11))
		NOERROR(NEWERROR(0, "Wrong properties values"));
	g_strfreev(elts);

	/* get details on the content */
	gsize max_offset = 0, max_size = 0;
	void _on_metachunk (void *i UNUSED, guint seq, gsize offt, gsize len) {
		GRID_TRACE2("metachunk: %u, %"G_GSIZE_FORMAT" %"G_GSIZE_FORMAT,
				seq, offt, len);
		max_offset = MAX(max_offset, offt);
		max_size = MAX(max_size, offt+len);
	}
	void _on_property (void *i UNUSED, const char *k, const char *v) {
		GRID_TRACE2("property: '%s' -> '%s'", k, v);
	}
	err = oio_sds_show_content (client, url, NULL, _on_metachunk, _on_property);
	NOERROR(err);

	/* if there is more than one metachunk, voluntarily ask a range crossing
	 * the borders of a metachunk */
	if (max_offset > 0 && max_size > 0 && max_offset != max_size) {
		GRID_DEBUG("max_offset=%"G_GSIZE_FORMAT" max_size=%"G_GSIZE_FORMAT,
				max_offset, max_size);
		struct oio_sds_dl_range_s range0 = {
			.offset = max_offset - 1,
			.size = 2,
		};
		struct oio_sds_dl_range_s range1 = {
			.offset = max_offset + 1,
			.size = 2,
		};
		struct oio_sds_dl_range_s *rangev[3] = {NULL, NULL, NULL};
		struct oio_sds_dl_src_s dl_src = { .url = url, .ranges = rangev, };

		/* first attempt with a buffer voluntarily too small */
		rangev[0] = &range0;
		rangev[1] = NULL;
		struct oio_sds_dl_dst_s dl_dst = {
			.type = OIO_DL_DST_BUFFER,
			.data = {.buffer = {.ptr = buf, .length=1}}
		};
		err = oio_sds_download (client, &dl_src, &dl_dst);
		if (!err)
			NOERROR(SYSERR("Unexpected success: DL of a range in a buffer too small"));
		g_clear_error ((GError**)&err);

		/* second attempt with a buffer exactly the expected size */
		rangev[0] = &range0;
		rangev[1] = NULL;
		dl_dst.data.buffer.length = 2;
		err = oio_sds_download (client, &dl_src, &dl_dst);
		NOERROR(err);

		/* now with 2 contiguous ranges */
		rangev[0] = &range0;
		rangev[1] = &range1;
		dl_dst.data.buffer.length = 4;
		err = oio_sds_download (client, &dl_src, &dl_dst);
		NOERROR(err);

		/* now with 2 non-contiguous ranges */
		rangev[0] = &range1;
		rangev[1] = &range0;
		dl_dst.data.buffer.length = 4;
		err = oio_sds_download (client, &dl_src, &dl_dst);
		NOERROR(err);

		/* try to download the end of a metachunk */
		rangev[0] = &range0;
		rangev[1] = NULL;
		dl_dst.data.buffer.length = 2;
		range0.offset = max_offset - 1;
		range0.size = 1;
		err = oio_sds_download (client, &dl_src, &dl_dst);
		NOERROR(err);

		/* try to download the start of a metachunk */
		dl_dst.data.buffer.length = 2;
		range0.offset = max_offset;
		range0.size = 1;
		err = oio_sds_download (client, &dl_src, &dl_dst);
		NOERROR(err);
	}

	/* Remove the roginal content from the container */
	err = oio_sds_delete (client, url);
	NOERROR(err);

	/* Check the content is not present anymore */
	CHECK_ABSENT(client,url);

	/* Remove the linked content from the container */
	err = oio_sds_delete (client, url1);
	NOERROR(err);

	/* Check the content is not present anymore */
	CHECK_ABSENT(client,url1);

	/* TODO deleting twice SHOULD fail. */
	/* TODO setting properties on the content MUST fail */
	/* TODO getting properties from the content MUST fail */

	oio_url_pclean(&url1);
	g_remove (tmppath);
}

/* Upload the content at once then check the content is OK */
static void
_roundtrip_with_file_upload (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path, const char * const * properties)
{
	g_printerr("\n*** %s ***\n", __FUNCTION__);

	struct oio_error_s *err = NULL;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7,15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	struct file_info_s fi0 = FILE_INFO_INIT;
	_checksum_file (path, &fi0);

	CHECK_ABSENT(client,url);

	GRID_INFO("Uploading from local file [%s] with id [%s]", path, content_id);
	struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
	ul_dst.url = url;
	ul_dst.autocreate = 1;
	ul_dst.append = 0;
	ul_dst.out_size = 0;
	ul_dst.content_id = content_id;
	ul_dst.properties = properties;
	err = oio_sds_upload_from_file (client, &ul_dst, path, 0, 0);
	NOERROR(err);
	GRID_INFO("Content uploaded");

	_roundtrip_tail (client, url, &fi0, content_id, (const char * const *)properties);

	oio_error_pfree (&err);
}

/* Perform subsequent appends then check the content is OK */
static void
_roundtrip_with_append (struct oio_sds_s *client, struct oio_url_s *url,
		const char * const * properties)
{
	g_printerr("\n*** %s ***\n", __FUNCTION__);

	struct oio_error_s *err = NULL;
	struct file_info_s fi0 = FILE_INFO_INIT ;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7,15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	CHECK_ABSENT(client,url);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	fi0.hs = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	const int max =  oio_ext_rand_int_range(7,17);
	GRID_INFO("Uploading from [%u] blocks with id [%s]", max, content_id);
	for (int i=0; i<max ;++i) {
		const size_t bufsize = oio_ext_rand_int_range(15,129);
		guint8 buf [bufsize];
		oio_buf_randomize(buf, bufsize);

		fi0.fs += bufsize;
		g_checksum_update (checksum, buf, bufsize);

		struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
		ul_dst.url = url;
		ul_dst.autocreate = 1;
		ul_dst.append = 1;
		ul_dst.out_size = 0;
		ul_dst.content_id = content_id;
		ul_dst.properties = properties;
		err = oio_sds_upload_from_buffer (client, &ul_dst, buf, sizeof(buf));
		NOERROR(err);
	}
	GRID_INFO("Content uploaded");

	g_checksum_get_digest (checksum, fi0.h, &fi0.hs);
	g_checksum_free (checksum);
	_roundtrip_tail (client, url, &fi0, content_id, (const char * const *)properties);

	oio_error_pfree (&err);
}

/* Now the case is set, check with a content uploaded at once, then built
 * with subsequent append */
static void
_roundtrip_common (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	gchar prop1 [7]="", prop2 [37]="";
	gchar *properties [5] = {prop1, prop1, prop2, prop2, NULL};

	oio_str_randomize (prop1, sizeof(prop1), random_chars);
	oio_str_randomize (prop2, sizeof(prop2), random_chars);

	_roundtrip_with_file_upload (client, url, path, (const char * const *)properties);
	_roundtrip_with_append (client, url, (const char * const *) properties);
}

/* check with all the Case manglings */
static void
_roundtrip_header_case (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	oio_header_case = OIO_HDRCASE_NONE;
	_roundtrip_common (client, url, path);
	oio_header_case = OIO_HDRCASE_LOW;
	_roundtrip_common (client, url, path);
	oio_header_case = OIO_HDRCASE_1CAP;
	_roundtrip_common (client, url, path);
	oio_header_case = OIO_HDRCASE_RANDOM;
	_roundtrip_common (client, url, path);
}

static void
_roundtrip_autocontainer (struct oio_sds_s *client, struct oio_url_s *url,
		const char *path)
{
	struct file_info_s fi;
	_checksum_file (path, &fi);

	/* compute the autocontainer with the SHA1, consider only the first 17 bits */
	char tmp[65];
	struct oio_str_autocontainer_config_s cfg = {
		.src_offset = 0, .src_size = 0, .dst_bits = 17,
	};
	const char *auto_container = oio_str_autocontainer_hash (fi.h, fi.hs, tmp, &cfg);

	/* build a new URL with the computed container name */
	struct oio_url_s *url_auto = oio_url_dup (url);
	oio_url_set (url_auto, OIOURL_USER, auto_container);
	_roundtrip_header_case (client, url_auto, path);
	oio_url_pclean (&url_auto);
}

int
main(int argc, char **argv)
{
	oio_log_to_stderr();
	oio_sds_default_autocreate = 1;
	oio_log_init_level_from_env("G_DEBUG_LEVEL");

	if (argc != 2) {
		g_printerr ("Usage: %s PATH\n", argv[0]);
		return 1;
	}

	const char *path = argv[1];

	struct oio_url_s *url = oio_url_empty ();
	oio_url_set (url, OIOURL_NS, g_getenv("OIO_NS"));
	oio_url_set (url, OIOURL_ACCOUNT, g_getenv("OIO_ACCOUNT"));
	oio_url_set (url, OIOURL_USER, g_getenv("OIO_USER"));
	oio_url_set (url, OIOURL_TYPE, g_getenv("OIO_TYPE"));
	oio_url_set (url, OIOURL_PATH, g_getenv("OIO_PATH"));

	if (!oio_url_has_fq_path(url)) {
		g_printerr ("Partial URL [%s]: requires a NS (%s), an ACCOUNT (%s),"
				" an USER (%s) and a PATH (%s) (+ optional TYPE: %s)\n",
				oio_url_get (url, OIOURL_WHOLE),
				oio_url_has (url, OIOURL_NS)?"ok":"missing",
				oio_url_has (url, OIOURL_ACCOUNT)?"ok":"missing",
				oio_url_has (url, OIOURL_USER)?"ok":"missing",
				oio_url_has (url, OIOURL_PATH)?"ok":"missing",
				oio_url_has (url, OIOURL_TYPE)?"ok":"missing");
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

	_roundtrip_header_case (client, url, path);
	_roundtrip_autocontainer (client, url, path);

	oio_error_pfree (&err);
	oio_sds_pfree (&client);
	oio_url_pclean (&url);
	return 0;
}

