/*
OpenIO SDS core library
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_sds.h>
#include <core/oio_core.h>
#include <metautils/lib/storage_policy.h>
#include <core/client_variables.h>

#include "internals.h"

#define NOERROR(E) g_assert_no_error((GError*)(E))

static const char random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789";

static const char hex_chars[] = "0123456789ABCDEF";

static const char *source_path = NULL;

struct oio_sds_s *client = NULL;

struct oio_url_s *url = NULL;

typedef void (*test_func_f) (const char * const *);

struct test_data_s
{
	enum oio_header_case_e header_case;
	test_func_f func;
};

static int
_on_item (void *ctx UNUSED, const struct oio_sds_list_item_s *item)
{
	GRID_DEBUG ("Listed item %s, size %"G_GSIZE_FORMAT" version %"G_GSIZE_FORMAT,
			item->name, item->size, item->version);
	const char * const * props = item->properties;
	if (!props)
		return 0;
	while (*props) {
		GRID_DEBUG("Listed item %s: %s=%s", item->name, *props, *(props+1));
		props += 2;
	}
	return 0;
}

struct file_info_s
{
	guint8 h[32];
	gsize hs;
	gsize fs;
};

#define FILE_INFO_INIT {"",0,0}

#define GET(RealSize) \
do { \
	/* ensure the buffer has the expected real size */ \
	buffer = g_realloc (buffer, RealSize); \
	g_assert_nonnull (buffer); \
	memset(buffer, 0, RealSize); \
	/* down and check the size of the result */ \
	struct oio_sds_dl_dst_s dst = {0}; \
	dst.type = OIO_DL_DST_BUFFER; \
	dst.data.buffer.ptr = buffer; \
	dst.data.buffer.length = RealSize; \
	struct oio_sds_dl_src_s src = {0}; \
	src.url = url_random; \
	src.ranges = NULL; \
	err = oio_sds_download (client, &src, &dst); \
	g_assert_no_error((GError*)err); \
	g_assert_cmpuint(dst.out_size, ==, size); \
	/* Check the hash of the downloaded content */ \
	gchar *post_hash = \
		g_compute_checksum_for_data(G_CHECKSUM_MD5, buffer, dst.out_size); \
	g_assert_nonnull(post_hash); \
	oio_str_upper(post_hash); \
	g_assert_cmpstr(pre_hash, ==, post_hash); \
	oio_str_clean (&post_hash); \
	if (GRID_TRACE2_ENABLED()) { /* Dump the downloaded content into a file */ \
		FILE *out = fopen("/tmp/post", "w"); \
		g_assert_nonnull(out); \
		size_t w = fwrite(buffer, dst.out_size, 1, out); \
		g_assert_cmpuint(w, ==, 1); \
		fclose(out); \
	} \
} while (0)

static void
putget (const gint64 size)
{
	struct oio_error_s *err = NULL;

	struct oio_url_s *url_random = oio_url_dup(url);
	gchar path[32];
	oio_str_randomize(path, oio_ext_rand_int_range(7,32), random_chars);
	oio_url_set (url_random, OIOURL_PATH, path);

	/* generate a buffer to work in. First we fill it of random bytes */
	guint8 *buffer = g_malloc(size);
	g_assert_nonnull (buffer);
	oio_buf_randomize (buffer, size);
	gchar *pre_hash =
		g_compute_checksum_for_data (G_CHECKSUM_MD5, buffer, size);
	g_assert_nonnull (pre_hash);
	oio_str_upper(pre_hash);
	if (GRID_TRACE2_ENABLED()) {
		FILE *out = fopen("/tmp/pre", "w");
		size_t w = fwrite(buffer, size, 1, out);
		fflush(out);
		fclose(out);
		g_assert_cmpuint(w, ==, 1);
	}

	/* Uploads the content */
	do {
		struct oio_sds_ul_dst_s dst = OIO_SDS_UPLOAD_DST_INIT;
		dst.url = url_random;
		dst.autocreate = 1;
		err = oio_sds_upload_from_buffer (client, &dst, buffer, size);
		g_assert_no_error((GError*)err);
	} while (0);

	/* check the hash and size known by OIO */
	void _cb (void *i UNUSED, enum oio_sds_content_key_e k, const char *v) {
		if (k == OIO_SDS_CONTENT_HASH)
			g_assert_cmpstr(pre_hash, ==, v);
		else if (k == OIO_SDS_CONTENT_SIZE) {
			gint64 oio_size = g_ascii_strtoll(v, NULL, 10);
			g_assert_cmpint(size, ==, oio_size);
		}
	}
	err = oio_sds_show_content (client, url_random, NULL, _cb, NULL, NULL);
	g_assert_no_error((GError*)err);

	/* download the file with a buffer too large */
	GET(size+1);
	GET(size);

	oio_pfree0 (&buffer, NULL);
	oio_url_pclean (&url_random);
	oio_str_clean (&pre_hash);
}

static void
putget_all_sizes (void)
{
	const gchar *v = g_getenv("OIO_CHUNK_SIZE");
	if (!v) {
		g_test_skip("No chunk size configured");
		return;
	}
	gint64 chunksize = g_ascii_strtoll(v, NULL, 10);
	if (chunksize > 10*1024*1024) {
		g_test_skip("chunk size too big");
		return;
	}
	g_assert(chunksize != 0);
	g_assert(chunksize != G_MAXINT64);
	g_assert(chunksize != G_MININT64);

	for (gsize i=1; i<7 ;++i) {
		putget ((i*chunksize)-1);
		putget ((i*chunksize));
		putget ((i*chunksize)+1);
	}
}

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
} while (0)

#define CHECK_PRESENT(client,url) do { \
	int has = 0; \
	err = oio_sds_has (client, url, &has); \
	if (!err && !has) \
		err = (struct oio_error_s*) NEWERROR(0, "content not found"); \
	NOERROR(err); \
} while (0)

static void
_roundtrip_tail (struct file_info_s *fi0, const char * content_id,
		const char * const * properties)
{
	guint8 buf[1024];
	gchar tmppath[256];
	struct oio_error_s *err = NULL;
	struct file_info_s fi;

	g_snprintf (tmppath, sizeof(tmppath),
			"/tmp/test-roundtrip-%d-%"G_GINT64_FORMAT"-",
			getpid(), oio_ext_real_time());
	oio_str_randomize (tmppath+strlen(tmppath), 17, random_chars);

	GRID_DEBUG ("Roundtrip on local(%s) distant(%s) content_id(%s)", tmppath,
			oio_url_get (url, OIOURL_WHOLE), content_id);

	CHECK_PRESENT(client,url);

	/* Get it to validate the content is accessible */
	err = oio_sds_download_to_file (client, url, tmppath);
	NOERROR(err);

	/* Validate the original and the copy match */
	_checksum_file (tmppath, &fi);
	if (NULL != fi0 && fi.fs != fi0->fs)
		NOERROR(NEWERROR(0, "Copy sizes mismatch (expected %zu, got %zu)", fi0->fs, fi.fs));

	if (NULL != fi0 && 0 != memcmp(fi.h, fi0->h, fi.hs))
		NOERROR(NEWERROR(0, "Copy hash mismatch"));

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

	/* List the container, the content must appear */
	do {
		struct oio_sds_list_param_s list_in = {
			.url = url,
			.prefix = NULL, .marker = NULL, .end = NULL, .delimiter = 0,
			.flag_allversions = 0, .flag_nodeleted = 0, .flag_properties = 1,
		};
		struct oio_sds_list_listener_s list_out = {
			.ctx = NULL,
			.on_item = _on_item, .on_prefix = NULL, .on_bound = NULL,
		};
		err = oio_sds_list (client, &list_in, &list_out);
	} while (0);
	NOERROR(err);

	/* list the properties on the content */
	GPtrArray *actual_props = g_ptr_array_new();
	void save_elements(void *u UNUSED, const char *k, const char *v) {
		g_ptr_array_add(actual_props, g_strdup(k));
		g_ptr_array_add(actual_props, g_strdup(v));
	}
	err = oio_sds_get_content_properties(client, url, save_elements, NULL);
	NOERROR(err);
	(void) properties;
	g_assert_cmpuint(actual_props->len, ==, oio_strv_length(properties));
	g_ptr_array_set_free_func(actual_props, g_free);
	g_ptr_array_free(actual_props, TRUE);

	/* get details on the content */
	gsize max_offset = 0, max_size = 0;
	void _on_metachunk (void *i UNUSED, guint seq UNUSED, gsize offt, gsize len) {
		GRID_DEBUG("metachunk: %u, %"G_GSIZE_FORMAT" %"G_GSIZE_FORMAT,
				seq, offt, len);
		max_offset = MAX(max_offset, offt);
		max_size = MAX(max_size, offt+len);
	}
	void _on_property (void *i UNUSED, const char *k UNUSED,
			const char *v UNUSED) {
		GRID_DEBUG("property: '%s' -> '%s'", k, v);
	}
	void _on_info (void *i UNUSED, enum oio_sds_content_key_e k, const char *v) {
		GRID_DEBUG("info: '%d' -> '%s'", k, v);
	}
	err = oio_sds_show_content (client, url, NULL, _on_info, _on_metachunk,
			_on_property);
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

	/* Drain the content */
	err = oio_sds_drain(client, url);
	NOERROR(err);

	/* Remove the original content from the container */
	err = oio_sds_delete (client, url);
	NOERROR(err);

	/* Check the content is not present anymore */
	CHECK_ABSENT(client,url);

	/* TODO deleting twice SHOULD fail. */
	/* TODO setting properties on the content MUST fail */
	/* TODO getting properties from the content MUST fail */

	g_remove (tmppath);
}

static void
_roundtrip_put_multipart (const char * const * properties)
{
	struct oio_error_s *err = NULL;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7,15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	struct file_info_s fi0 = FILE_INFO_INIT;
	_checksum_file (source_path, &fi0);

	oio_url_set(url, OIOURL_VERSION, "");
	CHECK_ABSENT(client,url);

	struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
	ul_dst.url = url;
	ul_dst.autocreate = 1;
	ul_dst.out_size = 0;
	ul_dst.content_id = content_id;
	ul_dst.properties = properties;

	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	size_t content_size = 0;
	void _get_size(void *cb_data UNUSED,
			enum oio_sds_content_key_e key, const char *value) {
		if (key == OIO_SDS_CONTENT_SIZE)
			content_size = g_ascii_strtoll(value, NULL, 10);
	}
	size_t metachunk_size = 0;
	void _get_mc_size_(void *cb_data UNUSED,
			unsigned int seq, size_t offset, size_t length) {
		if (seq == 0 && offset == 0)
			metachunk_size = length;
	}

	err = oio_sds_show_content(client, url, NULL, NULL, _get_mc_size_,
			NULL);
	NOERROR(err);

	ul_dst.offset = metachunk_size;
	ul_dst.meta_pos = 1;
	ul_dst.partial = TRUE;
	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	err = oio_sds_show_content(client, url, NULL, _get_size, NULL,
			NULL);
	NOERROR(err);
	g_assert_cmpint(fi0.fs + metachunk_size, ==, content_size);
	gint extra = ((content_size - 1) % metachunk_size) + 1;

	ul_dst.offset = 0;
	ul_dst.meta_pos = 0;
	ul_dst.partial = TRUE;
	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	err = oio_sds_show_content(client, url, NULL, _get_size, NULL,
			NULL);
	NOERROR(err);
	g_assert_cmpint(fi0.fs + extra, ==, content_size);

	_roundtrip_tail (NULL, content_id, properties);

	oio_error_pfree (&err);
}

static void
_roundtrip_put_multipart_truncate (const char * const * properties)
{
	struct oio_error_s *err = NULL;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7,15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	struct file_info_s fi0 = FILE_INFO_INIT;
	_checksum_file (source_path, &fi0);

	CHECK_ABSENT(client,url);

	struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
	ul_dst.url = url;
	ul_dst.autocreate = 1;
	ul_dst.out_size = 0;
	ul_dst.content_id = content_id;
	ul_dst.properties = properties;

	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	ul_dst.offset = fi0.fs;
	ul_dst.meta_pos = 1;
	ul_dst.partial = TRUE;
	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	size_t content_size = 0;
	void _get_size(void *cb_data UNUSED,
			enum oio_sds_content_key_e key, const char *value) {
		if (key == OIO_SDS_CONTENT_SIZE)
			content_size = g_ascii_strtoll(value, NULL, 10);
	}
	size_t metachunk_size = 0;
	void _get_mc_size_(void *cb_data UNUSED,
			unsigned int seq, size_t offset, size_t length) {
		if (seq == 0 && offset == 0)
			metachunk_size = length;
	}

	err = oio_sds_show_content(client, url, NULL, _get_size, _get_mc_size_,
			NULL);
	NOERROR(err);
	g_assert_cmpint(fi0.fs + metachunk_size, ==, content_size);

	err = oio_sds_truncate(client, url, metachunk_size);
	NOERROR(err);

	err = oio_sds_show_content(client, url, NULL, _get_size, NULL, NULL);
	NOERROR(err);
	g_assert_cmpint(content_size, ==, metachunk_size);

	_roundtrip_tail (NULL, content_id, properties);

	oio_error_pfree (&err);
}

/* Upload the content at once then check the content is OK */
static void
_roundtrip_put_from_file (const char * const * properties)
{
	struct oio_error_s *err = NULL;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7,15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	struct file_info_s fi0 = FILE_INFO_INIT;
	_checksum_file (source_path, &fi0);

	CHECK_ABSENT(client,url);

	struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
	ul_dst.url = url;
	ul_dst.autocreate = 1;
	ul_dst.append = 0;
	ul_dst.out_size = 0;
	ul_dst.content_id = content_id;
	ul_dst.properties = properties;
	err = oio_sds_upload_from_file (client, &ul_dst, source_path, 0, 0);
	NOERROR(err);

	_roundtrip_tail (&fi0, content_id, properties);

	oio_error_pfree (&err);
}

/* Upload a content larger than the chunk size
 * then check the chunks' size */
static void
check_chunksize (const char * const * properties)
{
	const gint64 mega = 1024 * 1024;
	gint64 chunk_size = 5 * mega;
	struct oio_error_s *err = NULL;

	struct oio_url_s *url_random = oio_url_dup(url);
	gchar path[32];
	oio_str_randomize(path, oio_ext_rand_int_range(7,32), random_chars);
	oio_url_set(url_random, OIOURL_PATH, path);

	/* generate a buffer to work in. First we fill it of random bytes */
	const gsize size = chunk_size + 1 * mega;
	guint8 *buffer = g_malloc(size);
	g_assert_nonnull(buffer);
	oio_buf_randomize(buffer, size);
	gchar *pre_hash =
		g_compute_checksum_for_data(G_CHECKSUM_MD5, buffer, size);
	g_assert_nonnull(pre_hash);
	oio_str_upper(pre_hash);
	if (GRID_TRACE2_ENABLED()) {
		g_file_set_contents("/tmp/pre", (gchar *) buffer, size, (GError **) &err);
		NOERROR(err);
	}

	/**************************************************
	 * Configure the chunk size in the client.        */
	g_assert_cmpint(oio_sds_configure(client, OIOSDS_CFG_FLAG_CHUNKSIZE,
			&chunk_size, sizeof(chunk_size)), ==, 0);

	struct oio_sds_ul_dst_s ul_dst = OIO_SDS_UPLOAD_DST_INIT;
	ul_dst.url = url;
	ul_dst.autocreate = 1;
	ul_dst.append = 0;
	ul_dst.out_size = 0;
	ul_dst.properties = properties;
	err = oio_sds_upload_from_buffer(client, &ul_dst, buffer, size);
	NOERROR(err);

	/* get details on the content */
	gsize max_size[2] = {0};
	guint k = 1;
	void _on_info(void *i UNUSED, enum oio_sds_content_key_e key, const char *v) {
		if (key != OIO_SDS_CONTENT_CHUNKMETHOD)
			return;
		k = data_security_decode_param_int64(v, DS_KEY_K, 1);
	}
	void _on_metachunk(void *i UNUSED, guint seq, gsize offt, gsize len) {
		GRID_DEBUG("metachunk: %u, %"G_GSIZE_FORMAT" %"G_GSIZE_FORMAT,
				seq, offt, len);
		g_assert_cmpuint(seq, <, 2);
		max_size[seq] = len;
	}
	err = oio_sds_show_content(client, url, NULL, _on_info, _on_metachunk, NULL);
	NOERROR(err);
	if (k == 1) {
		g_assert_cmpuint(max_size[0], ==, chunk_size);
		g_assert_cmpuint(max_size[1], ==, size - chunk_size);
	} else {
		g_assert_cmpuint(max_size[0], <=, k * chunk_size);
	}

	/* delete the content */
	err = oio_sds_delete(client, url);
	NOERROR(err);
	/* Unset the chunk size */
	int64_t default_chunk_size = 0;
	g_assert_cmpint(oio_sds_configure(client, OIOSDS_CFG_FLAG_CHUNKSIZE,
			&default_chunk_size, sizeof(default_chunk_size)), ==, 0);

	/**************************************************
	 * Configure the chunk size only for this upload. */
	oio_var_value_one("core.sds.adapt_metachunk_size", "false");
	ul_dst.chunk_size = chunk_size;
	err = oio_sds_upload_from_buffer(client, &ul_dst, buffer, size);
	NOERROR(err);

	/* get details on the content */
	memset(max_size, 0, 2 * sizeof(gsize));
	err = oio_sds_show_content(client, url, NULL, NULL, _on_metachunk, NULL);
	NOERROR(err);
	g_assert_cmpuint(max_size[0], ==, chunk_size);
	g_assert_cmpuint(max_size[1], ==, size - chunk_size);

	/* delete the content */
	err = oio_sds_delete(client, url);
	NOERROR(err);

	oio_error_pfree(&err);
	oio_pfree0 (&buffer, NULL);
	oio_url_pclean(&url_random);
	oio_str_clean(&pre_hash);
}

/* Perform subsequent appends then check the content is OK */
static void
_roundtrip_append (const char * const * properties)
{
	struct oio_error_s *err = NULL;
	struct file_info_s fi0 = FILE_INFO_INIT ;
	const size_t cidlen = 1 + 2 * oio_ext_rand_int_range (7, 15);
	gchar content_id[cidlen];
	oio_str_randomize (content_id, cidlen, hex_chars);

	CHECK_ABSENT(client,url);

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	fi0.hs = g_checksum_type_get_length (G_CHECKSUM_SHA256);

	size_t content_size = 0;
	void _get_size(void *cb_data UNUSED,
			enum oio_sds_content_key_e key, const char *value) {
		if (key == OIO_SDS_CONTENT_SIZE)
			content_size = g_ascii_strtoll(value, NULL, 10);
	}

	const int max =  oio_ext_rand_int_range(7, 17);
	GRID_DEBUG("Uploading from [%u] blocks with id [%s]", max, content_id);
	for (int i = 0; i < max; ++i) {
		const size_t bufsize = oio_ext_rand_int_range(15, 129);
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
		err = oio_sds_show_content(client, url, NULL, _get_size, NULL, NULL);
		NOERROR(err);
		g_assert_cmpint(content_size, ==, fi0.fs);
	}
	GRID_DEBUG("Content uploaded");

	g_checksum_get_digest (checksum, fi0.h, &fi0.hs);
	g_checksum_free (checksum);
	_roundtrip_tail (&fi0, content_id, (const char * const *)properties);

	oio_error_pfree (&err);
}

static void
_roundtrip_put_autocontainer (const char * const * properties)
{
	struct file_info_s fi;
	_checksum_file (source_path, &fi);

	/* compute the autocontainer with the SHA1, consider only the first 17 bits */
	char tmp[65];
	const char *auto_container = oio_buf_prefix (fi.h, fi.hs, tmp, 17);

	/* build a new URL with the computed container name */
	struct oio_url_s *url_auto = oio_url_dup (url);
	oio_url_set (url_auto, OIOURL_USER, auto_container);
	_roundtrip_put_from_file (properties);
	oio_url_pclean (&url_auto);
}

static void
_test_cycle (gconstpointer d)
{
	const struct test_data_s *test_data = (const struct test_data_s*) d;

	GPtrArray *tmp = g_ptr_array_new ();
	for (int i=2*oio_ext_rand_int_range(0,9); i>0 ;--i) {
		int len = oio_ext_rand_int_range (2,23);
		gchar *str = g_malloc0(len);
		oio_str_randomize (str, len, random_chars);
		g_ptr_array_add (tmp, str);
	}
	g_ptr_array_sort(tmp, (GCompareFunc)g_strcmp0);
	g_ptr_array_add (tmp, NULL);

	oio_header_case = test_data->header_case;

	test_data->func((const char * const *) tmp->pdata);
	g_ptr_array_set_free_func (tmp, g_free);
	g_ptr_array_free (tmp, TRUE);
}

static void
_add_test (const char *name, enum oio_header_case_e c,
		test_func_f func)
{
	struct test_data_s *td = g_malloc0(sizeof(*td));
	td->header_case = c;
	td->func = func;
	g_test_add_data_func_full(name, td, _test_cycle, g_free);
}

#define ADD_TEST(tag,hcase,fn) do { \
	gchar buf[256]; \
	g_snprintf(buf, sizeof(buf), "/oiosds/%s/%s", tag, #hcase); \
	_add_test(buf, hcase, fn); \
} while (0)

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);

	oio_sds_default_autocreate = 1;

	if (argc != 2) {
		g_printerr ("Usage: %s PATH\n", argv[0]);
		return 1;
	}
	if (!oio_var_value_with_files(g_getenv("OIO_NS"), TRUE, NULL)) {
		g_printerr("Unknown NS [%s]\n", g_getenv("OIO_NS"));
		return 1;
	}

	source_path = argv[1];

	/* Ensure the URL exists */
	url = oio_url_empty ();
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
	GRID_DEBUG("URL valid [%s]", oio_url_get (url, OIOURL_WHOLE));

	struct oio_error_s *err = NULL;

	/* Initiate a client */
	err = oio_sds_init (&client, oio_url_get(url, OIOURL_NS));
	if (err) {
		g_printerr ("Client init error: (%d) %s\n", oio_error_code(err),
				oio_error_message(err));
		oio_error_pfree (&err);
		return 4;
	}
	GRID_DEBUG("Client ready to [%s]", oio_url_get (url, OIOURL_NS));

	/* Initiate simple put/get tests that check the size/hash are correct */
	g_test_add_func("/oiosds/putget", putget_all_sizes);

	/* then add a variety of tests that involve multiple appends, metachunk
	 * replacements */
	struct test_def_s {
		const char *tag;
		test_func_f func;
	} putv[] = {
		{ "put/file/asis", _roundtrip_put_from_file },
		{ "put/file/autocontainer", _roundtrip_put_autocontainer },
		{ "append/buffer/asis",_roundtrip_append },
		{ "update/file/asis", _roundtrip_put_multipart },
		{ "truncate/file/asis", _roundtrip_put_multipart_truncate },
		{ NULL, NULL }
	};
	for (struct test_def_s *pdef=putv; pdef->tag && pdef->func ;++pdef)
		ADD_TEST (pdef->tag, OIO_HDRCASE_NONE, pdef->func);
	ADD_TEST ("put/file/asis", OIO_HDRCASE_LOW,    _roundtrip_put_from_file);
	ADD_TEST ("put/file/asis", OIO_HDRCASE_1CAP,   _roundtrip_put_from_file);
	ADD_TEST ("put/file/asis", OIO_HDRCASE_RANDOM, _roundtrip_put_from_file);
	ADD_TEST ("put/buffer/chunksize", OIO_HDRCASE_RANDOM, check_chunksize);

	oio_chunk_size_minimum = 0;
	oio_chunk_size_maximum = 0;

	int rc = g_test_run();
	oio_sds_pfree (&client);
	oio_url_pclean (&url);
	return rc;
}
