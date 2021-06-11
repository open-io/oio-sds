/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/xattr.h>

#include <metautils/lib/metautils.h>

#include "rawx.h"

static volatile ssize_t longest_xattr = 2048;

static gchar *
_getxattr_from_fd(int fd, const char *attrname)
{
	ssize_t size;
	ssize_t s = longest_xattr;
	gchar *buf = g_malloc0(s);
retry:
	size = fgetxattr(fd, attrname, buf, s);
	if (size > 0)
		return buf;
	if (size == 0) {
		*buf = 0;
		return buf;
	}

	if (errno == ERANGE) {
		s = s*2;
		longest_xattr = 1 + MAX(longest_xattr, s);
		buf = g_realloc(buf, s);
		memset(buf, 0, s);
		goto retry;
	}

	int errsav = errno;
	g_free(buf);
	errno = errsav;
	return NULL;
}

/* -------------------------------------------------------------------------- */

#define SET(K,V) if (K) { \
	if ((V) && 0 > fsetxattr(fd, ATTR_DOMAIN "." K, V, strlen(V), 0)) \
		goto error_set_attr; \
}

gboolean
set_rawx_info_to_fd(int fd, GError **error, struct chunk_textinfo_s *chunk)
{
	if (fd < 0) {
		GSETCODE(error, EINVAL, "invalid FD");
		return FALSE;
	}

	if (!chunk)
		return TRUE;

	if (chunk->content_fullpath && !chunk->chunk_id) {
		GSETCODE(error, EINVAL, "Missing chunk ID");
		return FALSE;
	}

	oio_str_upper(chunk->container_id);
	oio_str_upper(chunk->content_id);
	oio_str_upper(chunk->chunk_hash);
	oio_str_upper(chunk->metachunk_hash);

	if (chunk->content_fullpath) {
		gchar *attr_name_content_fullpath = g_strconcat(
				ATTR_DOMAIN_OIO "." ATTR_NAME_CONTENT_FULLPATH ":",
				chunk->chunk_id, NULL);
		if (fsetxattr(fd, attr_name_content_fullpath, chunk->content_fullpath,
				strlen(chunk->content_fullpath), 0) < 0) {
			g_free(attr_name_content_fullpath);
			goto error_set_attr;
		}
		g_free(attr_name_content_fullpath);
	}

	SET(ATTR_NAME_CONTENT_SIZE,        chunk->content_size);
	SET(ATTR_NAME_CONTENT_NBCHUNK,     chunk->content_chunk_nb);

	SET(ATTR_NAME_CONTENT_STGPOL,      chunk->content_storage_policy);
	SET(ATTR_NAME_CONTENT_CHUNKMETHOD, chunk->content_chunk_method);
	SET(ATTR_NAME_CONTENT_MIMETYPE,    chunk->content_mime_type);

	SET(ATTR_NAME_METACHUNK_SIZE, chunk->metachunk_size);
	SET(ATTR_NAME_METACHUNK_HASH, chunk->metachunk_hash);

	SET(ATTR_NAME_CHUNK_SIZE, chunk->chunk_size);
	SET(ATTR_NAME_CHUNK_HASH, chunk->chunk_hash);
	SET(ATTR_NAME_CHUNK_POS,  chunk->chunk_position);

	SET(ATTR_NAME_CHUNK_METADATA_COMPRESS, chunk->compression_metadata);
	SET(ATTR_NAME_CHUNK_COMPRESSED_SIZE,   chunk->compression_size);

	SET(ATTR_NAME_OIO_VERSION, chunk->oio_version);

	return TRUE;

error_set_attr:
	GSETCODE(error, errno, "setxattr error: (%d) %s", errno, strerror(errno));
	return FALSE;
}

gboolean
set_rawx_info_to_file(const char *p, GError **error,
		struct chunk_textinfo_s *chunk)
{
	int fd = open(p, O_WRONLY);
	if (fd < 0) {
		GSETCODE(error, errno, "open() error: (%d) %s", errno, strerror(errno));
		return FALSE;
	} else {
		gboolean rc = set_rawx_info_to_fd(fd, error, chunk);
		int errsav = errno;
		metautils_pclose (&fd);
		errno = errsav;
		return rc;
	}
}

gboolean
set_compression_info_in_attr(const char *p, GError ** error, const char *v)
{
	int rc = lsetxattr(p, ATTR_DOMAIN "." ATTR_NAME_CHUNK_METADATA_COMPRESS,
			v, strlen(v), 0);
	if (rc < 0)
		GSETCODE(error, errno, "setxattr error: (%d) %s", errno, strerror(errno));
	return rc == 0;
}

gboolean
set_chunk_compressed_size_in_attr(const char *p, GError ** error, guint32 v)
{
	gchar buf[32] = "";
	g_snprintf (buf, sizeof(buf), "%"G_GUINT32_FORMAT, v);
	int rc = lsetxattr(p, ATTR_DOMAIN ATTR_NAME_CHUNK_COMPRESSED_SIZE,
			buf, strlen(buf), 0);
	if (rc < 0)
		GSETCODE(error, errno, "setxattr error: (%d) %s", errno, strerror(errno));
	return rc == 0;
}

/* -------------------------------------------------------------------------- */

static gboolean
_get (int fd, const char *k, gchar **pv)
{
	gchar *v = _getxattr_from_fd (fd, k);
	int errsav = errno;
	oio_str_reuse(pv, v);
	errno = errsav;
	return v != NULL;
}

#define GET(K,R) _get(fd, ATTR_DOMAIN "." K, &(R))

gboolean
get_rawx_fullpath_info_from_fd(int fd, GError **error, gchar *hex_chunkid,
		struct chunk_textinfo_s *chunk)
{
	if (fd < 0) {
		GSETCODE(error, EINVAL, "invalid FD");
		return FALSE;
	}
	if (!hex_chunkid) {
		GSETCODE(error, EINVAL, "missing chunk ID");
		return FALSE;
	}
	if (!chunk) {
		GSETCODE(error, EINVAL, "missing chunk structure");
		return FALSE;
	}

	gboolean rc = TRUE;

	gchar *attr_name_content_fullpath = g_strconcat(
			ATTR_DOMAIN_OIO "." ATTR_NAME_CONTENT_FULLPATH ":", hex_chunkid,
			NULL);
	_get(fd, attr_name_content_fullpath, &(chunk->content_fullpath));
	if (chunk->content_fullpath) {
		// New chunk
		chunk->chunk_id = g_strdup(hex_chunkid);
		gchar **fullpath = g_strsplit(chunk->content_fullpath, "/", -1);
		guint fullpath_len = g_strv_length(fullpath);
		if (fullpath_len != 5) {
			GSETCODE(error, EINVAL, "invalid %s xattr",
					attr_name_content_fullpath);
			rc = FALSE;
		}

		char *account = g_uri_unescape_string(fullpath[0], NULL);
		char *container = g_uri_unescape_string(fullpath[1], NULL);
		guint8 container_id[32];
		char container_hexid[65];
		// NS is unused
		oio_str_hash_name(container_id, NULL, account, container);
		oio_str_bin2hex(container_id, sizeof(container_id),
				container_hexid, sizeof(container_hexid));
		g_free(account);
		g_free(container);

		chunk->container_id = g_strdup(container_hexid);
		chunk->content_path = g_uri_unescape_string(fullpath[2], NULL);
		chunk->content_version = g_uri_unescape_string(fullpath[3], NULL);
		chunk->content_id = g_uri_unescape_string(fullpath[4], NULL);
		g_strfreev(fullpath);
	} else {
		// Old chunk
		GET(ATTR_NAME_CHUNK_ID,          chunk->chunk_id);
		if (g_strcmp0(hex_chunkid, chunk->chunk_id) != 0) {
			GSETCODE(error, EINVAL,
					"no %s xattr, invalid or missing %s xattr",
					attr_name_content_fullpath,
					ATTR_DOMAIN_OIO "." ATTR_NAME_CHUNK_ID);
			rc = FALSE;
		}
		// Still try to load other attributes
		GET(ATTR_NAME_CONTENT_CONTAINER, chunk->container_id);
		GET(ATTR_NAME_CONTENT_PATH,      chunk->content_path);
		GET(ATTR_NAME_CONTENT_VERSION,   chunk->content_version);
		GET(ATTR_NAME_CONTENT_ID,        chunk->content_id);
	}
	g_free(attr_name_content_fullpath);

	return rc;
}

gboolean
get_rawx_fullpath_info_from_file(const char *p, GError **error, gchar *hex_chunkid,
		struct chunk_textinfo_s *chunk)
{
	int fd = open(p, O_RDONLY);
	if (fd < 0) {
		GSETCODE(error, errno, "open() error: (%d) %s", errno, strerror(errno));
		return FALSE;
	} else {
		gboolean rc = get_rawx_fullpath_info_from_fd(fd, error, hex_chunkid, chunk);
		int errsav = errno;
		metautils_pclose (&fd);
		errno = errsav;
		return rc;
	}
}

gboolean
get_rawx_info_from_fd(int fd, GError **error, gchar *hex_chunkid,
		struct chunk_textinfo_s *chunk)
{
	if (fd < 0) {
		GSETCODE(error, EINVAL, "invalid FD");
		return FALSE;
	}
	if (!hex_chunkid) {
		GSETCODE(error, EINVAL, "missing chunk ID");
		return FALSE;
	}

	gchar *v = NULL;
	if (!GET(ATTR_NAME_CONTENT_STGPOL, v)) {
		/* just one check to detect unsupported xattr */
		if (errno == ENOTSUP) {
			GSETCODE(error, errno, "xattr not supported");
			return FALSE;
		}
	}
	if (!chunk) {
		g_free0(v);
		return TRUE;
	} else {
		chunk->content_storage_policy = v;
	}

	gboolean rc = get_rawx_fullpath_info_from_fd(fd, error, hex_chunkid,
			chunk);

	GET(ATTR_NAME_CONTENT_SIZE,    chunk->content_size);
	GET(ATTR_NAME_CONTENT_NBCHUNK, chunk->content_chunk_nb);

	GET(ATTR_NAME_CONTENT_CHUNKMETHOD, chunk->content_chunk_method);
	GET(ATTR_NAME_CONTENT_MIMETYPE,    chunk->content_mime_type);

	GET(ATTR_NAME_METACHUNK_SIZE, chunk->metachunk_size);
	GET(ATTR_NAME_METACHUNK_HASH, chunk->metachunk_hash);

	GET(ATTR_NAME_CHUNK_SIZE, chunk->chunk_size);
	GET(ATTR_NAME_CHUNK_POS,  chunk->chunk_position);
	GET(ATTR_NAME_CHUNK_HASH, chunk->chunk_hash);

	GET(ATTR_NAME_CHUNK_METADATA_COMPRESS, chunk->compression_metadata);
	GET(ATTR_NAME_CHUNK_COMPRESSED_SIZE,   chunk->compression_size);

	GET(ATTR_NAME_OIO_VERSION, chunk->oio_version);

	return rc;
}

gboolean
get_rawx_info_from_file(const char *p, GError **error, gchar *hex_chunkid,
		struct chunk_textinfo_s *chunk)
{
	int fd = open(p, O_RDONLY);
	if (fd < 0) {
		GSETCODE(error, errno, "open() error: (%d) %s", errno, strerror(errno));
		return FALSE;
	} else {
		gboolean rc = get_rawx_info_from_fd(fd, error, hex_chunkid, chunk);
		int errsav = errno;
		metautils_pclose (&fd);
		errno = errsav;
		return rc;
	}
}

gboolean
get_compression_info_in_attr(const char *p, GError ** error, GHashTable *table)
{
	EXTRA_ASSERT (p != NULL);
	EXTRA_ASSERT (table != NULL);

	gchar buf[2048];
	memset(buf, 0, sizeof(buf));

	int rc = lgetxattr(p, ATTR_DOMAIN "." ATTR_NAME_CHUNK_METADATA_COMPRESS, buf, sizeof(buf));
	if (rc < 0) {
		// ENOATTR == ENODATA
		if (errno != ENODATA) {
			GSETCODE(error, errno, "Failed to get compression attr: %s", strerror(errno));
			return FALSE;
		}
	} else {
		if (*buf) {
			GHashTable *ht = metadata_unpack_string(buf, NULL);
			metadata_merge (table, ht);
			g_hash_table_destroy (ht);
		}
	}

	return TRUE;
}

void
chunk_textinfo_free_content(struct chunk_textinfo_s *cti)
{
	if (!cti)
		return;
	oio_str_clean (&cti->container_id);

	oio_str_clean (&cti->content_id);
	oio_str_clean (&cti->content_path);
	oio_str_clean (&cti->content_version);
	oio_str_clean (&cti->content_size);
	oio_str_clean (&cti->content_chunk_nb);

	oio_str_clean (&cti->content_storage_policy);
	oio_str_clean (&cti->content_chunk_method);
	oio_str_clean (&cti->content_mime_type);

	oio_str_clean (&cti->metachunk_size);
	oio_str_clean (&cti->metachunk_hash);

	oio_str_clean (&cti->chunk_id);
	oio_str_clean (&cti->chunk_size);
	oio_str_clean (&cti->chunk_hash);
	oio_str_clean (&cti->chunk_position);

	oio_str_clean (&cti->compression_metadata);
	oio_str_clean (&cti->compression_size);

	oio_str_clean (&cti->oio_version);

	oio_str_clean (&cti->content_fullpath);
}
