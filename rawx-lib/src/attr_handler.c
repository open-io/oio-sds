/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include "rawx.h"

static volatile ssize_t longest_xattr = 1024;
static volatile ssize_t longest_xattr_list = 2048;

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

static gboolean
_set_xattr_list(int fd, gchar* name, gchar* keys)
{
	if (!keys)
		return FALSE;
	gchar **fields = g_strsplit(keys, ",", -1);
	if (!fields)
		return FALSE;
	for(gchar **f = fields; *f; ++f) {
		gchar *escaped_name = g_strconcat(name, ":", *f, NULL);
		if (fsetxattr(fd, escaped_name, "", 0, 0) == -1) {
			g_free(escaped_name);
			g_strfreev(fields);
			return FALSE;
		}
		g_free(escaped_name);
	}
	g_strfreev(fields);
	return TRUE;
}

gboolean
set_rawx_info_to_fd (int fd, GError **error, struct chunk_textinfo_s *cti)
{
	if (fd < 0) {
		GSETCODE(error, EINVAL, "invalid FD");
		return FALSE;
	}

	if (!cti)
		return TRUE;

	oio_str_upper(cti->container_id);
	oio_str_upper(cti->content_id);
	oio_str_upper(cti->chunk_hash);
	oio_str_upper(cti->metachunk_hash);

	SET(ATTR_NAME_CONTENT_CONTAINER, cti->container_id);

	SET(ATTR_NAME_CONTENT_ID,          cti->content_id);
	SET(ATTR_NAME_CONTENT_PATH,        cti->content_path);
	SET(ATTR_NAME_CONTENT_VERSION,     cti->content_version);
	SET(ATTR_NAME_CONTENT_SIZE,        cti->content_size);
	SET(ATTR_NAME_CONTENT_NBCHUNK,     cti->content_chunk_nb);

	SET(ATTR_NAME_CONTENT_STGPOL,      cti->content_storage_policy);
	SET(ATTR_NAME_CONTENT_CHUNKMETHOD, cti->content_chunk_method);
	SET(ATTR_NAME_CONTENT_MIMETYPE,    cti->content_mime_type);

	SET(ATTR_NAME_METACHUNK_SIZE, cti->metachunk_size);
	SET(ATTR_NAME_METACHUNK_HASH, cti->metachunk_hash);

	SET(ATTR_NAME_CHUNK_ID,   cti->chunk_id);
	SET(ATTR_NAME_CHUNK_SIZE, cti->chunk_size);
	SET(ATTR_NAME_CHUNK_HASH, cti->chunk_hash);
	SET(ATTR_NAME_CHUNK_POS,  cti->chunk_position);

	SET(ATTR_NAME_CHUNK_METADATA_COMPRESS, cti->compression_metadata);
	SET(ATTR_NAME_CHUNK_COMPRESSED_SIZE,   cti->compression_size);

	SET(ATTR_NAME_OIO_VERSION, cti->oio_version);

	if (cti->oio_full_path && !_set_xattr_list(fd, ATTR_DOMAIN_OIO,
			cti->oio_full_path))
		goto error_set_attr;

	return TRUE;

error_set_attr:
	GSETCODE(error, errno, "setxattr error: (%d) %s", errno, strerror(errno));
	return FALSE;
}

gboolean
set_rawx_info_to_file (const char *p, GError **error, struct chunk_textinfo_s *cti)
{
	int fd = open(p, O_WRONLY);
	if (fd < 0) {
		GSETCODE(error, errno, "open() error: (%d) %s", errno, strerror(errno));
		return FALSE;
	} else {
		gboolean rc = set_rawx_info_to_fd (fd, error, cti);
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


/**
 * Fullpaths are in the form 'oio:account/container/path/version'
 * So we have to check the prefix:'oio:'.
 * Sometimes we need to only have the fullpath of a specific path
 * So we have to check /path
 */
static GString*
_get_fullpaths_from_listxattr(gchar * xattrlist, ssize_t size, gchar *path)
{
	GString* user_list = g_string_new("");
	gchar* elem = NULL;
	gchar* enclosed_path = g_strconcat("/", path, "/", NULL);
	for (gint i = 0; i < size; i+= strlen(&xattrlist[i]) + 1) {
		elem = strstr(&xattrlist[i], ATTR_DOMAIN_OIO);
		if (elem) {
			if (path)
				elem = g_strrstr(&xattrlist[i], enclosed_path );
			if(!path || elem) {
				if (user_list->len)
					user_list = g_string_append_c(user_list, ',');
				user_list = g_string_append(user_list,
						&xattrlist[i + strlen(ATTR_DOMAIN_OIO) + 1]);
			}
			elem = NULL;
		}
	}
	return user_list;
}

static gboolean
_get_fullpaths_from_fd(int fd, gchar **list_path, gchar *path)
{
	ssize_t s = longest_xattr_list;
	gchar *buf = g_malloc0(s);
	ssize_t rc;
retry:
	rc = flistxattr(fd, buf, longest_xattr_list);
	if (rc < 0) {
		if (errno == ERANGE) {
			s = s*2;
			longest_xattr_list = 1 + MAX(longest_xattr_list, s);
			buf = g_realloc(buf, s);
			memset(buf, 0, s);
			goto retry;
		} else {
			g_free(buf);
			return FALSE;
		}
	}
	GString *full_path = _get_fullpaths_from_listxattr(buf, rc, path);
	*list_path = full_path->str;
	g_free(buf);
	g_string_free(full_path, FALSE);
	return TRUE;
}

gboolean
get_rawx_info_from_fd (int fd, GError **error, struct chunk_textinfo_s *cti)
{
	if (fd < 0) {
		GSETCODE(error, EINVAL, "invalid FD");
		return FALSE;
	}

	if (!cti) {
		gchar *v = NULL;
		if (!GET(ATTR_NAME_CONTENT_CONTAINER, v)) {
			if (errno == ENOTSUP) {
				GSETCODE(error, errno, "xattr not supported");
				return FALSE;
			}
		} else {
			g_free0 (v);
		}
		return TRUE;
	}

	if (!GET(ATTR_NAME_CONTENT_CONTAINER, cti->container_id)) {
		/* just one check to detect unsupported xattr */
		if (errno == ENOTSUP) {
			GSETCODE(error, errno, "xattr not supported");
			return FALSE;
		}
	}

	_get_fullpaths_from_fd(fd, &(cti->oio_full_path),
			cti->content_path);

	GET(ATTR_NAME_CONTENT_ID,      cti->content_id);
	GET(ATTR_NAME_CONTENT_PATH,    cti->content_path);
	GET(ATTR_NAME_CONTENT_VERSION, cti->content_version);
	GET(ATTR_NAME_CONTENT_SIZE,    cti->content_size);
	GET(ATTR_NAME_CONTENT_NBCHUNK, cti->content_chunk_nb);

	GET(ATTR_NAME_CONTENT_STGPOL,      cti->content_storage_policy);
	GET(ATTR_NAME_CONTENT_CHUNKMETHOD, cti->content_chunk_method);
	GET(ATTR_NAME_CONTENT_MIMETYPE,    cti->content_mime_type);

	GET(ATTR_NAME_METACHUNK_SIZE, cti->metachunk_size);
	GET(ATTR_NAME_METACHUNK_HASH, cti->metachunk_hash);

	GET(ATTR_NAME_CHUNK_ID,   cti->chunk_id);
	GET(ATTR_NAME_CHUNK_SIZE, cti->chunk_size);
	GET(ATTR_NAME_CHUNK_POS,  cti->chunk_position);
	GET(ATTR_NAME_CHUNK_HASH, cti->chunk_hash);

	GET(ATTR_NAME_CHUNK_METADATA_COMPRESS, cti->compression_metadata);
	GET(ATTR_NAME_CHUNK_COMPRESSED_SIZE,   cti->compression_size);

	GET(ATTR_NAME_OIO_VERSION, cti->oio_version);

	return TRUE;
}

gboolean
get_rawx_info_from_file (const char *p, GError ** error, struct chunk_textinfo_s *cti)
{
	int fd = open(p, O_RDONLY);
	if (fd < 0) {
		GSETCODE(error, errno, "open() error: (%d) %s", errno, strerror(errno));
		return FALSE;
	} else {
		gboolean rc = get_rawx_info_from_fd (fd, error, cti);
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
		if (errno != ENOATTR) {
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

	oio_str_clean (&cti->oio_full_path);
}
