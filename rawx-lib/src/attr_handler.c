/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include "rawx.h"

// TODO FIXME factorise with the metautils equivalent
#define SETERROR(e, m, ...) *(e) = g_error_new(GQ(), 0, m, ##__VA_ARGS__);
#define SETERRCODE(e, c, m, ...) *(e) = g_error_new(GQ(), c, m, ##__VA_ARGS__);

struct attr_handle_s
{
	int xattr_supported;
	char *chunk_path;
	int chunk_file_des;
	char *attr_path;
	int attr_file_des;
	GHashTable *attr_hash;
};

typedef gboolean(*attr_writer_f) (int file, const gchar * key,
		const gchar * value, GError ** error);

/* ------------------------------------------------------------------------- */

static volatile ssize_t longest_xattr = 256;
static volatile ssize_t longest_xattr_list = 256;

static ssize_t
_getxattr(const char *path, int fd, const char *k, char *v, ssize_t vs)
{
	if (fd >= 0)
		return fgetxattr(fd, k, v, vs);
	else
		return getxattr(path, k, v, vs);
}

static char *
_getxattr_from_chunk(const char *path, int fd, const char *attrname)
{
	int errsav;
	ssize_t s, size;
	gchar *buf;

	if ((!path && fd<0) || !attrname) {
		errno = EINVAL;
		return NULL;
	}

	s = longest_xattr;
	buf = g_malloc0(s);
retry:
	size = _getxattr(path, fd, attrname, buf, s);

	if (0 > size) { /* error */
		errsav = errno;
		if (errno != ERANGE) {
			g_free(buf);
			errno = errsav;
			return NULL;
		}
		else {
			s = s*2;
			longest_xattr = 1 + MAX(longest_xattr, s);
			buf = g_realloc(buf, s);
			memset(buf, 0, s);
			goto retry;
		}
	}
	else if (!size) { /* success but empty xattr */
		g_free(buf);
		return g_malloc0(1);
	}
	else {
		/* success and buffer long enough */
		return buf;
	}
}

static gboolean
_write_to_xattr(int file, const gchar * key, const gchar * value, GError ** error)
{
	if (file < 0 || !key || !value) {
		SETERRCODE(error, EINVAL, "Invalid parameter (%d %p %p)", file, key, value);
		return FALSE;
	}

	if (0 > fsetxattr(file, key, value, strlen(value), 0)) {
		SETERRCODE(error, errno, "Failed to add [%s/%s] to file xattr : %s", key, value, strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
_write_to_attr_file(int file, const gchar * key, const gchar * value, GError ** error)
{
	ssize_t rc0, rc1, rc2, rc3;
	ssize_t key_len, value_len;

	if (file < 0 || !key || !value) {
		SETERRCODE(error, EINVAL, "Invalid argument (%d %p %p)", file, key, value);
		return FALSE;
	}

	key_len = strlen(key);
	value_len = strlen(value);

	rc0 = write(file, key, key_len);
	if (rc0 != key_len) {
		SETERRCODE(error, errno, "write error : %s", strerror(errno));
		return FALSE;
	}

	rc1 = write(file, "=", 1);
	if (rc1 != 1) {
		SETERRCODE(error, errno, "write error : %s", strerror(errno));
		return FALSE;
	}

	rc2 = write(file, value, value_len);
	if (rc2 != value_len) {
		SETERRCODE(error, errno, "write error : %s", strerror(errno));
		return FALSE;
	}

	rc3 = write(file, "\n", 1);
	if (rc3 != 1) {
		SETERRCODE(error, errno, "write error : %s", strerror(errno));
		return FALSE;
	}

	return TRUE;
}

static gboolean
_write_attributes(GHashTable * attr_hash, int file, attr_writer_f writer, GError ** error)
{
	GHashTableIter iterator;
	gpointer key = NULL, value = NULL;
	GError *local_error = NULL;

	if (attr_hash == NULL) {
		SETERRCODE(error, EINVAL, "Invalid parameter attr_hash");
		return FALSE;
	}

	g_hash_table_iter_init(&iterator, attr_hash);

	while (g_hash_table_iter_next(&iterator, &key, &value)) {
		if (!writer(file, (gchar *) key, (gchar *) value, &local_error)) {
			SETERROR(error, "%s", local_error->message);
			g_clear_error(&local_error);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
_commit_attr_handle(struct attr_handle_s *attr_handle, GError ** error)
{
	GError *local_error = NULL;

	if (attr_handle == NULL) {
		SETERRCODE(error, EINVAL, "Invalid attr_handle argument");
		return FALSE;
	}

	/* try to write the chunk extended attributes */
	attr_handle->chunk_file_des = open(attr_handle->chunk_path, O_RDWR);
	if (attr_handle->chunk_file_des >= 0) {
		if (_write_attributes(attr_handle->attr_hash, attr_handle->chunk_file_des, _write_to_xattr,
			&local_error)) {
			metautils_pclose(&(attr_handle->chunk_file_des));
			return TRUE;
		}
		else {
			/*WARN("Failed to write attributes to chunk xattr : %s", local_error->message);*/
			metautils_pclose(&(attr_handle->chunk_file_des));
			g_clear_error(&local_error);
		}
	}

	/* Fallback to .attr file */
	attr_handle->attr_file_des = open(attr_handle->attr_path, O_RDWR | O_CREAT | O_TRUNC, 0644);
	if (attr_handle->attr_file_des < 0) {
		SETERRCODE(error, errno, "File [%s] open failed : %s", attr_handle->attr_path, strerror(errno));
		return FALSE;
	}
	else {
		if (!_write_attributes(attr_handle->attr_hash, attr_handle->attr_file_des, _write_to_attr_file,
				&local_error)) {
			metautils_pclose(&(attr_handle->attr_file_des));
			SETERROR(error, "Failed to write attributes to chunk.attr : %s", local_error->message);
			g_clear_error(&local_error);
			return FALSE;
		}
		metautils_pclose(&(attr_handle->attr_file_des));
	}

	return TRUE;
}

static gboolean
_commit_v2_attr_handle(int filedes, struct attr_handle_s *attr_handle, GError ** error)
{
	GError *local_error = NULL;

	if (attr_handle == NULL) {
		SETERRCODE(error, EINVAL, "Invalid attr_handle argument");
		return FALSE;
	}

	/* try to write the chunk extended attributes */
	if (filedes >= 0) {
		if (_write_attributes(attr_handle->attr_hash, filedes, _write_to_xattr,
			&local_error))
			return TRUE;
		else
			g_clear_error(&local_error);
	}

	return TRUE;
}

static struct attr_handle_s *
_alloc_attr_handle(const gchar * chunk_path)
{
	struct attr_handle_s *attr_handle = NULL;

	attr_handle = g_try_malloc0(sizeof(struct attr_handle_s));
	if (!attr_handle)
		goto error_handle;

	attr_handle->chunk_path = g_strdup(chunk_path);
	if (!attr_handle->chunk_path)
		goto error_chunk_path;

	attr_handle->attr_path = g_strdup_printf("%s.attr", chunk_path);
	if (!attr_handle->attr_path)
		goto error_attr_path;

	attr_handle->attr_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!attr_handle->attr_hash)
		goto error_hash;

	attr_handle->attr_file_des = -1;
	attr_handle->chunk_file_des = -1;
	return attr_handle;

error_hash:
	g_free(attr_handle->attr_path);
error_attr_path:
	g_free(attr_handle->chunk_path);
error_chunk_path:
	g_free(attr_handle);
error_handle:
	return NULL;
}

static void
_clean_attr_handle(struct attr_handle_s *attr_handle, int content_only)
{
	if (!attr_handle)
		return;

	if (attr_handle->chunk_path) {
		g_free(attr_handle->chunk_path);
		attr_handle->chunk_path = NULL;
	}
	if (attr_handle->attr_path) {
		g_free(attr_handle->attr_path);
		attr_handle->attr_path = NULL;
	}
	if (attr_handle->attr_hash) {
		g_hash_table_destroy(attr_handle->attr_hash);
		attr_handle->attr_hash = NULL;
	}
	if (attr_handle->chunk_file_des >= 0)
		metautils_pclose(&(attr_handle->chunk_file_des));
	if (attr_handle->attr_file_des >= 0)
		metautils_pclose(&(attr_handle->attr_file_des));

	if (!content_only)
		g_free(attr_handle);
}

static gboolean
_load_from_file_attr(struct attr_handle_s *attr_handle, GError ** error)
{
	FILE *stream;
	struct stat chunk_stats;
	char lineBuf[8192];

	EXTRA_ASSERT(attr_handle != NULL);
	EXTRA_ASSERT(attr_handle->attr_hash != NULL);

	/* stat the file */
	if (0 > stat(attr_handle->attr_path, &chunk_stats)) {
		SETERRCODE(error, errno, "Attr file [%s] not found for chunk", attr_handle->attr_path);
		return FALSE;
	}

	stream = fopen(attr_handle->attr_path, "r");
	if (!stream) {
		SETERRCODE(error, errno, "Failed to open stream to file [%s] : %s)",
			attr_handle->attr_path, strerror(errno));
		return FALSE;
	}

	while (fgets(lineBuf, sizeof(lineBuf), stream)) {
		/* Remove trailing \n */
		int line_len = strlen(lineBuf);
		if (lineBuf[line_len-1] == '\n')
			lineBuf[line_len-1] = '\0';

		char **tokens = g_strsplit(lineBuf, ":", 2);

		if (tokens) {
			if (*tokens && *(tokens + 1)) {
				g_hash_table_insert(attr_handle->attr_hash, *tokens, *(tokens + 1));
				g_free(tokens);
			}
			else
				g_strfreev(tokens);
		}
	}

	fclose(stream);

	return TRUE;
}

static gboolean
_load_from_xattr(struct attr_handle_s *attr_handle, GError ** error)
{
	char *last_name, *buf;
	register ssize_t i;
	ssize_t s, size;

	EXTRA_ASSERT(attr_handle != NULL);
	EXTRA_ASSERT(attr_handle->attr_hash != NULL);

	s = longest_xattr_list;
	buf = g_malloc0(s);
retry:
	size = listxattr(attr_handle->chunk_path, buf, s);
	if (0 > size) {
		if (errno != ERANGE) {
			SETERRCODE(error, errno, "Failed to list xattr from file [%s] : %s",
					attr_handle->chunk_path, strerror(errno));
			g_free(buf);
			return FALSE;
		}
		else {
			s = s*2;
			longest_xattr_list = 1 + MAX(longest_xattr_list, s);
			buf = g_realloc(buf, s);
			memset(buf, 0, s);
			goto retry;
		}
	}
	if (!size) {
		g_free(buf);
		return TRUE;
	}

	for (last_name = buf, i = 0; i < size; i++) {
		if (buf[i] == '\0') {
			char *value = _getxattr_from_chunk(attr_handle->chunk_path, attr_handle->chunk_file_des, last_name);
			if (NULL != value) {
				g_hash_table_insert(attr_handle->attr_hash, g_strdup(last_name), value);
			}
			else if (errno == ENOATTR) {
				/* XATTR disappeared ! */
			}
			else {
				SETERRCODE(error, errno, "Cannot get xattr %s from %s : %s",
						last_name, attr_handle->chunk_path, strerror(errno));
				g_free(buf);
				return FALSE;
			}
			last_name = buf + i + 1;
		}
	}

	g_free(buf);
	return TRUE;
}

static gboolean
_load_attr_from_file(const char *chunk_path, struct attr_handle_s** attr_handle, GError ** error)
{
	struct attr_handle_s *ah = NULL;
	GError *local_error = NULL;

	if (!(ah = _alloc_attr_handle(chunk_path))) {
		SETERRCODE(error, ENOMEM, "Memory allocation failure");
		return FALSE;
	}

	if (!_load_from_xattr(ah, &local_error)) {
		if (!local_error) {
			SETERRCODE(&local_error, 500, "Failed to load xattr : unknown error");
			goto error_and_exit;
		}
		else if (local_error->code != ENOTSUP)
			goto error_and_exit;
		else {
			g_clear_error(&local_error);
			if (!_load_from_file_attr(ah, &local_error))
				goto error_and_exit;
		}
	}

	if (local_error)
		g_clear_error(&local_error);
	*error = NULL;
	*attr_handle = ah;
	return TRUE;

error_and_exit:
	if (error)
		*error = local_error;
	else if (local_error)
		g_clear_error(&local_error);
	_clean_attr_handle(ah, FALSE);
	return FALSE;
}

static gboolean
_lazy_load_attr_from_file(const char *chunk_path, struct attr_handle_s** attr_handle, GError ** error)
{
	if (!(*attr_handle = _alloc_attr_handle(chunk_path))) {
		SETERRCODE(error, ENOMEM, "Memory allocation failure");
		return FALSE;
	}

	*error = NULL;
	return TRUE;
}

static gboolean
_get_attr_from_handle(struct attr_handle_s *attr_handle, GError ** error,
		const char *domain, const char *attrname, gchar **result)
{
	char key[ATTR_NAME_MAX_LENGTH], *value;

	if (!attr_handle || !domain || !attrname || !result) {
		SETERRCODE(error, EINVAL, "Invalid argument (%p %p %p %p)",
			attr_handle, domain, attrname, result);
		return FALSE;
	}

	g_snprintf(key, sizeof(key), "%s.%s", domain, attrname);

	value = g_hash_table_lookup(attr_handle->attr_hash, key);

	if (value)
		*result = g_strdup(value);
	else {
		GRID_TRACE("Attribute [%s] not found for chunk [%s]", key, attr_handle->chunk_path);
		*result = NULL;
	}
	return TRUE;
}

static gboolean
_set_attr_in_handle(struct attr_handle_s *attr_handle, GError ** error,
		const char *domain, const char *attrname, const char *attrvalue)
{
	char *k, *v;

	if (!attr_handle || !domain || !attrname || !attrvalue) {
		SETERRCODE(error, errno, "Invalid argument");
		return FALSE;
	}

	k = g_strdup_printf("%s.%s", domain, attrname);
	v = g_strdup(attrvalue);
	if (k && v) {
		g_hash_table_insert(attr_handle->attr_hash, k, v);
		return TRUE;
	}
	else {
		g_free(k);
		g_free(v);
		SETERRCODE(error, ENOMEM, "Memory allocation failure");
		return FALSE;
	}
}

/* -------------------------------------------------------------------------- */

#define SET(K,V) if (K) { \
	if ((V) && !_set_attr_in_handle(attr_handle, &e, ATTR_DOMAIN, K, (V))) \
		goto error_set_attr; \
}

static void _up (gchar *s) { do { *s = g_ascii_toupper(*s); } while (*(s++)); }

gboolean
set_rawx_full_info_in_attr(const char *p, int filedes, GError **error,
		struct content_textinfo_s * content, struct chunk_textinfo_s * chunk,
		const char* compression_info, const char* compressed_size)
{
	struct attr_handle_s *attr_handle;
	GError *e = NULL;

	if (!_lazy_load_attr_from_file(p, &attr_handle, &e)) {
		SETERROR(error, "Failed to init the attribute management context : %s", e->message);
		g_clear_error(&e);
		return FALSE;
	}

	if (chunk) {
		_up(chunk->hash);

		SET(ATTR_NAME_CHUNK_ID, chunk->id);
		SET(ATTR_NAME_CHUNK_SIZE, chunk->size);
		SET(ATTR_NAME_CHUNK_HASH, chunk->hash);
		SET(ATTR_NAME_CHUNK_POS, chunk->position);
		SET(ATTR_NAME_CHUNK_METADATA, chunk->metadata);
	}

	if (content) {
		_up(content->container_id);
		_up(content->content_id);

		SET(ATTR_NAME_CONTENT_CONTAINER, content->container_id);
		SET(ATTR_NAME_CONTENT_ID, content->content_id);
		SET(ATTR_NAME_CONTENT_PATH, content->path);
		SET(ATTR_NAME_CONTENT_VERSION, content->version);
		SET(ATTR_NAME_CONTENT_SIZE, content->size);
		SET(ATTR_NAME_CONTENT_NBCHUNK, content->chunk_nb);

		SET(ATTR_NAME_CONTENT_STGPOL, content->storage_policy);
		SET(ATTR_NAME_CONTENT_MIMETYPE, content->mime_type);
		SET(ATTR_NAME_CONTENT_CHUNKMETHOD, content->chunk_method);
	}

	SET(ATTR_NAME_CHUNK_COMPRESSED_SIZE, compressed_size);
	SET(ATTR_NAME_CHUNK_METADATA_COMPRESS, compression_info);

	gboolean rc;
	if (filedes < 0)
		rc = _commit_attr_handle(attr_handle, &e);
	else
		rc = _commit_v2_attr_handle(filedes, attr_handle, &e);

	if (!rc) {
		SETERROR(error, "Could not write all the attributes on disk : %s", e->message);
		g_clear_error(&e);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);
	return TRUE;

error_set_attr:
	SETERROR(error, "Failed to set attr in handle : %s", e->message);
	g_clear_error(&e);
	_clean_attr_handle(attr_handle, FALSE);
	return FALSE;
}

gboolean
set_rawx_info_in_attr(const char *p, GError ** error, struct content_textinfo_s * content,
    struct chunk_textinfo_s * chunk)
{
	return set_rawx_full_info_in_attr (p, -1, error, content, chunk, NULL, NULL);
}

gboolean
set_chunk_info_in_attr(const char *p, GError ** error, struct chunk_textinfo_s * cti)
{
	return set_rawx_full_info_in_attr (p, -1, error, NULL, cti, NULL, NULL);
}

gboolean
set_content_info_in_attr(const char *p, GError ** error, struct content_textinfo_s * cti)
{
	return set_rawx_full_info_in_attr (p, -1, error, cti, NULL, NULL, NULL);
}

gboolean
set_compression_info_in_attr(const char *p, GError ** error, const char *v)
{
	if (!v) {
		SETERROR(error, "Empty compression metadata");
		return FALSE;
	}
	return set_rawx_full_info_in_attr (p, -1, error, NULL, NULL, v, NULL);
}

gboolean
set_chunk_compressed_size_in_attr(const char *p, GError ** error, guint32 v)
{
	gchar buf[32] = "";
	g_snprintf (buf, sizeof(buf), "%"G_GUINT32_FORMAT, v);
	return set_rawx_full_info_in_attr (p, -1, error, NULL, NULL, NULL, buf);
}

/* -------------------------------------------------------------------------- */

#define GET(K,R) if (!_get_attr_from_handle(attr_handle, &e, ATTR_DOMAIN, K, &(R))) { \
	goto error_get_attr; \
}

gboolean
get_chunk_compressed_size_in_attr(const char *pathname, GError ** error, guint32* compressed_size)
{
	gchar* tmp = NULL;

	if (!(tmp = _getxattr_from_chunk(pathname, -1, ATTR_DOMAIN "." ATTR_NAME_CHUNK_COMPRESSED_SIZE))) {
		GSETCODE(error, errno, "compressedsize not found : %s", strerror(errno));
		return FALSE;
	}

	*compressed_size = g_ascii_strtoll(tmp, NULL, 10);
	g_free(tmp);
	return TRUE;
}

gboolean
get_rawx_info_in_attr(const char *pathname, GError ** error,
		struct content_textinfo_s * content, struct chunk_textinfo_s * chunk)
{
	struct attr_handle_s *attr_handle;
	GError *e = NULL;

	if (!_load_attr_from_file(pathname, &attr_handle, &e)) {
		SETERROR(error, "Failed to init the attribute management context : %s",
				e->message);
		g_clear_error(&e);
		return FALSE;
	}

	if (chunk) {
		GET(ATTR_NAME_CHUNK_ID, chunk->id);
		GET(ATTR_NAME_CHUNK_SIZE, chunk->size);
		GET(ATTR_NAME_CHUNK_POS, chunk->position);
		GET(ATTR_NAME_CHUNK_HASH, chunk->hash);
		GET(ATTR_NAME_CHUNK_METADATA, chunk->metadata);
	}

	if (content) {
		GET(ATTR_NAME_CONTENT_CONTAINER, content->container_id);
		GET(ATTR_NAME_CONTENT_ID, content->content_id);
		GET(ATTR_NAME_CONTENT_PATH, content->path);
		GET(ATTR_NAME_CONTENT_VERSION, content->version);
		GET(ATTR_NAME_CONTENT_SIZE, content->size);
		GET(ATTR_NAME_CONTENT_NBCHUNK, content->chunk_nb);

		GET(ATTR_NAME_CONTENT_STGPOL, content->storage_policy);
		GET(ATTR_NAME_CONTENT_CHUNKMETHOD, content->chunk_method);
		GET(ATTR_NAME_CONTENT_MIMETYPE, content->mime_type);
	}

	_clean_attr_handle(attr_handle, FALSE);
	return TRUE;

error_get_attr:
	SETERROR(error, "Failed to get attr : %s", e->message);
	g_clear_error(&e);
	_clean_attr_handle(attr_handle, FALSE);
	return FALSE;
}

gboolean
get_content_info_in_attr(const char *p, GError **e, struct content_textinfo_s *c)
{
	return get_rawx_info_in_attr (p, e, c, NULL);
}

gboolean
get_chunk_info_in_attr(const char *p, GError **e, struct chunk_textinfo_s *c)
{
	return get_rawx_info_in_attr (p, e, NULL, c);
}

gboolean
get_compression_info_in_attr(const char *pathname, GError ** error,
		GHashTable ** table)
{
	gchar *tmp;

	if (!table || !*table || !pathname) {
		SETERROR(error, "invalid parameter");
		return FALSE;
	}

	tmp = _getxattr_from_chunk(pathname, -1,
			ATTR_DOMAIN "." ATTR_NAME_CHUNK_METADATA_COMPRESS);

	if (!tmp) {
		if (errno != ENOATTR) {
			GSETCODE(error, errno, "Failed to get compression attr : %s\n", strerror(errno));
			return FALSE;
		}
	}
	else {
		if (*tmp) {
			GHashTable *ht = metadata_unpack_string(tmp, NULL);
			metadata_merge(*table, ht);
		}
		g_free(tmp);
	}

	return TRUE;
}

/* -------------------------------------------------------------------------- */

static void
_rawx_acl_clean(gpointer data, gpointer udata)
{
	(void) udata;
	addr_rule_g_free(data);
}

void
rawx_conf_gclean(rawx_conf_t* c)
{
	rawx_conf_clean(c);
	g_free(c);
}

void
rawx_conf_clean(rawx_conf_t* c)
{
	if(!c)
		return;

	if(c->ni) {
		namespace_info_free(c->ni);
		c->ni = NULL;
	}
	if(c->sp) {
		storage_policy_clean(c->sp);
		c->sp = NULL;
	}
	if(c->acl) {
		g_slist_foreach(c->acl, _rawx_acl_clean, NULL);
		g_slist_free(c->acl);
		c->acl = NULL;
	}
}

