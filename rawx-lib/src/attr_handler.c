#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.attr"
#endif

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
#define SETERROR(e, m, ...) *(e) = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN), 0, m, ##__VA_ARGS__);
#define SETERRCODE(e, c, m, ...) *(e) = g_error_new(g_quark_from_static_string(G_LOG_DOMAIN), c, m, ##__VA_ARGS__);

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

/**
 Write key/value pair into an extended attribute of a file

 @param file an opened file descriptor to the file
 @param key the key
 @param value the value
 @param error

 @return TRUE or FALSE if an error occured (error will be set)
 */
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


/**
 Write key/value pair into a regular file

 @param file an opened file descriptor to the file
 @key the key
 @param value the value
 @param error

 @return TRUE or FALSE if an error occured (error will be set)
 */
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


/**
 Write attibutes from attr_handle using the given writer

 @param attr_hash the hash containing key/value pairs to write
 @param file an opened descriptor to a file (depends on the writer used)
 @param writer a writer function pointer
 @param error

 @return TRUE or FALSE if an error occured (error will be set)
 */
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

/**
 Write all attributes

 @param attr_handle the attr_handle containing attibutes to write
 @param error

 @return TRUE or FALSE if an error occured (error will be set)
 */
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

/**
 Write all attributes

 @param attr_handle the attr_handle containing attibutes to write
 @param error

 @return TRUE or FALSE if an error occured (error will be set)
 */
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

/**
 Alloc a new struct attr_handle_s

 @param chunk_path the path to the chunk file

 @return an allocated struct attr_handle_s or NULL if a memory alocation failed
 */
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


/**
 * Free struct attr_handle_s
 *
 * @param attr_handle a struct attr_handle_s to free
 * @param content_only a flag to specify if we want to free the struct itself
 *
 * TODO FIXME XXX duplicated in rawx-lighttpd/li and rules-motor/c2python.c
 */
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


/**
 Load attributes from .attr file

 @param attr_handle the struct attr_handle to fill
 @param error

 @return TRUE or FALSE if an errror occured (error is set)
 */
static gboolean
_load_from_file_attr(struct attr_handle_s *attr_handle, GError ** error)
{
	FILE *stream;
	struct stat chunk_stats;
	char lineBuf[65536];

	g_assert(attr_handle != NULL);
	g_assert(attr_handle->attr_hash != NULL);

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


/**
 Load attributes from xattr

 @param attr_handle the struct attr_handle to fill
 @param error

 @return TRUE or FALSE if an error occured (error is set)
 */
static gboolean
_load_from_xattr(struct attr_handle_s *attr_handle, GError ** error)
{
	char *last_name, *buf;
	register ssize_t i;
	ssize_t s, size;

	g_assert(attr_handle != NULL);
	g_assert(attr_handle->attr_hash != NULL);

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


/**
 Load attributes from chunk (either from xattr or from chunk.attr)

 @param chunk_path the path to the chunk file
 @param attr_handle a double pointer to struct attr_handle_s which will be allocated
 @param error

 @return TRUE or FALSE if a memory allocation failed
 */
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

/**
 Get an empty attr handler for chunk (either from xattr or from chunk.attr)

 @param chunk_path the path to the chunk file
 @param attr_handle a double pointer to struct attr_handle_s which will be allocated
 @param error

 @return TRUE or FALSE if a memory allocation failed
 */
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

/**
 Get attribute from attr_handle struct

 @param attr_handle the attr_handle to look attribute in
 @param error
 @param domain the attibute domain
 @param attrname the attribute name
 @param result will be allocated with attribute value or NULL if an error
	occured or attrbute was not found

 @return TRUE or FALSE if an error occured or attribute was not found
	(error is set)
 */
static gboolean
_get_attr_from_handle(struct attr_handle_s *attr_handle, GError ** error,
		const char *domain, const char *attrname, char **result, gboolean opt)
{
	char attr_name_buf[ATTR_NAME_MAX_LENGTH], *value;

	if (!attr_handle || !domain || !attrname || !result) {
		SETERRCODE(error, EINVAL, "Invalid argument (%p %p %p %p)",
			attr_handle, domain, attrname, result);
		return FALSE;
	}

	memset(attr_name_buf, '\0', sizeof(attr_name_buf));
	g_snprintf(attr_name_buf, sizeof(attr_name_buf), "%s.%s", domain, attrname);

	value = g_hash_table_lookup(attr_handle->attr_hash, attr_name_buf);

	if (value)
		*result = g_strdup(value);
	else {
		if(!opt)
			INFO("Attribute [%s] not found for chunk [%s]",
					attr_name_buf, attr_handle->chunk_path);
		else
			DEBUG("Attribute [%s] not found for chunk [%s]",
					attr_name_buf, attr_handle->chunk_path);
		*result = NULL;
	}
	return TRUE;
}


/**
 Set attribute in attr_handle

 @param attr_handle the attr_handle to set the attribute in
 @param error
 @param domain the attribute domain
 @param attrname the attribute name
 @param attrvalue the attribute value

 @return TRUE or FALSE if an error occured (error is set)
 */
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


/* --------------------------------------------------------------------------------------------------------------------------- */
gboolean
set_rawx_full_info_in_attr(const char *pathname, int filedes, GError ** error, struct content_textinfo_s * content,
    struct chunk_textinfo_s * chunk, char* compression_info, char* compressed_size)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (chunk->id && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_ID, chunk->id))
		goto error_set_attr;
	if (chunk->size
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_SIZE, chunk->size))
		goto error_set_attr;
	if (chunk->hash
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_HASH, chunk->hash))
		goto error_set_attr;
	if (chunk->position
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_POS, chunk->position))
		goto error_set_attr;
	if (chunk->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_METADATA, chunk->metadata))
		goto error_set_attr;

	if (content->path
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_PATH, content->path))
		goto error_set_attr;
	if (content->size
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_SIZE, content->size))
		goto error_set_attr;
	if (content->chunk_nb
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_NBCHUNK,
		content->chunk_nb))
		goto error_set_attr;
	if (content->container_id
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_CONTAINER,
		content->container_id))
		goto error_set_attr;
	if (content->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA,
		content->metadata))
		goto error_set_attr;
	if (content->system_metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA_SYS,
		content->system_metadata))
		goto error_set_attr;

	/* Compression info */
	if(compressed_size && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_COMPRESSED_SIZE,
		compressed_size))
		goto error_set_attr;

	if(compression_info && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_METADATA_COMPRESS,
		compression_info))
		goto error_set_attr;

	if (!_commit_v2_attr_handle(filedes, attr_handle, &local_error)) {
		SETERROR(error, "Could not write all the attributes on disk : %s", local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_set_attr:
	SETERROR(error, "Failed to set attr in handle : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
set_rawx_info_in_attr(const char *pathname, GError ** error, struct content_textinfo_s * content,
    struct chunk_textinfo_s * chunk)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (chunk->id && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_ID, chunk->id))
		goto error_set_attr;
	if (chunk->size
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_SIZE, chunk->size))
		goto error_set_attr;
	if (chunk->hash
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_HASH, chunk->hash))
		goto error_set_attr;
	if (chunk->position
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_POS, chunk->position))
		goto error_set_attr;
	if (chunk->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_METADATA, chunk->metadata))
		goto error_set_attr;

	if (content->path
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_PATH, content->path))
		goto error_set_attr;
	if (content->size
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_SIZE, content->size))
		goto error_set_attr;
	if (content->chunk_nb
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_NBCHUNK,
		content->chunk_nb))
		goto error_set_attr;
	if (content->container_id
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_CONTAINER,
		content->container_id))
		goto error_set_attr;
	if (content->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA,
		content->metadata))
		goto error_set_attr;
	if (content->system_metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA_SYS,
		content->system_metadata))
		goto error_set_attr;

	if (!_commit_attr_handle(attr_handle, &local_error)) {
		SETERROR(error, "Could not write all the attributes on disk : %s", local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_set_attr:
	SETERROR(error, "Failed to set attr in handle : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
set_chunk_info_in_attr(const char *pathname, GError ** error, struct chunk_textinfo_s * cti)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_ID, cti->id))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_PATH, cti->path))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_SIZE, cti->size))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_HASH, cti->hash))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_POS, cti->position))
		goto error_set_attr;
	if (cti->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_METADATA, cti->metadata))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_CONTAINER, cti->container_id))
		goto error_set_attr;

	if (!_commit_attr_handle(attr_handle, &local_error)) {
		SETERROR(error, "Could not write all the attributes on disk : %s", local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_set_attr:
	SETERROR(error, "Failed to set attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
set_content_info_in_attr(const char *pathname, GError ** error, struct content_textinfo_s * cti)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERRCODE(error, local_error->code, "Failed to init the attribute management context : %s",
			local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_PATH, cti->path))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_SIZE, cti->size))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_NBCHUNK, cti->chunk_nb))
		goto error_set_attr;
	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_CONTAINER,
		cti->container_id))
		goto error_set_attr;
	if (cti->metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA, cti->metadata))
		goto error_set_attr;
	if (cti->system_metadata
	    && !_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CONTENT_METADATA_SYS,
		cti->system_metadata))
		goto error_set_attr;

	if (!_commit_attr_handle(attr_handle, &local_error)) {
		SETERRCODE(error, local_error->code, "Could not write all the attributes on disk : %s",
			local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_set_attr:
	SETERRCODE(error, local_error->code, "Failed to set attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
set_compression_info_in_attr(const char *pathname, GError ** error, gchar * metadata_compress)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if(!metadata_compress) {
		SETERROR(error, "Empty compression metadata");
		g_clear_error(&local_error);
		return FALSE;
	}
	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_METADATA_COMPRESS, metadata_compress)){
		SETERROR(error, "Failed to add [%s : %s] in attributes context : %s", ATTR_NAME_CHUNK_METADATA_COMPRESS,
					 metadata_compress, local_error->message);
		g_clear_error(&local_error);
		goto error_set_attr;
	}

	if (!_commit_attr_handle(attr_handle, &local_error)) {
		SETERRCODE(error, local_error->code, "Could not write all the attributes on disk : %s",
			local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}
	_clean_attr_handle(attr_handle, FALSE);
	return TRUE;

	error_set_attr:
		SETERRCODE(error, local_error->code, "Failed to set attr : %s", local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);

	return FALSE;

}

gboolean
set_chunk_compressed_size_in_attr(const char *pathname, GError ** error, guint32 compressed_size)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;
	gchar *size = NULL;
	size = g_malloc0(32);
	g_snprintf(size, 32, "%d", compressed_size);

	if (!_lazy_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s", local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_set_attr_in_handle(attr_handle, &local_error, ATTR_DOMAIN, ATTR_NAME_CHUNK_COMPRESSED_SIZE, size)){
		goto error_set_attr;
	}

	if (!_commit_attr_handle(attr_handle, &local_error)) {
		SETERRCODE(error, local_error->code, "Could not write all the attributes on disk : %s",
			local_error->message);
		g_clear_error(&local_error);
		g_free(size);
		_clean_attr_handle(attr_handle, FALSE);
		return FALSE;
	}

	_clean_attr_handle(attr_handle, FALSE);
	g_free(size);
	return TRUE;

	error_set_attr:
		SETERRCODE(error, local_error->code, "Failed to set attr : %s", local_error->message);
		g_clear_error(&local_error);
		_clean_attr_handle(attr_handle, FALSE);
		g_free(size);

	return FALSE;
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
	GError *local_error = NULL;

	if (!_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s",
				local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_PATH, &(content->path), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_SIZE, &(content->size), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_NBCHUNK, &(content->chunk_nb), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_CONTAINER, &(content->container_id), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_METADATA, &(content->metadata), TRUE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_METADATA_SYS,
				&(content->system_metadata), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_ID, &(chunk->id), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_SIZE, &(chunk->size), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_POS, &(chunk->position), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_HASH, &(chunk->hash), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_METADATA, &(chunk->metadata), TRUE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_PATH, &(chunk->path), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_CONTAINER, &(chunk->container_id), FALSE))
		goto error_get_attr;

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_get_attr:
	SETERROR(error, "Failed to get attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
get_content_info_in_attr(const char *pathname, GError ** error,
		struct content_textinfo_s * cti)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	if (!cti || !pathname) {
		SETERROR(error, "invalid parameter");
		return FALSE;
	}

	if (!_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s",
				local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_PATH, &(cti->path), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_SIZE, &(cti->size), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_NBCHUNK, &(cti->chunk_nb), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_CONTAINER, &(cti->container_id), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_METADATA, &(cti->metadata), TRUE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_METADATA_SYS, &(cti->system_metadata), FALSE))
		goto error_get_attr;

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_get_attr:
	SETERROR(error, "Failed to get attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
}

gboolean
get_chunk_info_in_attr(const char *pathname, GError ** error,
		struct chunk_textinfo_s * cti)
{
	struct attr_handle_s *attr_handle;
	GError *local_error = NULL;

	DEBUG("Getting chunk attributes...");

	if (!cti || !pathname) {
		SETERROR(error, "invalid parameter");
		return FALSE;
	}

	if (!_load_attr_from_file(pathname, &attr_handle, &local_error)) {
		SETERROR(error, "Failed to init the attribute management context : %s",
				local_error->message);
		g_clear_error(&local_error);
		return FALSE;
	}

	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_ID, &(cti->id), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_SIZE, &(cti->size), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_POS, &(cti->position), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_HASH, &(cti->hash), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CHUNK_METADATA, &(cti->metadata), TRUE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_CONTAINER, &(cti->container_id), FALSE))
		goto error_get_attr;
	if (!_get_attr_from_handle(attr_handle, &local_error, ATTR_DOMAIN,
				ATTR_NAME_CONTENT_PATH, &(cti->path), FALSE))
		goto error_get_attr;

	_clean_attr_handle(attr_handle, FALSE);

	return TRUE;

      error_get_attr:
	SETERROR(error, "Failed to get attr : %s", local_error->message);
	g_clear_error(&local_error);
	_clean_attr_handle(attr_handle, FALSE);

	return FALSE;
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

gboolean
rawx_get_lock_info(const char *vol,
	gchar *dst_host, gsize dst_host_size,
	gchar *dst_ns, gsize dst_ns_size, GError **gerr)
{
	ssize_t size;
	size_t usize;

	if (!vol || !dst_ns || !dst_host || !dst_host_size || !dst_ns_size) {
		SETERRCODE(gerr, EINVAL, "Invalid parameter");
		return FALSE;
	}

	bzero(dst_host, dst_host_size);
	bzero(dst_ns, dst_ns_size);

	switch (size = getxattr(vol, RAWXLOCK_ATTRNAME_URL, NULL, 0)) {
		case -1:
			if (errno != ENOATTR) {
				SETERRCODE(gerr, errno, "getxattr(%s) : %s", RAWXLOCK_ATTRNAME_URL, strerror(errno));
				return FALSE;
			}
			break;
		case 0:
			SETERRCODE(gerr, ENOTSUP, "getxattr(%s) : operation not supported", RAWXLOCK_ATTRNAME_URL);
			return FALSE;
		default:
			usize = size;
			if (usize > dst_host_size) {
				SETERRCODE(gerr, EINVAL, "getxattr(%s) : xattr value too long", RAWXLOCK_ATTRNAME_URL);
				return FALSE;
			}
			getxattr(vol, RAWXLOCK_ATTRNAME_URL, dst_host, dst_host_size);
			break;
	}

	switch (size = getxattr(vol, RAWXLOCK_ATTRNAME_NS, NULL, 0)) {
		case -1:
			if (errno != ENOATTR) {
				SETERRCODE(gerr, errno, "getxattr(%s) : %s", RAWXLOCK_ATTRNAME_NS, strerror(errno));
				return FALSE;
			}
			break;
		case 0:
			SETERRCODE(gerr, ENOTSUP, "getxattr(%s) : operation not supported", RAWXLOCK_ATTRNAME_NS);
			return FALSE;
		default:
			usize = size;
			if (usize > dst_ns_size) {
				SETERRCODE(gerr, EINVAL, "getxattr(%s) : xattr value too long", RAWXLOCK_ATTRNAME_URL);
				return FALSE;
			}
			getxattr(vol, RAWXLOCK_ATTRNAME_NS, dst_ns, dst_ns_size);
			break;
	}

	errno = 0;
	return TRUE;
}

int
rawx_lock_volume(const char *vol, const char *ns, const char *host, uint32_t flags, GError **err)
{
	int xattr_flags = (flags & RAWXLOCK_FLAG_OVERWRITE) ? 0 : XATTR_CREATE;

	if (0 > setxattr(vol, RAWXLOCK_ATTRNAME_URL, host, strlen(host), xattr_flags)) {
		if (errno == ENOTSUP) {
			SETERRCODE(err, ENOTSUP, "XATTR not supported on volume [%s], no lock set", vol);
			return 0;
		} else if (errno == EEXIST) {
			SETERRCODE(err, EEXIST, "URL already set");
			return 0;
		} else {
			SETERRCODE(err, errno, "setxattr error: [%s]", strerror(errno));
			return 0;
		}
	}

	if (0 > setxattr(vol, RAWXLOCK_ATTRNAME_NS, ns, strlen(ns), xattr_flags)) {
		if (errno==ENOTSUP) {
			SETERRCODE(err, ENOTSUP, "XATTR not supported on volume [%s], no lock set", vol);
			return 0;
		} else if (errno == EEXIST) {
			SETERRCODE(err, EEXIST, "Namespace already set");
			return 0;
		} else {
			SETERRCODE(err, errno, "setxattr error: [%s]", strerror(errno));
			return 0;
		}
	}

	return 1;
}

enum lock_state_e
rawx_get_volume_lock_state(const char *vol, const char *ns, const char *host, GError **err)
{
	gchar value_host[512], value_ns[512];

	memset(value_host, 0, sizeof(value_host));
	memset(value_ns, 0, sizeof(value_ns));

	if (!vol || !ns || !host) {
		SETERRCODE(err, EINVAL, "Invalid parameter");
		return ERROR_LS;
	}

	if (!rawx_get_lock_info(vol, value_host, sizeof(value_host), value_ns,
			sizeof(value_ns), err))
		return ERROR_LS;

	if (!*value_host && !*value_ns)
		return NOLOCK_LS;

	if (*value_host) {
		if (0 != g_ascii_strncasecmp(host, value_host, sizeof(value_host)))
			return OTHER_LS;
	}

	if (*value_ns) {
		if (0 != g_ascii_strncasecmp(ns, value_ns, sizeof(value_ns)))
			return OTHER_LS;
	}

	return OWN_LS;
}

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

#define REAL_TIME_BUF_SIZE 16
/* stamp a chunk */
void
stamp_a_chunk(const char *chunk_path, const char *attr_to_set){
	char attr_name_buf[ATTR_NAME_MAX_LENGTH];
	int real_time;
	char real_time_buf[REAL_TIME_BUF_SIZE];
	if (!attr_to_set)
		return;
	/* Concatenate the ATTR_DOMAIN and ATTR_NAME_CHUNK_LAST_SCANNED_TIME */
	memset(attr_name_buf, '\0', sizeof(attr_name_buf));
	snprintf(attr_name_buf, sizeof(attr_name_buf), "%s.%s", ATTR_DOMAIN, attr_to_set);
	/* get time and stamp it g_get_real_time is available since 2.28 */
	real_time = time((time_t *)NULL);
	snprintf(real_time_buf, REAL_TIME_BUF_SIZE, "%d", real_time);
	setxattr(chunk_path, attr_name_buf, real_time_buf, strlen(real_time_buf), 0);
}
