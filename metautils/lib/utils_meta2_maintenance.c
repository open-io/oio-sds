#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.meta2_maintenance"
#endif

#include <errno.h>

#include "metautils.h"

struct meta2_raw_content_s *
meta2_maintenance_create_content(const container_id_t container_id, gint64 size,
    guint32 nb_chunks, guint32 flags, const gchar * path, gsize path_len)
{
	struct meta2_raw_content_s *result = NULL;

	if (!path || size < 0LL || path_len > LIMIT_LENGTH_CONTENTPATH)
		return NULL;

	result = g_try_malloc0(sizeof(struct meta2_raw_content_s));
	if (!result)
		return NULL;

	g_memmove(result->container_id, container_id, sizeof(container_id_t));
	g_memmove(result->path, path, MIN(path_len, sizeof(result->path) - 1));

	result->nb_chunks = nb_chunks;
	result->flags = flags;
	result->size = size;
	result->raw_chunks = NULL;
	result->metadata = NULL;
	result->system_metadata = NULL;

	return result;
}

void
meta2_raw_content_clean(meta2_raw_content_t *content)
{
	if (!content)
		return;

	if (content->raw_chunks) {
		g_slist_foreach(content->raw_chunks, meta2_raw_chunk_gclean, NULL);
		g_slist_free(content->raw_chunks);
	}

	if (content->metadata)
		g_byte_array_free(content->metadata, TRUE);

	if (content->system_metadata)
		g_byte_array_free(content->system_metadata, TRUE);

	if (content->storage_policy)
		g_free(content->storage_policy);

	bzero(content, sizeof(meta2_raw_content_t));
	g_free(content);
}

void
meta2_raw_content_gclean(gpointer p, gpointer ignored)
{
	(void) ignored;
	meta2_raw_content_clean(p);
}

void
meta2_maintenance_destroy_content(struct meta2_raw_content_s *content)
{
	meta2_raw_content_clean(content);
}

void
meta2_maintenance_add_chunk(struct meta2_raw_content_s *content, const struct meta2_raw_chunk_s *chunk)
{
	struct meta2_raw_chunk_s *copy = NULL;

	if (!content || !chunk)
		return;
	/*copy the chunk */
	copy = g_memdup(chunk, sizeof(struct meta2_raw_chunk_s));
	if (!copy)
		return;
	if (chunk->metadata && chunk->metadata->len > 0 && chunk->metadata->data) {
		copy->metadata = g_byte_array_sized_new(chunk->metadata->len);
		copy->metadata = g_byte_array_append(copy->metadata, chunk->metadata->data, chunk->metadata->len);
	} else {
		copy->metadata = g_byte_array_new();
	}
	/*add the chunk to the content */
	content->raw_chunks = g_slist_prepend(content->raw_chunks, copy);
}


void
meta2_maintenance_increment_chunks_count(struct meta2_raw_content_s *content)
{
	if (!content)
		return;
	content->nb_chunks++;
}

struct meta2_raw_chunk_s *
meta2_maintenance_create_chunk(const chunk_id_t * chunk_id, const chunk_hash_t hash,
    guint32 flags, gint64 size, guint32 position)
{
	struct meta2_raw_chunk_s *result = NULL;

	result = g_try_new0(struct meta2_raw_chunk_s, 1);

	if (result != NULL) {
		memcpy(&(result->id), chunk_id, sizeof(chunk_id_t));
		memcpy(result->hash, hash, sizeof(chunk_hash_t));
		result->flags = flags;
		result->size = size;
		result->position = position;
		result->metadata = NULL;
	}

	return result;
}

void
meta2_raw_chunk_clean(meta2_raw_chunk_t *chunk)
{
	if (chunk == NULL)
		return;
	if (chunk->metadata)
		g_byte_array_free(chunk->metadata, TRUE);
	bzero(chunk, sizeof(meta2_raw_chunk_t));
	g_free(chunk);
}

void
meta2_raw_chunk_gclean(gpointer p, gpointer ignored)
{
	(void) ignored;
	meta2_maintenance_destroy_chunk(p);
}

/**
	Destroy the given raw chunk
 */
void
meta2_maintenance_destroy_chunk(struct meta2_raw_chunk_s *chunk)
{
	meta2_raw_chunk_clean(chunk);
}

/**
	Glib compatible raw chunk cleaner
 */
void
meta2_maintenance_chunk_gclean(gpointer p1, gpointer p2)
{
	struct meta2_raw_chunk_s *chunk = p1;

	(void) p2;

	meta2_maintenance_destroy_chunk(chunk);
}

#ifdef HAVE_UNUSED_CODE
static gchar *
_metadata_to_str(GByteArray * metadata)
{
#define NULL_STR "null"

	gchar *str = NULL;

	if (metadata == NULL) {
		str = g_try_malloc0(1 + sizeof(NULL_STR));
		strncpy(str, NULL_STR, sizeof(NULL_STR));
	}
	else {
		str = g_try_malloc0(1 + metadata->len);
		memcpy(str, metadata->data, metadata->len);
	}

	return str;
}

/**
 * Diff the two given raw chunks field by field
 *
 * @param mismatch a list filled with mismatch fields
 *
 * @return TRUE or FALSE if we found a field mismatch
 */
gboolean
meta2_maintenance_diff_chunks(struct meta2_raw_chunk_s * chunk1, struct meta2_raw_chunk_s * chunk2, GSList ** mismatch,
    GError ** error)
{
	gboolean result = TRUE;

	/* cmp id */
	if (0 != memcmp(&(chunk1->id), &(chunk2->id), sizeof(chunk_id_t))) {
		gchar id1[sizeof(chunk_id_t) * 2 + 1], id2[sizeof(chunk_id_t) * 2 + 1];

		memset(id1, '\0', sizeof(id1));
		chunk_id_to_string(&(chunk1->id), id1, sizeof(id1));
		memset(id2, '\0', sizeof(id2));
		chunk_id_to_string(&(chunk2->id), id2, sizeof(id2));

		GSETERROR(error, "id mismatch : %s/%s", id1, id2);
		*mismatch = g_slist_prepend(*mismatch, "id");
		result = FALSE;
	}

	/* cmp hash */
	if (0 != memcmp(chunk1->hash, chunk2->hash, sizeof(chunk_hash_t))) {
		gchar hash1[sizeof(chunk_hash_t) * 2 + 1], hash2[sizeof(chunk_hash_t) * 2 + 1];

		memset(hash1, '\0', sizeof(hash1));
		buffer2str(chunk1->hash, sizeof(chunk_hash_t), hash1, sizeof(hash1));
		memset(hash2, '\0', sizeof(hash2));
		buffer2str(chunk2->hash, sizeof(chunk_hash_t), hash2, sizeof(hash2));

		GSETERROR(error, "hash mismatch : %s/%s", hash1, hash2);
		*mismatch = g_slist_prepend(*mismatch, "hash");
		result = FALSE;
	}

	/* cmp flags */
	if (chunk1->flags != chunk2->flags) {
		GSETERROR(error, "flags mismatch : %i/%i", chunk1->flags, chunk2->flags);
		*mismatch = g_slist_prepend(*mismatch, "flags");
		result = FALSE;
	}

	/* cmp size */
	if (chunk1->size != chunk2->size) {
		GSETERROR(error, "size mismatch : %lu/%lu", chunk1->size, chunk2->size);
		*mismatch = g_slist_prepend(*mismatch, "size");
		result = FALSE;
	}

	/* cmp position */
	if (chunk1->position != chunk2->position) {
		GSETERROR(error, "position mismatch : %i/%i", chunk1->position, chunk2->position);
		*mismatch = g_slist_prepend(*mismatch, "position");
		result = FALSE;
	}

	/* cmp metadata */
	if (((chunk1->metadata == NULL && chunk2->metadata != NULL)
		|| (chunk1->metadata != NULL && chunk2->metadata == NULL))
	    || ((chunk1->metadata != NULL && chunk2->metadata != NULL)
		&& (chunk1->metadata->len != chunk2->metadata->len
		    || 0 != memcmp(chunk1->metadata->data, chunk2->metadata->data, chunk1->metadata->len)))) {

		gchar *mdata1, *mdata2;

		mdata1 = _metadata_to_str(chunk1->metadata);
		mdata2 = _metadata_to_str(chunk2->metadata);

		GSETERROR(error, "metadata mismatch : %s/%s", mdata1, mdata2);
		*mismatch = g_slist_prepend(*mismatch, "metadata");
		result = FALSE;

		g_free(mdata1);
		g_free(mdata2);
	}

	return result;
}
#endif /* HAVE_UNUSED_CODE */


void
meta2_property_clean(meta2_property_t *prop)
{
	if (!prop) {
		errno = EINVAL;
		return;
	}

	if (prop->name)
		g_free(prop->name);
	if (prop->value)
		g_byte_array_free(prop->value, TRUE);
	bzero(prop, sizeof(*prop));
	g_free(prop);
	errno = 0;
}

void
meta2_property_gclean(gpointer prop, gpointer ignored)
{
	(void) ignored;
	meta2_property_clean(prop);
}

void
meta2_raw_content_header_clean(meta2_raw_content_header_t *header)
{
	if (!header) {
		errno = EINVAL;
		return ;
	}

	if (header->metadata)
		g_byte_array_free(header->metadata, TRUE);
	if (header->system_metadata)
		g_byte_array_free(header->system_metadata, TRUE);

	bzero(header, sizeof(meta2_raw_content_header_t));
	g_free(header);
	errno = 0;
}

void
meta2_raw_content_header_gclean(gpointer p, gpointer ignored)
{
	(void) ignored;
	meta2_raw_content_header_clean(p);
}

void meta2_raw_content_v2_clean(meta2_raw_content_v2_t *content)
{
	if (!content) {
		errno = EINVAL;
		return ;
	}

	if (content->header.metadata)
		g_byte_array_free(content->header.metadata, TRUE);
	if (content->header.system_metadata)
		g_byte_array_free(content->header.system_metadata, TRUE);
	if (content->header.policy)
		g_free(content->header.policy);

	if (content->raw_chunks) {
		g_slist_foreach(content->raw_chunks, meta2_raw_chunk_gclean, NULL);
		g_slist_free(content->raw_chunks);
	}

	if (content->raw_services) {
		g_slist_foreach(content->raw_services, service_info_gclean, NULL);
		g_slist_free(content->raw_services);
	}

	if (content->properties) {
		g_slist_foreach(content->properties, meta2_property_gclean, NULL);
		g_slist_free(content->properties);
	}

	bzero(content, sizeof(meta2_raw_content_v2_t));
	g_free(content);
	errno = 0;
}

void
meta2_raw_content_v2_gclean(gpointer p, gpointer ignored)
{
	(void) ignored;
	meta2_raw_content_v2_clean(p);
}

/* ------------------------------------------------------------------------- */

gchar*
meta2_raw_content_header_to_string(const meta2_raw_content_header_t *header)
{
	gchar str_cid[STRLEN_CONTAINERID];

	if (!header)
		return g_strdup("CONTENT_HEADER[NULL]");

	container_id_to_string(header->container_id, str_cid, sizeof(str_cid));
	return g_strdup_printf("CONTENT_HEADER[%.*s|%.*s|%04x|%u|%"G_GINT64_FORMAT"|%"G_GSIZE_FORMAT"|%"G_GSIZE_FORMAT"|%s]",
		(int) sizeof(str_cid), str_cid,
		(int) sizeof(header->path), header->path,
		header->flags, header->nb_chunks,
		header->size,
		metautils_gba_len(header->metadata), metautils_gba_len(header->system_metadata),
		header->policy ? header->policy : "none");
}

gchar*
meta2_raw_chunk_to_string(const meta2_raw_chunk_t *chunk)
{
	gchar str_id[STRLEN_CHUNKID+1], str_hash[STRLEN_CHUNKHASH+1];

	if (!chunk)
		return g_strdup("CHUNK[NULL]");

	bzero(str_id, sizeof(str_id));
	chunk_id_to_string(&(chunk->id), str_id, sizeof(str_id)-1);

	bzero(str_hash, sizeof(str_hash));
	buffer2str(&(chunk->hash), sizeof(chunk->hash), &(str_hash[0]), sizeof(str_hash)-1);

	return g_strdup_printf("CHUNK[%.*s|%.*s|%04x|%"G_GINT64_FORMAT"|%u|%"G_GSIZE_FORMAT"]",
		(int) sizeof(str_id), str_id,
		(int) sizeof(str_hash), str_hash,
		chunk->flags, chunk->size, chunk->position,
		metautils_gba_len(chunk->metadata));
}

gchar*
meta2_property_to_string(const meta2_property_t *prop)
{
	gchar str_data[128];

	if (!prop)
		return g_strdup("PROP[NULL]");

	bzero(str_data, sizeof(str_data));
	metautils_gba_data_to_string(prop->value, str_data, sizeof(str_data)-1);

	return g_strdup_printf("PROP[%s|%"G_GSIZE_FORMAT":%s]",
			prop->name, metautils_gba_len(prop->value), str_data);
}

gchar*
meta2_raw_content_v2_to_string(const meta2_raw_content_v2_t *content)
{
	gchar *result = NULL, **tab = NULL;
	gsize tab_max = 0, tab_count = 0;
	GSList *l;

	void _concat(gchar *s) {
		if (!s)
			return;
		if (tab_count >= tab_max) {
			tab_max += 4;
			tab = g_realloc(tab, sizeof(gchar*) * (tab_max+1));
		}
		tab[tab_count ++] = s;
		tab[tab_count] = NULL;
	}

	tab_max = 12;
	tab_count = 0;
	tab = g_malloc0(sizeof(gchar*) * (tab_max+1));

	_concat(g_strdup("CONTENT["));
	_concat(meta2_raw_content_header_to_string(&(content->header)));

	_concat(g_strdup("CHUNKS["));
	for (l=content->raw_chunks; l ;l=l->next)
		_concat(meta2_raw_chunk_to_string(l->data));
	_concat(g_strdup("]"));

	_concat(g_strdup("PROPERTIES["));
	for (l=content->properties; l ;l=l->next)
		_concat(meta2_property_to_string(l->data));
	_concat(g_strdup("]"));

	_concat(g_strdup("]"));

	result = g_strjoinv(";",tab);
	g_strfreev(tab);
	return result;
}

gint
meta2_raw_chunk_cmp(const meta2_raw_chunk_t *r1, const meta2_raw_chunk_t *r2)
{
	meta2_raw_chunk_t c1, c2;
	int i_cmp;

	if (r1 == r2)
		return 0;
	if (!r1 && r2)
		return 1;
	if (r1 && !r2)
		return -1;

	memcpy(&c1, r1, sizeof(c1));
	c1.metadata = NULL;
	memcpy(&c2, r2, sizeof(c2));
	c2.metadata = NULL;

	return (i_cmp = memcmp(&c1, &c2, sizeof(meta2_raw_chunk_t)))
		? i_cmp : metautils_gba_cmp(r1->metadata, r2->metadata);
}

gint
meta2_property_cmp(const meta2_property_t *p1, const meta2_property_t *p2)
{
	int i_cmp;
	if (p1 == p2)
		return 0;
	if (!p1 && p2)
		return 1;
	if (p1 && !p2)
		return -1;

	if (!p1->name && p2->name)
		return 1;
	if (p1->name && !p2->name)
		return -1;
	return (i_cmp = strcmp(p1->name, p2->name)) ? i_cmp : metautils_gba_cmp(p1->value, p2->value);
}

gint
meta2_raw_content_header_cmp(const meta2_raw_content_header_t *r1, const meta2_raw_content_header_t *r2)
{
	meta2_raw_content_header_t c1, c2;
	int i_cmp;

	if (r1 == r2)
		return 0;
	if (!r1 && r2)
		return 1;
	if (r1 && !r2)
		return -1;

	memcpy(&c1, r1, sizeof(c1));
	c1.metadata = NULL;
	c1.system_metadata = NULL;
	memcpy(&c2, r2, sizeof(c2));
	c2.metadata = NULL;
	c2.system_metadata = NULL;

	if (0 != (i_cmp = memcmp(&c1, &c2, sizeof(c1))))
		return i_cmp;
	if (0 != (i_cmp = metautils_gba_cmp(r1->metadata, r2->metadata)))
		return i_cmp;
	if (0 != (i_cmp = metautils_gba_cmp(r1->system_metadata, r2->system_metadata)))
		return i_cmp;
	return 0;
}

/* ------------------------------------------------------------------------- */

meta2_raw_content_v2_t*
meta2_raw_content_v1_get_v2(meta2_raw_content_t *v1, GError **err)
{
	GSList *l;
	meta2_raw_content_v2_t *v2;

	if (!v1) {
		GSETCODE(err, 500+EINVAL, "Invalid parameter");
		return NULL;
	}
	if (!(v2 = g_try_malloc0(sizeof(*v2)))) {
		GSETCODE(err, 500+ENOMEM, "Memory allocation failure");
		return NULL;
	}

	/* Copy the header */
	memcpy(v2->header.container_id, v1->container_id, sizeof(container_id_t));
	g_strlcpy(v2->header.path, v1->path, sizeof(v2->header.path)-1);
	v2->header.flags = v1->flags;
	v2->header.nb_chunks = v1->nb_chunks;
	v2->header.size = v1->size;
	v2->header.version = v1->version;
	v2->header.deleted = v1->deleted;
	v2->header.metadata = metautils_gba_dup(v1->metadata);
	v2->header.system_metadata = metautils_gba_dup(v1->system_metadata);

	/* Copy the chunks */
	for (l=v1->raw_chunks; l ;l=l->next) {
		meta2_raw_chunk_t *chunk_copy = meta2_raw_chunk_dup(l->data);
		if (chunk_copy)
			v2->raw_chunks = g_slist_prepend(v2->raw_chunks, chunk_copy);
	}
	v2->raw_chunks = g_slist_reverse(v2->raw_chunks);

	return v2;
}

meta2_raw_content_t*
meta2_raw_content_v2_get_v1(const meta2_raw_content_v2_t *v2, GError **err)
{
	meta2_raw_content_t *v1 = NULL;
	GSList *l;

	if (!v2) {
		GSETCODE(err, 500+EINVAL, "Invalid parameter");
		return NULL;
	}
	if (!(v1 = g_try_malloc0(sizeof(*v1)))) {
		GSETCODE(err, 500+ENOMEM, "Memory allocation failure");
		return NULL;
	}

	/* Copy the header */
	memcpy(v1->container_id, v2->header.container_id, sizeof(container_id_t));
	g_strlcpy(v1->path, v2->header.path, sizeof(v1->path)-1);
	v1->flags = v2->header.flags;
	v1->nb_chunks = v2->header.nb_chunks;
	v1->size = v2->header.size;
	v1->metadata = metautils_gba_dup(v2->header.metadata);
	v1->system_metadata = metautils_gba_dup(v2->header.system_metadata);
	v1->storage_policy = g_strdup(v2->header.policy);
	v1->version = v2->header.version;
	v1->deleted = v2->header.deleted;

	/* Copy the chunks */
	for (l=v2->raw_chunks; l ;l=l->next) {
		meta2_raw_chunk_t *chunk_copy = meta2_raw_chunk_dup(l->data);
		if (chunk_copy)
			v1->raw_chunks = g_slist_prepend(v1->raw_chunks, chunk_copy);
	}
	v1->raw_chunks = g_slist_reverse(v1->raw_chunks);

	return v1;
}

meta2_raw_chunk_t*
meta2_raw_chunk_dup(meta2_raw_chunk_t *chunk)
{
	meta2_raw_chunk_t *copy;
	if (!chunk)
		return NULL;
	if (!(copy = g_try_malloc0(sizeof(*copy))))
		return NULL;
	g_memmove(copy, chunk, sizeof(*copy));
	copy->metadata = metautils_gba_dup(chunk->metadata);
	return copy;
}

meta2_property_t*
meta2_property_dup(meta2_property_t *prop_orig)
{
	meta2_property_t *prop_copy;

	if (!prop_orig)
		return NULL;

	if (!(prop_copy = g_try_malloc0(sizeof(*prop_copy))))
		return NULL;

	prop_copy->name = g_strdup(prop_orig->name);
	prop_copy->version = prop_orig->version;
	prop_copy->value = metautils_gba_dup(prop_orig->value);
	return prop_copy;
}

gboolean
convert_content_text_to_raw(const struct content_textinfo_s* text_content,
	struct meta2_raw_content_s* raw_content, GError** error)
{
	if (!text_content || !raw_content) {
		GSETERROR(error, "Invalid parameter (%p %p)", text_content, raw_content);
		return FALSE;
	}

	if (text_content->container_id != NULL
		&& !hex2bin(text_content->container_id, &(raw_content->container_id), sizeof(container_id_t), error)) {
			GSETERROR(error, "Failed to convert container_id from hex to bin");
			return FALSE;
	}

	if (text_content->path != NULL) {
		gsize copied;
		bzero(raw_content->path, sizeof(raw_content->path));
		copied = g_strlcpy(raw_content->path, text_content->path, sizeof(raw_content->path)-1);
		if (copied >= sizeof(raw_content->path)) {
			GSETERROR(error, "Content path too long");
			return FALSE;
		}
	}
	if (text_content->version != NULL)
		raw_content->version = g_ascii_strtoll(text_content->version, NULL, 10);

	if (text_content->size != NULL)
		raw_content->size = g_ascii_strtoll(text_content->size, NULL, 10);

	if (text_content->chunk_nb != NULL)
		raw_content->nb_chunks = g_ascii_strtoull(text_content->chunk_nb, NULL, 10);

	if (text_content->metadata != NULL)
		raw_content->metadata = metautils_gba_from_string(text_content->metadata);

	if (text_content->system_metadata != NULL)
		raw_content->system_metadata = metautils_gba_from_string(text_content->system_metadata);

	return TRUE;
}

