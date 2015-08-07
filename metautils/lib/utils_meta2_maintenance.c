/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.meta2_maintenance"
#endif

#include <errno.h>

#include "metautils.h"

struct meta2_raw_content_s *
meta2_maintenance_create_content(const container_id_t container_id, gint64 size,
    guint32 nb_chunks, guint32 flags, const gchar * path, gsize path_len)
{
	if (!path || size < 0LL || path_len > LIMIT_LENGTH_CONTENTPATH)
		return NULL;
	struct meta2_raw_content_s *result = g_malloc0(sizeof(struct meta2_raw_content_s));
	memcpy(result->container_id, container_id, sizeof(container_id_t));
	memcpy(result->path, path, MIN(path_len, sizeof(result->path) - 1));
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
	g_slist_free_full(content->raw_chunks, (GDestroyNotify)meta2_raw_chunk_gclean);
	g_free0(content->storage_policy);
	if (content->metadata)
		g_byte_array_free(content->metadata, TRUE);
	if (content->system_metadata)
		g_byte_array_free(content->system_metadata, TRUE);
	g_free(content);
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

struct meta2_raw_chunk_s *
meta2_maintenance_create_chunk(const chunk_id_t * chunk_id, const chunk_hash_t hash,
    guint32 flags, gint64 size, guint32 position)
{
	struct meta2_raw_chunk_s *result = g_malloc0(sizeof(struct meta2_raw_chunk_s));
	memcpy(&(result->id), chunk_id, sizeof(chunk_id_t));
	memcpy(result->hash, hash, sizeof(chunk_hash_t));
	result->flags = flags;
	result->size = size;
	result->position = position;
	result->metadata = NULL;
	return result;
}

void
meta2_raw_chunk_clean(meta2_raw_chunk_t *chunk)
{
	if (chunk == NULL)
		return;
	if (chunk->metadata)
		g_byte_array_free(chunk->metadata, TRUE);
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

void
meta2_property_clean(meta2_property_t *prop)
{
	if (!prop)
		return;
	g_free0(prop->name);
	if (prop->value)
		g_byte_array_free(prop->value, TRUE);
	g_free(prop);
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
	if (!header)
		return ;
	if (header->metadata)
		g_byte_array_free(header->metadata, TRUE);
	if (header->system_metadata)
		g_byte_array_free(header->system_metadata, TRUE);
	g_free(header);
}

void meta2_raw_content_v2_clean(meta2_raw_content_v2_t *content)
{
	if (!content)
		return ;
	if (content->header.metadata)
		g_byte_array_free(content->header.metadata, TRUE);
	if (content->header.system_metadata)
		g_byte_array_free(content->header.system_metadata, TRUE);
	g_free0(content->header.policy);
	g_slist_free_full(content->raw_chunks, (GDestroyNotify)meta2_raw_chunk_clean);
	g_slist_free_full(content->raw_services, (GDestroyNotify)service_info_clean);
	g_slist_free_full(content->properties, (GDestroyNotify)meta2_property_clean);
	g_free(content);
}

void
meta2_raw_content_v2_gclean(gpointer p, gpointer ignored)
{
	(void) ignored;
	meta2_raw_content_v2_clean(p);
}

/* ------------------------------------------------------------------------- */

gchar*
meta2_raw_chunk_to_string(const meta2_raw_chunk_t *chunk)
{
	gchar str_id[STRLEN_CHUNKID], str_hash[STRLEN_CHUNKHASH];

	if (!chunk)
		return g_strdup("CHUNK[NULL]");

	chunk_id_to_string(&(chunk->id), str_id, sizeof(str_id));
	buffer2str(&(chunk->hash), sizeof(chunk->hash), &(str_hash[0]), sizeof(str_hash));

	return g_strdup_printf("CHUNK[%.*s|%.*s|%04x|%"G_GINT64_FORMAT"|%u|%"G_GSIZE_FORMAT"]",
			(int) sizeof(str_id), str_id,
			(int) sizeof(str_hash), str_hash,
			chunk->flags, chunk->size, chunk->position,
			metautils_gba_len(chunk->metadata));
}

/* ------------------------------------------------------------------------- */

meta2_raw_content_t*
meta2_raw_content_v2_get_v1(const meta2_raw_content_v2_t *v2, GError **err)
{
	GSList *l;

	if (!v2) {
		GSETCODE(err, ERRCODE_PARAM, "Invalid parameter");
		return NULL;
	}
	meta2_raw_content_t *v1 = g_malloc0(sizeof(*v1));

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
	if (!chunk)
		return NULL;
	meta2_raw_chunk_t *copy = g_malloc0(sizeof(*copy));
	memcpy(copy, chunk, sizeof(*copy));
	copy->metadata = metautils_gba_dup(chunk->metadata);
	return copy;
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
		gsize copied = g_strlcpy(raw_content->path, text_content->path, sizeof(raw_content->path));
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

