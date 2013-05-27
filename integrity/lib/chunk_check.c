/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "integrity.lib.chunk_check"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include "check.h"

#include "chunk_check.h"
#include "broken_event.h"


/**
 * Compute the MD5 hash of a chunk file
 *
 * @param chunk_path the full path to the chunk file
 * @param chunk_hash the chunk_hash_t to fill with the computed hash
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
static gboolean
_compute_chunk_md5_hash(const gchar * chunk_path, chunk_hash_t chunk_hash, GError ** error)
{
	int fd;
	size_t len;
	ssize_t size_read;
	guint8 buffer[4096];
	GChecksum *md5_sum = NULL;

	memset(buffer, 0, sizeof(buffer));

	fd = open(chunk_path, O_RDONLY);
	if (fd == -1) {
		GSETERROR(error, "Failed to open chunk file [%s] for reading : %s", chunk_path, strerror(errno));
		return FALSE;
	}

	md5_sum = g_checksum_new(G_CHECKSUM_MD5);
	if (md5_sum == NULL) {
		GSETERROR(error, "GChecksum allocation failure");
		close(fd);
		return FALSE;
	}

	while (0 < (size_read = read(fd, buffer, sizeof(buffer)))) {
		g_checksum_update(md5_sum, buffer, size_read);
		memset(buffer, 0, sizeof(buffer));
	}

	close(fd);
	len = sizeof(chunk_hash_t);
	g_checksum_get_digest(md5_sum, chunk_hash, &len);
	g_checksum_free(md5_sum);

	if (size_read == -1) {
		GSETERROR(error, "Failed while reading chunk file [%s] : %s", chunk_path, strerror(errno));
		memset(chunk_hash, 0, sizeof(chunk_hash_t));
		return FALSE;
	}

	if (len != sizeof(chunk_hash_t)) {
		GSETERROR(error, "Chunk file content computed hash hash wrong size : %d instead of %d", len,
		    sizeof(chunk_hash_t));
		memset(chunk_hash, 0, sizeof(chunk_hash_t));
		return FALSE;
	}

	return TRUE;
}


gboolean
check_chunk_integrity(const char *chunk_path, const struct chunk_textinfo_s * text_chunk, GSList ** mismatch,
    GError ** error)
{
	GError *local_error = NULL;
	chunk_hash_t chunk_file_hash, chunk_attr_hash;
	gint64 chunk_attr_size;

	CHECK_ARG_POINTER(chunk_path, error);
	CHECK_ARG_POINTER(text_chunk, error);
	CHECK_ARG_VALID_FILE(chunk_path, error);


#define ADD_BRK_EL_TXT(L, P, R, V) \
do {\
	struct broken_element_s* brk_el; \
	brk_el = broken_element_alloc2(text_chunk->container_id, text_chunk->path, text_chunk->id, L, P, R, V); \
	if (brk_el != NULL) \
		*mismatch = g_slist_prepend(*mismatch, brk_el); \
	else { \
		GSETERROR(error, "Memory allocation failure"); \
		goto error; \
	} \
} while(0)

	/* See if we have a chunk_hash in attr */
	if (text_chunk->hash != NULL) {

		/* Compute chunk hash from file */
		if (!_compute_chunk_md5_hash(chunk_path, chunk_file_hash, error)) {
			GSETERROR(error, "Failed to compute MD5 hash of chunk file [%s]", chunk_path);
			goto error;
		}

		/* Convert attr chunk hash to bin */
		if (!hex2bin(text_chunk->hash, chunk_attr_hash, sizeof(chunk_hash_t), &local_error)) {
			WARN("Failed to convert chunk hash from hex [%s] to bin format : %s", text_chunk->hash,
			    local_error->message);
			g_clear_error(&local_error);
		}
		else if (0 != memcmp(chunk_file_hash, chunk_attr_hash, sizeof(chunk_hash_t)))
			ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_HASH, R_MISMATCH, g_memdup(chunk_attr_hash,
				sizeof(chunk_hash_t)));
	}

	/* See if we have a chunk size in attr */
	if (text_chunk->size != NULL) {
		struct stat file_stat;

		chunk_attr_size = g_ascii_strtoll(text_chunk->size, NULL, 10);

		/* Read chunk file size */
		memset(&file_stat, 0, sizeof(struct stat));
		if (-1 == stat(chunk_path, &file_stat)) {
			GSETERROR(error, "Failed to stat chunk file [%s] : %s", chunk_path, strerror(errno));
			goto error;
		}

		/* Compare chunk size */
		if (file_stat.st_size != chunk_attr_size){
			NOTICE("Chunk size mismatch, starting new broken event");
			ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&chunk_attr_size,
				sizeof(chunk_attr_size)));
		}
	}
	else {
		NOTICE("text_chunk size =NULL!...\n");
		ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&chunk_attr_size, sizeof(chunk_attr_size)));
	
	}
	return TRUE;

      error:
	if (*mismatch != NULL) {
		g_slist_foreach(*mismatch, broken_element_gfree, NULL);
		g_slist_free(*mismatch);
		*mismatch = NULL;
	}

	return FALSE;
}

gboolean
check_chunk_referencing(const struct content_textinfo_s * content_from_chunk,
    const struct chunk_textinfo_s * chunk_from_chunk, const struct meta2_raw_content_s * content_from_meta2,
    GSList ** broken, GError ** error)
{
	struct meta2_raw_chunk_s *chunk_from_meta2 = NULL;
	GError *local_error = NULL;

	CHECK_ARG_POINTER(content_from_chunk, error);
	CHECK_ARG_POINTER(chunk_from_chunk, error);
	CHECK_ARG_POINTER(content_from_meta2, error);
	CHECK_ARG_POINTER(content_from_meta2->raw_chunks, error);

#define ADD_BRK_EL_BIN(L, P, R, V) \
do {\
	struct broken_element_s* brk_el; \
	brk_el = broken_element_alloc(content_from_meta2->container_id, content_from_meta2->path, chunk_from_meta2->id.id, L, P, R, V); \
	if (brk_el != NULL) \
		*broken = g_slist_prepend(*broken, brk_el); \
	else { \
		GSETERROR(error, "Memory allocation failure"); \
		goto error; \
	} \
} while(0)

	if (g_slist_length(content_from_meta2->raw_chunks) == 0) {
		GSETERROR(error, "List of raw_chunk in content from META2 is emty");
		return FALSE;
	}

	chunk_from_meta2 = g_slist_nth_data(content_from_meta2->raw_chunks, 0);

	/* Check chunk hash */
	if (chunk_from_chunk->hash == NULL && !data_is_zeroed(chunk_from_meta2->hash, sizeof(chunk_hash_t))) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_HASH, R_MISSING, g_memdup(chunk_from_meta2->hash,
			sizeof(chunk_hash_t)));
	}
	else if (data_is_zeroed(chunk_from_meta2->hash, sizeof(chunk_hash_t)) && chunk_from_chunk->hash != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CHUNK_HASH, R_MISSING, NULL);
	}
	else {
		chunk_hash_t hash;

		if (!hex2bin(chunk_from_chunk->hash, hash, sizeof(chunk_hash_t), &local_error)) {
			WARN("Failed to convert chunk_hash from hex [%s] to bin : %s", chunk_from_chunk->hash,
			    local_error->message);
			g_clear_error(&local_error);
			ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_HASH, R_FORMAT, g_memdup(chunk_from_meta2->hash,
				sizeof(chunk_hash_t)));
		}
		else if (0 != memcmp(chunk_from_meta2->hash, hash, sizeof(chunk_hash_t)))
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_HASH, R_MISMATCH, g_memdup(chunk_from_meta2->hash,
				sizeof(chunk_hash_t)));
	}

	/* Check chunk id */
	if (chunk_from_chunk->id == NULL && !data_is_zeroed(chunk_from_meta2->id.id, sizeof(hash_sha256_t))) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_ID, R_MISSING, g_memdup(chunk_from_meta2->id.id,
			sizeof(hash_sha256_t)));
	}
	else if (data_is_zeroed(chunk_from_meta2->id.id, sizeof(hash_sha256_t)) && chunk_from_chunk->id != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CHUNK_ID, R_MISSING, NULL);
	}
	else {
		hash_sha256_t id;

		if (!hex2bin(chunk_from_chunk->id, id, sizeof(hash_sha256_t), &local_error)) {
			WARN("Failed to convert chunk_id from hex [%s] to bin : %s", chunk_from_chunk->id,
			    local_error->message);
			g_clear_error(&local_error);
			ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_ID, R_FORMAT, g_memdup(chunk_from_meta2->id.id,
				sizeof(hash_sha256_t)));
		}
		else if (0 != memcmp(chunk_from_meta2->id.id, id, sizeof(hash_sha256_t)))
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_ID, R_MISMATCH, g_memdup(chunk_from_meta2->id.id,
				sizeof(hash_sha256_t)));
	}

	/* Check chunk size */
	if (chunk_from_chunk->size == NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_SIZE, R_MISSING, g_memdup(&(chunk_from_meta2->size),
			sizeof(chunk_from_meta2->size)));
	}
	else {
		NOTICE("chunk_size broken but not report..\n");
		gint64 size = g_ascii_strtoll(chunk_from_chunk->size, NULL, 10);

		if (size != chunk_from_meta2->size)
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&(chunk_from_meta2->size),
				sizeof(chunk_from_meta2->size)));
	}

	/* Check chunk position */
	if (chunk_from_chunk->position == NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_POS, R_MISSING, g_memdup(&(chunk_from_meta2->position),
			sizeof(chunk_from_meta2->position)));
	}
	else {
		guint32 position = atoi(chunk_from_chunk->position);

		if (position != chunk_from_meta2->position)
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_POS, R_MISMATCH, g_memdup(&(chunk_from_meta2->position),
				sizeof(chunk_from_meta2->position)));
	}

	/* Check content name */
	if (content_from_chunk->path == NULL
	    && !data_is_zeroed(content_from_meta2->path, sizeof(content_from_meta2->path))) {
		NOTICE("chunk_check: path null..\n");
		ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_NAME, R_MISSING, g_strdup(content_from_meta2->path));
	}
	else if (data_is_zeroed(content_from_meta2->path, sizeof(content_from_meta2->path))
	    && content_from_chunk->path != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CONTENT_NAME, R_MISSING, g_strdup(content_from_chunk->path));
	}
	else if (strncmp(content_from_chunk->path, content_from_meta2->path, LIMIT_LENGTH_CONTENTPATH)) {
		ADD_BRK_EL_BIN(L_ALL, P_CONTENT_NAME, R_MISMATCH, g_strdup(content_from_meta2->path));
	}

	/* Check content system metadata */
	if (content_from_chunk->system_metadata == NULL && content_from_meta2->system_metadata != NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_SYSMETADATA, R_MISSING,
		    g_memdup(content_from_meta2->system_metadata->data, content_from_meta2->system_metadata->len));
	}
	else if ((content_from_meta2->system_metadata == NULL || content_from_meta2->system_metadata->len == 0)
	    && content_from_chunk->system_metadata != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CONTENT_SYSMETADATA, R_MISSING, g_byte_array_append(g_byte_array_new(),
			(guint8*)content_from_chunk->system_metadata, strlen(content_from_chunk->system_metadata) + 1));
	}
	else {
		gchar metadata[content_from_meta2->system_metadata->len + 1];

		memset(metadata, '\0', sizeof(metadata));
		memcpy(metadata, content_from_meta2->system_metadata->data, sizeof(metadata) - 1);

		if (0 != strcmp(content_from_chunk->system_metadata, metadata))
			ADD_BRK_EL_BIN(L_ALL, P_CONTENT_SYSMETADATA, R_MISMATCH,
			    g_memdup(content_from_meta2->system_metadata->data,
				content_from_meta2->system_metadata->len));
	}

	/* Check properties on chunk with position 0 */
	if (chunk_from_chunk->position != NULL && 0 == atoi(chunk_from_chunk->position)) {

		/* Check content nb chunk */
		if (content_from_chunk->chunk_nb == NULL) {
			ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_CHUNK_NB, R_MISSING,
			    g_memdup(&(content_from_meta2->nb_chunks), sizeof(content_from_meta2->nb_chunks)));
		}
		else {
			guint32 nb_chunk = atoi(content_from_chunk->chunk_nb);

			if (nb_chunk != content_from_meta2->nb_chunks)
				ADD_BRK_EL_BIN(L_ALL, P_CONTENT_CHUNK_NB, R_MISMATCH,
				    g_memdup(&(content_from_meta2->nb_chunks), sizeof(content_from_meta2->nb_chunks)));
		}

		/* Check content size */
		if (content_from_chunk->size == NULL) {
			ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_SIZE, R_MISSING, g_memdup(&(content_from_meta2->size),
				sizeof(content_from_meta2->size)));
		}
		else {
			gint64 size = g_ascii_strtoll(content_from_chunk->size, NULL, 10);

			if (size != content_from_meta2->size)
				ADD_BRK_EL_BIN(L_ALL, P_CONTENT_SIZE, R_MISMATCH, g_memdup(&(content_from_meta2->size),
					sizeof(content_from_meta2->size)));
		}
	}

	return TRUE;

      error:
	if (*broken != NULL) {
		g_slist_foreach(*broken, broken_element_gfree, NULL);
		g_slist_free(*broken);
		*broken = NULL;
	}

	return FALSE;
}
