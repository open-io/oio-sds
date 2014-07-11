#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "rawx.client.directory_data"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>

#include <glib.h>

#include "rawx_client_internals.h"

static void
parse_chunkinfo_from_rawx(GHashTable *ht, struct content_textinfo_s *content,
    struct chunk_textinfo_s *chunk)
{
	GHashTableIter iterator;
	gpointer key, value;

	g_hash_table_iter_init(&iterator, ht);

	while (g_hash_table_iter_next(&iterator, &key, &value)) {
		DEBUG("key (%s) / value (%s)", (gchar*)key, (gchar*)value);
		if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CHUNK_ID, key))
			chunk->id = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CHUNK_SIZE, key))
			chunk->size = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CHUNK_HASH, key))
			chunk->hash = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CHUNK_POS, key))
			chunk->position = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CHUNK_METADATA, key))
			chunk->metadata = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_PATH, key)) {
			chunk->path = g_strdup(value);
			content->path = g_strdup(value);
		}
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_CONTAINER, key)) {
			chunk->container_id = g_strdup(value);
			content->container_id = g_strdup(value);
		}
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_SIZE, key))
			content->size = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_NBCHUNK, key))
			content->chunk_nb = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_METADATA, key))
			content->metadata = g_strdup(value);
		else if (0 == g_ascii_strcasecmp(RAWXATTR_NAME_CONTENT_METADATA_SYS, key))
			content->system_metadata = g_strdup(value);
	}
}

gboolean
rawx_client_get_directory_data(rawx_session_t * session, hash_sha256_t chunk_id, struct content_textinfo_s *content,
    struct chunk_textinfo_s *chunk, GError ** error)
{
	int rc;
	gchar str_addr[64];
	gsize str_addr_size;
	gchar str_req[2048];
	gchar str_chunk_id[(sizeof(hash_sha256_t) * 2) + 1];
	GHashTable *result = NULL;
	GByteArray *buffer = NULL;
	ne_request *request = NULL;

	if (!session) {
		GSETERROR(error, "Invalid parameter");
		return FALSE;
	}

	memset(str_chunk_id, '\0', sizeof(str_chunk_id));
	buffer2str(chunk_id, sizeof(hash_sha256_t), str_chunk_id, sizeof(str_chunk_id));

	memset(str_req, '\0', sizeof(str_req));
	snprintf(str_req, sizeof(str_req) - 1, "%s/%s", RAWX_REQ_GET_DIRINFO, str_chunk_id);

	ne_set_connect_timeout(session->neon_session, session->timeout.cnx / 1000);
	ne_set_read_timeout(session->neon_session, session->timeout.req / 1000);
	request = ne_request_create(session->neon_session, "GET", str_req);
	if (!request) {
		GSETERROR(error, "neon request creation error");
		return FALSE;
	}

	buffer = g_byte_array_new();
	ne_add_response_body_reader(request, ne_accept_2xx, body_reader, buffer);

	switch (rc = ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				GSETERROR(error, "RAWX returned an error %d : %s",
						ne_get_status(request)->code, ne_get_status(request)->reason_phrase);
				goto error;
			}
			else if (!(result = body_parser(buffer, error))) {
				GSETERROR(error, "No directory data from the RAWX server");
				goto error;
			}
			break;
		case NE_ERROR:
		case NE_TIMEOUT:
		case NE_CONNECT:
		case NE_AUTH:
			str_addr_size = addr_info_to_string(&(session->addr), str_addr, sizeof(str_addr));
			GSETERROR(error, "cannot download the data from [%.*s]' (%s)",
					str_addr_size, str_addr, ne_get_error(session->neon_session));
			goto error;
		default:
			GSETERROR(error, "Unexpected return code from the neon library : %d", rc);
			goto error;
	}

	g_byte_array_free(buffer, TRUE);
	ne_request_destroy(request);

	/* Fill the textinfo structs */
	parse_chunkinfo_from_rawx(result, content, chunk);
	g_hash_table_destroy(result);
	return TRUE;

error:
	g_byte_array_free(buffer, TRUE);
	ne_request_destroy(request);

	return FALSE;
}


gboolean
rawx_client_set_directory_data(rawx_session_t * session, hash_sha256_t chunk_id,
    struct content_textinfo_s * content, struct chunk_textinfo_s * chunk, GError ** error)
{
	(void) session;
	(void) chunk_id;
	(void) content;
	(void) chunk;
	(void) error;
	return TRUE;
}
