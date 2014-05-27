#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.chunk_repair"
#endif

#include <metautils/lib/metautils.h>
#include <rawx_client.h>

#include "chunk_repair_event_filter.h"
#include "event_filter.h"

#define RAWX_CONN_TIMEOUT 10
#define RAWX_REQ_TIMEOUT 10

gboolean
repair_chunk_attr(const struct broken_event_s *broken_event, void *data, GError **error)
{
	NOTICE("Starting repair_chunk_attr");
	struct info_s {
		struct content_textinfo_s content_info;
		struct chunk_textinfo_s chunk_info;
	};

	GSList * l1 = NULL;
	GHashTable * chunks = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	GHashTableIter chunk_iterator;

	TRACE("Running repair_chunk_attr filter");

	if (broken_event->broken_elements == NULL) {
		GSETERROR(error, "No broken elements in broken event");
		return FALSE;
	}

	for (l1 = broken_event->broken_elements; l1 && l1->data; l1 = l1->next) {
		struct broken_element_s * broken_element = (struct broken_element_s *)l1->data;
		struct info_s * infos = g_hash_table_lookup(chunks, broken_element->chunk_id);
		gchar * str_container_id = NULL;
		gchar * str_chunk_id = NULL;
		gchar * str_chunk_hash = NULL;
		
		if (infos == NULL) {
			infos = g_malloc0(sizeof(struct info_s));
			g_hash_table_insert(chunks,  broken_element->chunk_id, infos);
		}

		/** Check we are really handling a broken chunk attribute */
		if (broken_element->location != L_CHUNK)
			continue;

		/** Check we have some data usable for repair */
		if (broken_element->reference_value == NULL)
			continue;

		switch (broken_element->property) {
			case P_CONTAINER_ID:
				str_container_id = g_malloc0(sizeof(STRLEN_CONTAINERID));
				buffer2str(broken_element->reference_value, sizeof(container_id_t), str_container_id, sizeof(STRLEN_CONTAINERID));
				infos->content_info.container_id = str_container_id;
				infos->chunk_info.container_id = str_container_id;
				break;
			case P_CONTENT_NAME:
				infos->content_info.path = broken_element->reference_value;
				infos->chunk_info.path = broken_element->reference_value;
				break;
			case P_CONTENT_SIZE:
				infos->content_info.size = g_strdup_printf("%"G_GINT64_FORMAT, *(gint64*)(broken_element->reference_value)); 
				break;
			case P_CONTENT_CHUNK_NB:
				infos->content_info.chunk_nb = g_strdup_printf("%"G_GUINT32_FORMAT, *(guint32*)(broken_element->reference_value)); 
				break;
			case P_CONTENT_METADATA:
				infos->content_info.metadata = g_strdup(((GByteArray*)broken_element->reference_value)->data);
				break;
			case P_CONTENT_SYSMETADATA:
				infos->content_info.system_metadata = g_strdup(((GByteArray*)broken_element->reference_value)->data);
				break;
			case P_CHUNK_ID:
				str_chunk_id = g_malloc0(sizeof(hash_sha256_t));
				buffer2str(broken_element->reference_value, sizeof(hash_sha256_t), str_chunk_id, sizeof(STRLEN_CHUNKID));
				infos->chunk_info.id = str_chunk_id;
				break;
			case P_CHUNK_SIZE:
				NOTICE(" broken property identified as chunk size");
				NOTICE("broken_element->reference_value = %s",broken_element->reference_value);
				infos->chunk_info.size = g_strdup_printf("%"G_GINT64_FORMAT, *(gint64*)(broken_element->reference_value));
				break;
			case P_CHUNK_HASH:
				str_chunk_hash = g_malloc0(sizeof(hash_md5_t));
				buffer2str(broken_element->reference_value, sizeof(hash_md5_t), str_chunk_hash, sizeof(STRLEN_CHUNKHASH));
				infos->chunk_info.hash = str_chunk_hash;
				break;
			case P_CHUNK_POS:
				infos->chunk_info.position = g_strdup_printf("%"G_GUINT32_FORMAT, *(guint32*)(broken_element->reference_value));
				break;
			case P_CHUNK_METADATA:
				infos->chunk_info.metadata =  g_strdup(((GByteArray*)broken_element->reference_value)->data);
				break;
		}
	}

	gpointer key, value;
	g_hash_table_iter_init(&chunk_iterator, chunks);
	while (g_hash_table_iter_next(&chunk_iterator, &key, &value)) {
		struct info_s * info = value;
		gchar str_chunk_id[STRLEN_CHUNKID];

		memset(str_chunk_id, '\0', sizeof(str_chunk_id));

		NOTICE("Starting reparation of chunk attributes...");
		buffer2str(key, sizeof(hash_sha256_t), str_chunk_id, sizeof(str_chunk_id));
		DEBUG("Repairing attributes of chunk [%s]", str_chunk_id);

		/* Update attributes on remote chunk through RAWX */
		rawx_session_t * session = NULL;

		/* Create http session */
		session = rawx_client_create_session(&(broken_event->service_info.addr), error);
		if (session == NULL) {
			GSETERROR(error, "Failed to create HTTP session to access rawx");
			chunk_textinfo_free_content(&(info->chunk_info));
			content_textinfo_free_content(&(info->content_info));
			return FALSE;
		}

		rawx_client_session_set_timeout(session, RAWX_CONN_TIMEOUT, RAWX_REQ_TIMEOUT);

		if (!rawx_client_set_directory_data(session, key, &(info->content_info), &(info->chunk_info), error)) {
			NOTICE("Error in setting directory data");
			GSETERROR(error, "Failed to set directory data in rawx");
			rawx_client_free_session(session);
			return FALSE;
		}
		NOTICE("Job done, closing session");
		/* destroy session */
		rawx_client_free_session(session);
	}

	return TRUE;
}

gboolean
init_chunk_repair_event_filter(GError **error)
{
        struct broken_event_filter_s filter;

        memset(&filter, 0, sizeof(filter));

        filter.location = L_CHUNK;
        filter.property =
            P_CONTAINER_ID | P_CONTENT_NAME | P_CONTENT_SIZE | P_CONTENT_CHUNK_NB | P_CONTENT_METADATA |
            P_CONTENT_SYSMETADATA | P_CHUNK_ID | P_CHUNK_SIZE | P_CHUNK_HASH | P_CHUNK_POS | P_CHUNK_METADATA;
        filter.reason = R_MISSING | R_MISMATCH | R_FORMAT;

        if (!register_event_filter(&filter, repair_chunk_attr, NULL, error)) {
                GSETERROR(error, "Failed to register filter");
                return FALSE;
        }

        return TRUE;
}
