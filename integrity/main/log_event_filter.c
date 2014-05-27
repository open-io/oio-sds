#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.log_event_filter"
#endif

#include <metautils/lib/metautils.h>

#include "log_event_filter.h"
#include "event_filter.h"

static gchar *broken_property_str[] = {
	"container id",
	"content name",
	"content size",
	"content chunk nb",
	"content metadata",
	"content system metadata",
	"chunk id",
	"chunk size",
	"chunk hash",
	"chunk position",
	"chunk metadata"
};

static gchar *broken_location_str[] = {
	"in both chunk and META2",
	"in chunk",
	"in META2"
};

static gchar *broken_reason_str[] = {
	"is missing",
	"mismatch",
	"has a bad format"
};

/**
 * Compute a string path for a chunk broken event
 *
 * @param service_info the service_info hosting the chunk
 * @param broken_element the chunk broken element
 * @param chunk_path the string to fill with the computed string
 * @param chunk_path_size the chunk_path_size (including \0)
 * @param error
 *
 * @return TRUE or FALSE if an error occured
 */
static gboolean
_build_chunk_path(const service_info_t * service_info, const struct broken_element_s *broken_element,
    gchar * chunk_path, gsize chunk_path_size, GError ** error)
{
	struct service_tag_s *tag = NULL;
	gchar str_chunk_id[2 * sizeof(hash_sha256_t) + 1];
	gchar str_rawx_addr[256];
	gchar str_volume_path[LIMIT_LENGTH_VOLUMENAME];

	if (broken_element == NULL) {
		GSETERROR(error, "broken_element not found in event");
		return FALSE;
	}

	if (broken_element->chunk_id == NULL) {
		GSETERROR(error, "chunk_id not found in broken_element");
		return FALSE;
	}

	if (service_info == NULL) {
		GSETERROR(error, "service_info not found in event");
		return FALSE;
	}

	tag = service_info_get_tag(service_info->tags, NAME_TAGNAME_RAWX_VOL);
	if (tag == NULL) {
		GSETERROR(error, "Failed to retrieve tag [%s] from service_info", NAME_TAGNAME_RAWX_VOL);
		return FALSE;
	}

	memset(str_volume_path, '\0', sizeof(str_volume_path));

	if (!service_tag_get_value_string(tag, str_volume_path, LIMIT_LENGTH_VOLUMENAME - 1, error)) {
		GSETERROR(error, "Failed to extract string value from tag [%s]", NAME_TAGNAME_RAWX_VOL);
		return FALSE;
	}

	memset(str_chunk_id, '\0', sizeof(str_chunk_id));

	buffer2str(broken_element->chunk_id, sizeof(broken_element->chunk_id), str_chunk_id, sizeof(str_chunk_id) - 1);

	memset(str_rawx_addr, '\0', sizeof(str_rawx_addr));

	addr_info_to_string(&(service_info->addr), str_rawx_addr, sizeof(str_rawx_addr) - 1);

	snprintf(chunk_path, chunk_path_size - 1, "%s/%s@%s", str_volume_path, str_chunk_id, str_rawx_addr);

	return TRUE;
}

gboolean
log_broken_event(const struct broken_event_s * broken_event, void *domain, GError ** error)
{
	GSList *l1 = NULL;
	struct broken_element_s *broken_element = NULL;
	gchar str_chunk[2048];
	gchar str_container_id[2 * sizeof(container_id_t) + 1];

	TRACE("Executing log_broken_event");

	if (data_is_zeroed(&(broken_event->service_info), sizeof(service_info_t))) {
		GSETERROR(error, "The filtered broken event has no service_info");
		return FALSE;
	}

	for (l1 = broken_event->broken_elements; l1 && l1->data; l1 = l1->next) {
		broken_element = (struct broken_element_s *) l1->data;
		GError *local_error = NULL;

		if (broken_element == NULL) {
			ERROR("The filtered broken event has no broken_element");
			continue;
		}

		memset(str_container_id, '\0', sizeof(str_container_id));

		buffer2str(broken_element->container_id, sizeof(broken_element->container_id), str_container_id,
		    sizeof(str_container_id) - 1);

		if (!data_is_zeroed(broken_element->chunk_id, sizeof(hash_sha256_t))) {
			memset(str_chunk, '\0', sizeof(str_chunk));
			if (!_build_chunk_path(&(broken_event->service_info), broken_element, str_chunk,
				sizeof(str_chunk), &local_error)) {
				ERROR("Failed to build chunk path : %s", local_error->message);
				continue;
			}
			INFO_DOMAIN(domain, "The property [%s] in chunk [%s] of content [%s/%s/%s] %s %s",
			    broken_property_str[broken_element->property], str_chunk,
			    broken_event->service_info.ns_name, broken_element->content_name, str_container_id,
			    broken_reason_str[broken_element->reason], broken_location_str[broken_element->location]);
				NOTICE("log event filter info..\n");
		}
	}

	return TRUE;
}


gboolean
init_log_event_filter(const gchar * domain, GError ** error)
{
	struct broken_event_filter_s filter;

	memset(&filter, 0, sizeof(filter));

	filter.location = L_ALL | L_CHUNK | L_META2;
	filter.property =
	    P_CONTAINER_ID | P_CONTENT_NAME | P_CONTENT_SIZE | P_CONTENT_CHUNK_NB | P_CONTENT_METADATA |
	    P_CONTENT_SYSMETADATA | P_CHUNK_ID | P_CHUNK_SIZE | P_CHUNK_HASH | P_CHUNK_POS | P_CHUNK_METADATA;
	filter.reason = R_MISSING | R_MISMATCH | R_FORMAT;

	if (!register_event_filter(&filter, log_broken_event, g_strdup(domain), error)) {
		GSETERROR(error, "Failed to register filter");
		return FALSE;
	}

	return TRUE;
}
