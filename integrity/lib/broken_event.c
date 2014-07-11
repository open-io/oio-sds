#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.broken_event"
#endif

#include <string.h>

#include <metautils/lib/metautils.h>

#include "./broken_event.h"

const gchar * const loc_to_str[] = {
	"chunk or meta2",
	"chunk",
	"meta2"
};

const gchar * const reason_to_str[] = {
	"missing",
	"mismatch",
	"bad format"
};


struct broken_element_s *
broken_element_alloc(const container_id_t container_id, const gchar * content_name, const hash_sha256_t chunk_id,
    enum broken_location_e location, enum broken_property_e property, enum broken_reason_e reason, void * reference_value)
{
	struct broken_element_s *element = NULL;

	element = g_try_new0(struct broken_element_s, 1);

	if (element != NULL) {
		memcpy(element->container_id, container_id, sizeof(container_id_t));
		memcpy(element->chunk_id, chunk_id, sizeof(hash_sha256_t));
		if (content_name != NULL)
			strncpy(element->content_name, content_name, sizeof(element->content_name) - 1);
		element->location = location;
		element->property = property;
		element->reason = reason;
		element->reference_value = reference_value;
	}

	return element;
}

struct broken_element_s *
broken_element_alloc2(const gchar * container_id, const gchar * content_name, const gchar * chunk_id,
    enum broken_location_e location, enum broken_property_e property, enum broken_reason_e reason, void * reference_value)
{
	GError *local_error = NULL;
	container_id_t raw_container_id;
	hash_sha256_t raw_chunk_id;

	memset(raw_container_id, 0, sizeof(container_id_t));
	memset(raw_chunk_id, 0, sizeof(hash_sha256_t));

	if (!hex2bin(container_id, raw_container_id, sizeof(container_id_t), &local_error)) {
		ERROR("Failed to convert container_id from hex [%s] to bin format : %s", container_id,
		    local_error->message);
		g_clear_error(&local_error);
		return NULL;
	}

	if (!hex2bin(chunk_id, raw_chunk_id, sizeof(hash_sha256_t), &local_error)) {
		ERROR("Failed to convert chunk_id from hex [%s] to bin format : %s", chunk_id, local_error->message);
		g_clear_error(&local_error);
		return NULL;
	}

	return broken_element_alloc(raw_container_id, content_name, raw_chunk_id, location, property, reason, reference_value);
}

void
broken_element_gfree(gpointer data, gpointer user_data)
{
	(void) user_data;
	broken_element_free(data);
}

void
broken_element_free(gpointer elem)
{
	struct broken_element_s *element = (struct broken_element_s *) elem;
	if (element)
		g_free(element->reference_value);
	g_free(element);
}
