/**
 * @file broken_event.h
 */

#ifndef BROKEN_EVENT_H
#define BROKEN_EVENT_H

/**
 * @defgroup integrity_loop_lib_broken_event Broken events management
 * @ingroup integrity_loop_lib
 * @{
 */

#include <string.h>
#include <metautils/lib/metatypes.h>

/**
 * The list of chunk and content properties that can be checked by the integrity loop
 */
enum broken_property_e
{
	P_CONTAINER_ID =1,		/**< container id */
	P_CONTENT_NAME,		/**< content name */
	P_CONTENT_SIZE,		/**< content size */
	P_CONTENT_CHUNK_NB,	/**< content chunk nb */
	P_CONTENT_METADATA,	/**< content metadata */
	P_CONTENT_SYSMETADATA,	/**< content system metadata */
	P_CHUNK_ID,		/**< chunk id */
	P_CHUNK_SIZE,		/**< chunk size */
	P_CHUNK_HASH,		/**< chunk hash */
	P_CHUNK_POS,		/**< chunk position */
	P_CHUNK_METADATA	/**< chunk metadata */
};

/**
 * The list of broken reasons
 */
enum broken_reason_e
{
	R_MISSING,	/**< The element property is missing or null */
	R_MISMATCH,	/**< The element property doesn't have the same value as its reference */
	R_FORMAT	/**< The element property doesn't have the correct format */
};

extern const gchar * const reason_to_str[];

/**
 * The list of broken locations
 */
enum broken_location_e
{
	L_ALL,		/**< The element value mismatch, we can't decide were it's broken */
	L_CHUNK,	/**< The element was missing or badly formated in chunk attributes */
	L_META2		/**< The element was missing or badly formated in META2 */
};

extern const gchar * const loc_to_str[];

/**
 * A broken element
 */
struct broken_element_s
{
	container_id_t container_id;			/**< The container this element belongs to */
	gchar content_name[LIMIT_LENGTH_CONTENTPATH];	/**< The content this element belongs to */
	hash_sha256_t chunk_id;				/**< The chunk this element belongs to */
	enum broken_location_e location;		/**< The location of the broken element */
	enum broken_property_e property;		/**< The property broken in this element */
	enum broken_reason_e reason;			/**< The reason this property is broken */
	void * reference_value;				/**< The value the property should have if not broken */
};

/**
 * A broken event
 */
struct broken_event_s
{
	service_info_t service_info;			/**< The grid service this element refers to */
	GSList *broken_elements;			/**< A list of struct broken_element_s */
};

/**
 * Allocate a new struct broken_element_s
 *
 * @param container_id the container id this broken element belongs to
 * @param content_name the content name this broken element belongs to (or NULL if we don't know it)
 * @param chunk_id the chunk this broken element belongs to (or NULL if we don't know it)
 * @param location the location of this element
 * @param property the broken property
 * @param reason the broken reason
 * @param reference_value the value the property should have if not broken
 *
 * @return the newly allocated and filled broken_element
 */
struct broken_element_s *broken_element_alloc(const container_id_t container_id, const gchar * content_name,
    const hash_sha256_t chunk_id, enum broken_location_e location, enum broken_property_e property,
    enum broken_reason_e reason, void * reference_value);

/**
 * Allocate a new struct broken_element_s from infos in text format
 *
 * @param container_id the container id this broken element belongs to
 * @param content_name the content name this broken element belongs to (or NULL if we don't know it)
 * @param chunk_id the chunk this broken element belongs to (or NULL if we don't know it)
 * @param location the location of this element
 * @param property the broken property
 * @param reason the broken reason
 * @param reference_value the value the property should have if not broken
 *
 * @return the newly allocated and filled broken_element
 */
struct broken_element_s *broken_element_alloc2(const gchar * container_id, const gchar * content_name,
    const gchar * chunk_id, enum broken_location_e location, enum broken_property_e property,
    enum broken_reason_e reason, void * reference_value);

/**
 * Free the given struct broken_element_s (glib GList form)
 *
 * @param data the element to free
 * @param user_data unused (for glib compatibility)
 */
void broken_element_gfree(gpointer data, gpointer user_data);

/**
 * Free the given struct broken_element_s
 *
 * @param E the element to free
 */
void broken_element_free(gpointer e);

/** @} */

#endif /* BROKEN_EVENT_H */
