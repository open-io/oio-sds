#ifndef __REDCURRANT_metatype_srvinfo__h
#define __REDCURRANT_metatype_srvinfo__h 1
#include <glib/gtypes.h>

/**
 * @defgroup metautils_srvinfo Generic Services
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a pretty string representation of the score.
 *
 * @param src
 * @param dst
 * @param dstsize
 *
 * @return the number of bytes writen in the given buffer
 */
gint score_to_string(const score_t * src, gchar * dst, gsize dstsize);


/**
 * Free a service_info_t pointer
 *
 * @param si the service_info_t pointer to free
 */
void service_info_clean(struct service_info_s *si);

void service_info_cleanv(struct service_info_s **siv, gboolean content_only);

/**
 * Same as service_info_clean() usable for g_slist_foreach()
 *
 * @param si the service_info_t pointer to free
 * @param unused
 */
void service_info_gclean(gpointer si, gpointer unused);


/**
 * Duplicate a service_info_t pointer
 *
 * @param si the service_info_t pointer to duplicate
 *
 * @return an allocated service_info_t duplicates of si or NULL if an error occured
 */
struct service_info_s *service_info_dup(const struct service_info_s *si);


/**
 * Copy a GPtrArray of service_tag_t
 *
 * @param original the GPtrArray to copy
 *
 * @return a new GPtrArray or NULL if an error occured
 */
GPtrArray *service_info_copy_tags(GPtrArray * original);


/**
 * Extract the list of all namespace names involved in a list of services
 *
 * @param services a list of service_info_t to exctract the namespace names from
 * @param copy set to TRUE if you want the names be duplicated
 *
 * @return a list of names or NULL if services was an empty list
 */
GSList* service_info_extract_nsname(GSList *services, gboolean copy);


/**
 * Frees a service_tag_t and all its internal data
 *
 * @param tag the service_tag_t to free
 */
void service_tag_destroy(struct service_tag_s *tag);


/**
 * Same as service_tag_destroy() usable for g_slist_foreach()
 *
 * @param tag the service_tag_t to free
 * @param unused
 */
void service_tag_gclean(gpointer tag, gpointer unused);


/**
 * Set a service_tag_t string value
 *
 * @param tag the service_tag_t to set the value in
 * @param s the string value (duplicated inside)
 */
void service_tag_set_value_string(struct service_tag_s *tag, const gchar *s);


/**
 * Get a service_tag_t string value
 *
 * @param tag the service_tag_t to get the value from
 * @param s a pointer to a string to fill with the result
 * @param s_size the size of s string
 * @param error;
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_string(struct service_tag_s *tag, gchar * s,
		gsize s_size, GError **error);


/**
 * Set a service_tag_t boolean value
 *
 * @param tag the service_tag_t to set the value in
 * @param b the boolean value
 */
void service_tag_set_value_boolean(struct service_tag_s *tag, gboolean b);


/**
 * Get a service_tag_t boolean value
 *
 * @param tag the service_tag_t to get the value from
 * @param b a pointer to a gboolean to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_boolean(struct service_tag_s *tag, gboolean *b,
		GError **error);


/**
 * Set a service_tag_t int value
 *
 * @param tag the service_tag_t to set the value in
 * @param i the int value
 */
void service_tag_set_value_i64(struct service_tag_s *tag, gint64 i);


/**
 * Get a service_tag_t int value
 *
 * @param tag the service_tag_t to get the value from
 * @param i a pointer to an int64 to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_i64(struct service_tag_s *tag, gint64* i,
		GError** error);


/**
 * Set a service_tag_t double value
 *
 * @param tag the service_tag_t to set the value in
 * @param r the double value
 */
void service_tag_set_value_float(struct service_tag_s *tag, gdouble r);


/**
 * Get a service_tag_t double value
 *
 * @param tag the service_tag_t to get the value from
 * @param r a pointer to a double to fill with the result
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_float(struct service_tag_s *tag, gdouble *r,
		GError** error);


/**
 * Copy a service_tag_t from src to dst
 *
 * @param dst the service_tag_t to copy to
 * @param src the service_tag_t to copy from
 */
void service_tag_copy(struct service_tag_s *dst, struct service_tag_s *src);


/**
 * Set a service_tag_t macro value
 *
 * @param tag the service_tag_t to set the value in
 * @param type the macro type
 * @param param the macro param
 */
void service_tag_set_value_macro(struct service_tag_s *tag, const gchar * type,
		const gchar * param);


/**
 * Get a service_tag_t macro value
 *
 * @param tag the service_tag_t to get the value from
 * @param type a pointer to a macro type to fill with the result
 * @param type_size the size of the string type
 * @param param a pointer to a macro param to fill with the result
 * @param param_size the size of the param string
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_tag_get_value_macro(struct service_tag_s *tag, gchar * type,
		gsize type_size, gchar* param, gsize param_size, GError** error);


/**
 * Duplicate a service_tag_t
 *
 * @param src the service_tag_t to duplicate
 *
 * @return a newly allocated service_tag_t duplicates of src or NULL if an error occured
 */
struct service_tag_s *service_tag_dup(struct service_tag_s *src);


/**
 * Convert a service_tag_t to a string representation
 *
 * @param tag the service_tag_t to convert
 * @param dst the destination string
 * @param dst_size the destinatino string size
 *
 * @return the size of the resulting string or 0 if an error occured
 */
gsize service_tag_to_string(const struct service_tag_s *tag, gchar * dst,
		gsize dst_size);


/**
 * @param si
 * @return
 */
gchar* service_info_to_string(const service_info_t *si);

/**
 * @param si0
 * @param si1
 */
void service_info_swap(struct service_info_s *si0, struct service_info_s *si1);

/**
 * GSList sort callback to sort a list of service_info_t by score
 *
 * @param a a value
 * @param b a value to compare with
 *
 * @return negative value if a < b; zero if a = b; positive value if a > b
 */
gint service_info_sort_by_score(gconstpointer a, gconstpointer b);


/**
 * Compare two service_info_t pointers
 *
 * @param si1 a service_info_t
 * @param si2 a service_info_t to compare with
 * @return TRUE if si1 equals si2 or FALSE if not
 */
gboolean service_info_equal(const struct service_info_s * si1,
		const struct service_info_s * si2);


/**
 * Compare two service_info_t pointers, compare only ns part of name which is vns name, 
 * or all name if simple ns
 *
 * @param si1 a service_info_t
 * @param si2 a service_info_t to compare with
 * @return TRUE if si1 equals si2 or FALSE if not
 */
gboolean service_info_equal_v2(const struct service_info_s * si1,
		const struct service_info_s * si2);


/**
 * Convert a service_info_t to a legacy meta0_info_t
 *
 * @param srv the service_info_t to convert
 * @return a newly allocated meta0_info_t or NULL if an error occured
 * @deprecated
 */
meta0_info_t *service_info_convert_to_m0info(struct service_info_s *srv);

/**
 * Extract the tag with the given name from a GPtrArray of service_tag_t
 *
 * @param a a GPtrArray of service_tag_t
 * @param n a tag name
 * @return the service_tag_t from array or NULL if an error occured or the tag was not found
 */
struct service_tag_s *service_info_get_tag(GPtrArray * a, const gchar * n);


/**
 * Create a new empty service_tag_t with the given name and store it in a GPtrArray
 *
 * @param a a GPtrArray of service_tag_t
 * @param name a tag name
 * @return the newly allocated service_tag_t or NULL if an error occured
 */
struct service_tag_s *service_info_ensure_tag(GPtrArray * a, const gchar * name);


/**
 * Remove a service_tag_t with the given name from a GPtrArray
 *
 * @param a a GPtrArray of service_tag_t
 * @param name a tag name
 */
void service_info_remove_tag(GPtrArray * a, const gchar * name);


/**
 * Set a service_info_t addr
 * 
 * @param si the service_info_t to set the addr in
 * @param addr the service addr in string format
 * @param port the service port
 * @param error
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean service_info_set_address(struct service_info_s *si,
		const gchar * addr, int port, GError ** error);

/**
 * Returns a direct pointer to the tag value. If the tag does not exist or
 * is a not a string, 'def' is returned.
 */
const gchar * service_info_get_tag_value(const struct service_info_s *si,
		const gchar *name, const gchar *def);

/**
 * Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_LOC as 2nd parameter.
 */
const gchar * service_info_get_rawx_location(const struct service_info_s *si,
		const gchar *def);

/**
 * Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_VOL as 2nd parameter.
 */
const gchar * service_info_get_rawx_volume(const struct service_info_s *si,
		const gchar *def);

/**
 * Calls service_info_get_tag_value() with NAME_TAGNAME_RAWX_STGCLASS as 2nd parameter.
 */
const gchar * service_info_get_stgclass(const struct service_info_s *si,
		const gchar *def);

/**
 * Check if a service_info is specified as internal (i.e. if it has a tag "tag.internal"
 * with a string value not equals to "false"
 */
gboolean service_info_is_internal(const struct service_info_s *si);

/** Extract the rawx location from service info tag */
gchar* get_rawx_location(service_info_t* rawx);

#define metautils_rawx_get_location(si) \
	g_strdup(service_info_get_rawx_location((si), ""))

#define metautils_rawx_get_volume(si) \
	g_strdup(service_info_get_rawx_volume((si), "/"))

struct json_object;

GError* service_info_load_json_object(struct json_object *obj,
		struct service_info_s **out);

GError* service_info_load_json(const gchar *encoded,
		struct service_info_s **out);

// Appends to 'out' a json representation of 'si'
void service_info_encode_json(GString *out, struct service_info_s *si);

/** @} */

#endif // __REDCURRANT_metatype_srvinfo__h
