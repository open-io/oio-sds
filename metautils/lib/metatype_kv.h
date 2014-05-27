#ifndef __REDCURRANT_metatype_kv__h
#define __REDCURRANT_metatype_kv__h 1
#include <glib/gtypes.h>

/**
 * @defgroup metautil_kv KeyValue pairs
 * @ingroup metautils_utils
 * @{
 */

/**
 *
 * @param pairs
 * @param copy do a deep copy or not (key and values are copied too)
 * @param err
 * @return a GHashtable of (gchar*,GBytearray*)
 */
GHashTable *key_value_pairs_convert_to_map(GSList * pairs, gboolean copy,
		GError ** err);


/**
 *
 * @param ht
 * @param copy do a deep copy or not (key and values are copied too)
 * @param err
 * @return a GHashtable of (gchar*,GBytearray*)
 */
GSList *key_value_pairs_convert_from_map(GHashTable * ht, gboolean copy, GError ** err);


/**
 * Deep cleaning of the given key_value_pair_t (frees all the structure members and the structure)
 */
void key_value_pair_clean(key_value_pair_t * kv);


/**
 * Call key_value_pair_clean() on the first argument
 */
void key_value_pair_gclean(gpointer p, gpointer u);


/**
 * @param k copied
 * @param v copied
 * @param vs
 * @return
 */
struct key_value_pair_s* key_value_pair_create(const gchar *k,
		const guint8 *v, gsize vs);


/**
 * @return a valid '\0'-terminated character string
 */
gchar* key_value_pair_to_string(key_value_pair_t * kv);

/** @} */

#endif // __REDCURRANT_metatype_kv__h
