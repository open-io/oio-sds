#ifndef __REDCURRANT__metautils_gba__h
# define __REDCURRANT__metautils_gba__h 1

#include <glib.h>

#include <metautils/lib/metatypes.h>

/**
 * @defgroup metautils_utils_gba GByteArray
 * @ingroup metautils_utils
 * @brief GByteArray utils
 * @{
 */

/**
 * @param cid
 * @return
 */
GByteArray* metautils_gba_from_cid(const container_id_t cid);


/**
 * @param gba
 * @return
 */
GByteArray* metautils_gba_dup(const GByteArray *gba);


/**
 * @param str
 * @return
 */
GByteArray* metautils_gba_from_string(const gchar *str);


/**
 * @param gba
 * @param dst
 * @param dst_size
 * @return
 */
gsize metautils_gba_data_to_string(const GByteArray *gba, gchar *dst,
		gsize dst_size);


/**
 * @param a
 * @param b
 * @return 0 if a differs from b, something true elsewhere
 */
int metautils_gba_cmp(const GByteArray *a, const GByteArray *b);

/**
 * @param gba
 */
void metautils_gba_randomize(GByteArray *gba);

/**
 * @param gba
 * @return the internal size of gba or 0 if gba is invalid
 */
gsize metautils_gba_len(const GByteArray *gba);


/** Calls g_byte_array_free() on GByteArray in GLib containers
 *
 * Factored code
 * @param p a GByteArray
 */
void metautils_gba_clean(gpointer p);


/** Calls g_byte_array_free() on GByteArray in GLib associative containers
 *
 * @param p1 a GByteArray
 * @param p2 ignored
 */
void meatutils_gba_gclean(gpointer p1, gpointer p2);


/** Factored code
 *
 * @see g_byte_array_unref()
 * @param p a GByteArray
 */
void metautils_gba_unref(gpointer p);


/**
 * @param p0
 * @param p1 ignored
 */
void metautils_gba_gunref(gpointer p0, gpointer p1);

/**
 * @param gstr
 * @param gba
 * @return
 */
GString* metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba);

/** @} */
#endif // __REDCURRANT__metautils_gba__h
