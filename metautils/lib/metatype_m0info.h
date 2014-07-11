#ifndef __REDCURRANT_metatype_m0info__h
#define __REDCURRANT_metatype_m0info__h 1
#include <glib/gtypes.h>

/**
 * @defgroup metautils_m0info META0
 * @ingroup metautils_utils
 * @{
 */

/**
 * Fills dst with a textual representation (whose maximum length will
 * be dstsize) of the given meta0_info_t structure.
 *
 * The printed characters will always be NULL terminated as soon as the
 * buffer size greater or equal to 1
 *
 * @param m0 a pointer to the meta0_info_t to be printed
 * @param dst a not-NULL pointer to the target buffer
 * @param dstsize the size of the targe buffer
 *
 * @return the size really written or -1 in case of failure.
 */
gsize meta0_info_to_string(const meta0_info_t * m0, gchar * dst, gsize dstsize);


/**
 * @param m0
 */
void meta0_info_clean(meta0_info_t *m0);


/**
 * @param d
 * @param u
 */
void meta0_info_gclean(gpointer d, gpointer u);


/**
 * @param mL
 * @param err
 * @return
 */
GHashTable *meta0_info_list_map_by_addr(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GHashTable *meta0_info_list_map_by_prefix(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GSList *meta0_info_compress_prefixes(GSList * mL, GError ** err);


/**
 * @param mL
 * @param err
 * @return
 */
GSList *meta0_info_uncompress_prefixes(GSList * mL, GError ** err);

/** @} */

#endif // __REDCURRANT_metatype_m0info__h
