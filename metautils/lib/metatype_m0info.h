/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__metautils__lib__metatype_m0info_h
# define OIO_SDS__metautils__lib__metatype_m0info_h 1

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

#endif /*OIO_SDS__metautils__lib__metatype_m0info_h*/