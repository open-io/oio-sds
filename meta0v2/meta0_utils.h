/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file meta0_utils.h
 */

#ifndef GRID__META0_UTILS__H
# define GRID__META0_UTILS__H 1

# include <glib.h>

# include <metatypes.h>


/**
 * @addtogroup meta0v2_utils
 * @{
 */

/**
 * @param bytes
 * @return
 */
guint16 meta0_utils_bytes_to_prefix(const guint8 *bytes);

/**
 * @param array
 * @return a GTree mapping <hashstr_t*,GArray*>
 */
GTree* meta0_utils_array_to_tree(GPtrArray *array);

/**
 * @param tree
 * @result
 */
GSList* meta0_utils_tree_to_list(GTree *tree);

/**
 * @param list
 * @return
 */
GTree* meta0_utils_list_to_tree(GSList *list);

/**
 * @param list
 * @return
 */
GPtrArray* meta0_utils_list_to_array(GSList *list);

/**
 * @param array
 * @return
 */
GSList* meta0_utils_array_to_list(GPtrArray *array);

/**
 * @param array
 * @param bytes
 * @return
 */
gchar ** meta0_utils_array_get_urlv(GPtrArray *array, const guint8 *bytes);

/**
 * @param in
 * @return
 */
GPtrArray* meta0_utils_array_dup(GPtrArray *in);

/**
 * @param array
 */
void meta0_utils_array_clean(GPtrArray *array);

/**
 * @param list
 */
void meta0_utils_list_clean(GSList *list);

/**
 * @param gpa
 * @param b
 * @param s
 */
void meta0_utils_array_add(GPtrArray *gpa, const guint8 *b, const gchar *s);

/**
 *  @param gpa
 *  @param b
 *  @param s
 *  @param d
 *  */
gboolean meta0_utils_array_replace(GPtrArray *gpa, const guint8 *b, const gchar *s, const gchar *d);

/**
 * @return
 */
GPtrArray * meta0_utils_array_create(void);

/**
 * @param tree
 * @param b
 * @param url
 * @return
 */
GTree* meta0_utils_tree_add_url(GTree *tree, const guint8 *b, const gchar *url);

/**
 * @return
 */
GTree* meta0_utils_tree_create(void);


/**
 *  @param array
 */
void meta0_utils_array_meta1ref_clean(GPtrArray *array);

/**
 * @param GPtrArray
 * @return
 */
GPtrArray* meta0_utils_array_meta1ref_dup(GPtrArray *in);


/**
 * @param addr
 * @param ref
 * @param nb
 * @return gchar*
 */
gchar * meta0_utils_pack_meta1ref(gchar *addr, gchar *ref, gchar *nb);

/**
 * @param s_m1ref
 * @param addr
 * @param ref
 * @param nb
 * @return gboolean
 */
gboolean meta0_utils_unpack_meta1ref(const gchar *s_m1ref, gchar **addr, gchar **ref, gchar **nb);


gboolean meta0_utils_check_url_from_base(gchar **url);


/**
 * @param m0List
 * @param exclude
 * @return addr_info_t
 */
addr_info_t * meta0_utils_getMeta0addr(gchar *ns, GSList **m0List, GSList *exclude );

/** @} */

#endif /* GRID__META0_UTILS__H */
