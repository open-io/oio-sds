/*
OpenIO SDS meta0v2
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

#ifndef OIO_SDS__meta0v2__meta0_utils_h
# define OIO_SDS__meta0v2__meta0_utils_h 1

# include <glib.h>

# include <metautils/lib/metatypes.h>

#define CID_PREFIX_COUNT 65536

GTree* meta0_utils_array_to_tree(const GPtrArray *array);

GSList* meta0_utils_tree_to_list(GTree *tree);

GTree* meta0_utils_list_to_tree(const GSList *list);

GPtrArray* meta0_utils_list_to_array(GSList *list);

GSList* meta0_utils_array_to_list(GPtrArray *array);

gchar ** meta0_utils_array_get_urlv(GPtrArray *array, const guint8 *bytes);

GPtrArray* meta0_utils_array_dup(const GPtrArray *in);

void meta0_utils_array_clean(GPtrArray *array);

void meta0_utils_list_clean(GSList *list);

void meta0_utils_array_add(GPtrArray *gpa, const guint8 *b, const gchar *s);

GPtrArray * meta0_utils_array_create(void);

void meta0_utils_tree_add_url(GTree *tree, const guint8 *b, const gchar *url);

GTree* meta0_utils_tree_create(void);

void meta0_utils_array_meta1ref_clean(GPtrArray *array);

GPtrArray* meta0_utils_array_meta1ref_dup(GPtrArray *in);

gchar * meta0_utils_pack_meta1ref(gchar *addr, gchar *ref, gchar *nb);

gboolean meta0_utils_unpack_meta1ref(const gchar *s_m1ref, gchar **addr,
		gchar **ref, gchar **nb);

/* @return TRUE to continue */
typedef gboolean (*meta0_on_prefix)(gpointer u,
		const guint8 *group, const guint8 *prefix);

/* iterate on all the prefixes in a given coalescence group */
void meta0_utils_foreach_prefix_in_group(const guint8* bin, guint digits,
		meta0_on_prefix on_prefix, gpointer u);

/* iterate on all the prefixes */
void meta0_utils_foreach_prefix(guint digits,
		meta0_on_prefix on_prefix, gpointer u);

#endif /*OIO_SDS__meta0v2__meta0_utils_h*/
