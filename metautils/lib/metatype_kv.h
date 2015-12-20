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

#ifndef OIO_SDS__metautils__lib__metatype_kv_h
# define OIO_SDS__metautils__lib__metatype_kv_h 1

#include <glib/gtypes.h>

/* Deep copy of the map */
GSList *key_value_pairs_convert_from_map(GHashTable * ht, gboolean copy,
		GError ** err);

/* Deep cleaning of the given key_value_pair_t (frees all the structure
 * members and the structure) */
void key_value_pair_clean(key_value_pair_t * kv);

void key_value_pair_gclean(gpointer p, gpointer u);

struct key_value_pair_s* key_value_pair_create(const gchar *k,
		const guint8 *v, gsize vs);

#endif /*OIO_SDS__metautils__lib__metatype_kv_h*/
