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

#ifndef OIO_SDS__metautils__lib__metautils_gba_h
# define OIO_SDS__metautils__lib__metautils_gba_h 1

#include <glib.h>

#include <metautils/lib/metatypes.h>

GByteArray* metautils_gba_from_cid(const container_id_t cid);

GByteArray* metautils_gba_dup(const GByteArray *gba);

GByteArray* metautils_gba_from_string(const gchar *str);

GByteArray* metautils_gba_from_hexstring(const gchar *str);

gsize metautils_gba_data_to_string(const GByteArray *gba, gchar *dst,
		gsize dst_size);

/** Compare 2 GByteArray. Can be cast to GEqualFunc and used as 2nd param of
 * g_hash_table_new(). */
gboolean metautils_gba_equal(const GByteArray *a, const GByteArray *b);

/** 3-way comparison */
int metautils_gba_cmp(const GByteArray *a, const GByteArray *b);

/** Replaces the contents of <gba> with random content of the same length */
void metautils_gba_randomize(GByteArray *gba);

/** Calls g_byte_array_free() on GByteArray in GLib containers */
void metautils_gba_clean(gpointer p);

void metautils_gba_cleanv(GByteArray **tab);

/** @see g_byte_array_unref() */
void metautils_gba_unref(gpointer p);

/** Convert the content to its hexadecimal representation */
GString* metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba);

void gba_pool_clean(GSList **pool);

GByteArray * gba_poolify(GSList **pool, GByteArray *gba);

#endif /*OIO_SDS__metautils__lib__metautils_gba_h*/
