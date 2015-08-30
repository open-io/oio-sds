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

#ifndef OIO_SDS__metautils__lib__metatype_metadata_h
# define OIO_SDS__metautils__lib__metatype_metadata_h 1

#include <glib/gtypes.h>

GHashTable* metadata_create_empty(void);

GHashTable* metadata_unpack_gba(GByteArray *gba, GError **error);

GHashTable* metadata_unpack_buffer(const guint8 *data, gsize size, GError **error);

GHashTable* metadata_unpack_string(const gchar *data, GError **error);

GByteArray* metadata_pack(GHashTable *unpacked, GError **error);

/* Returns if given metadata strings contain the same key/values. */
gboolean metadata_equal(const gchar *md1, const gchar *md2, GSList **diff);

GHashTable* metadata_remove_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error);

GHashTable* metadata_extract_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error);

void metadata_merge(GHashTable *base, GHashTable *complement);

void metadata_add_time(GHashTable *md, const gchar *key, GTimeVal *t); 

void metadata_add_printf(GHashTable *md, const gchar *key, const gchar *fmt, ...)
__attribute__ ((format (printf, 3, 4)));

#endif /*OIO_SDS__metautils__lib__metatype_metadata_h*/
