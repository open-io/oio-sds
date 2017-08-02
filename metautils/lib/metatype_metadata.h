/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

GHashTable* metadata_unpack_buffer(const guint8 *data, gsize size, GError **error);

GHashTable* metadata_unpack_string(const gchar *data, GError **error);

GByteArray* metadata_pack(GHashTable *unpacked, GError **error);

void metadata_merge(GHashTable *base, GHashTable *complement);

#endif /*OIO_SDS__metautils__lib__metatype_metadata_h*/
