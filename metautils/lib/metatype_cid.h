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

#ifndef OIO_SDS__metautils__lib__metatype_cid_h
# define OIO_SDS__metautils__lib__metatype_cid_h 1

#include <glib/gtypes.h>

/**
 * @defgroup metautils_cid Container ID 
 * @ingroup metautils_utils
 * @{
 */

guint container_id_hash(gconstpointer k);

gboolean container_id_equal(gconstpointer k1, gconstpointer k2);

/** Fills the given buffer with the haxedecimal representatino of the
 * container_id. The destination buffer will always be NULL terminated. */
gsize container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize);

#define meta1_name2hash oio_str_hash_name

/** @} */

#endif /*OIO_SDS__metautils__lib__metatype_cid_h*/
