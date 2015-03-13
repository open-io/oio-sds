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

/**
 *
 * @param s
 * @param src_size
 * @param dst
 * @param error
 */
gboolean container_id_hex2bin(const gchar * s, gsize src_size,
		container_id_t * dst, GError ** error);

/**
 * @param k
 * @return
 */
guint container_id_hash(gconstpointer k);

/**
 * @param k1
 * @param k2
 * @return
 */
gboolean container_id_equal(gconstpointer k1, gconstpointer k2);

/**
 * Fills the given buffer with the haxedecimal representatino of the
 * container_id. The destination buffer will always be NULL terminated.
 *
 * @param id the container identifier to be printed
 * @param dst the destination buffer
 * @param dstsize
 * @return 
 */
gsize container_id_to_string(const container_id_t id, gchar * dst, gsize dstsize);

/**
 * Builds the container identifier from the container name
 *
 * If the container name is a null-terminated character array, the NULL
 * character will be hashed as a regular character.
 *
 * @param name the container name
 * @param nameLen the length of the container name.
 * @param id the container_id we put the result in
 *
 * @return NULL if an error occured, or a valid pointer to a container identifier.
 */
void name_to_id(const gchar * name, gsize nameLen, container_id_t * id);

/**
 * Builds the container identifier from the container name
 *
 * If the container name is a null-terminated character array, the NULL
 * character will be hashed as a regular character.
 *
 * @param name the container name
 * @param nameLen the length of the container name.
 * @param vns the name of the associated virtual namespace
 * @param id the container_id we put the result in
 *
 * @return NULL if an error occured, or a valid pointer to a container identifier.
 */
void name_to_id_v2(const gchar * name, gsize nameLen, const gchar *vns,
		container_id_t * id);

/**
 * @param cid
 * @param ns
 * @param cname
 */
void meta1_name2hash(container_id_t cid, const gchar *ns, const gchar *cname);

/** @} */

#endif /*OIO_SDS__metautils__lib__metatype_cid_h*/