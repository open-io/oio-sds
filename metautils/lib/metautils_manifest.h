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

#ifndef OIO_SDS__metautils__lib__metautils_manifest_h
# define OIO_SDS__metautils__lib__metautils_manifest_h 1

/**
 * @defgroup metautils_manifest Manifest 
 * @ingroup metautils_utils
 * @{
 */

# ifndef  GS_MANIFEST_KEY_NS
#  define GS_MANIFEST_KEY_NS   "gs.service.namespace"
# endif

# ifndef  GS_MANIFEST_KEY_TYPE
#  define GS_MANIFEST_KEY_TYPE "gs.service.type"
# endif

# ifndef  GS_MANIFEST_KEY_NAME
#  define GS_MANIFEST_KEY_NAME  "gs.service.name"
# endif

# include <stdarg.h>
# include <glib.h>

/**
 * @brief
 *
 * The optional arguments consist in a NULL terminated sequence of
 * valid character strings (NULL-terminated gchar*) coming by pair,
 * e.g. in: "k1", "v1", "k2", "v2", NULL
 *
 * Mandatory keys: "ns", "name", "type".
 *
 * @param path
 * @param prefix
 * @param error
 * @return 0 in case of error, 1 upon success
 */
extern int gs_manifest_testandset(const gchar *path, const gchar *prefix, GError **error, ...);

/**
 * @param path
 * @param prefix
 * @param error
 * @return
 */
extern GHashTable* gs_manifest_read(const gchar *path, const gchar *prefix, GError **error);

/** @} */

#endif /*OIO_SDS__metautils__lib__metautils_manifest_h*/