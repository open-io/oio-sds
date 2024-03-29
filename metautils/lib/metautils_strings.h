/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2023 OVH SAS

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

#ifndef OIO_SDS__metautils__lib__metautils_strings_h
# define OIO_SDS__metautils__lib__metautils_strings_h 1

#include <glib.h>

#define BUFFER_STACKIFY(P,L) do { \
	gsize _l = (L); void *_t = (P); \
	(P) = alloca(_l); memcpy((P), _t, _l); g_free(_t); \
} while (0)

/* Replaces the heap-allocated buffer at S by a stack-allocated copy */
#define STRING_STACKIFY(S) do { \
	if (!(S)) break; \
	BUFFER_STACKIFY((S),1+strlen(S)); \
} while (0)

/* Replaces the heap-allocated null-terminated strings array by a deep copy
 * that is stack allocated. */
#define STRINGV_STACKIFY(V) do { \
	if (!(V)) break; \
	BUFFER_STACKIFY((V), (1+g_strv_length(V))*sizeof(void*)); \
	for (gchar **__p=(V); *__p ;++__p) { STRING_STACKIFY(*__p); } \
} while (0)

#define metautils_str_upper oio_str_upper

#define metautils_str_lower oio_str_lower

/** @return to be freed with g_free(), not g_strfreev() */
gchar ** g_strdupv_inline (gchar **src);

/** Calls g_strcmp0(a,b) and ignores its third argument. */
int metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored);

/** g_free(p) if p is not NULL */
void g_free0(gpointer p);

/* Create a string compatible with the LTSV format
 * (replace the tabulation and newline characters).
 * The result must be freed with g_free(). */
gchar * string_to_ltsv_value(const gchar *value);

#endif /*OIO_SDS__metautils__lib__metautils_strings_h*/
