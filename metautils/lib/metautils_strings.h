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
	for (gchar **p=(V); *p ;++p) { STRING_STACKIFY(*p); } \
} while (0)

/**
 * Copies in 'd' the part of 's' representing a valid physical namespace.
 *
 * @param d the target buffer to store the physical NS
 * @param s a source string starting with the physical namespace
 * @param dlen the size of the target buffer
 * @return the size of the physical namespace in the source string
 */
gsize metautils_strlcpy_physical_ns(gchar *d, const gchar *s, gsize dlen);

/**
 * @param src
 * @return to be freed with g_free(), not g_strfreev()
 */
gchar ** g_strdupv2(gchar **src);

void metautils_str_upper(register gchar *s);

void metautils_str_lower(register gchar *s);

/** Splits the given buffer (considered as a non NULL-terminated) into 
 * newly allocated tokens (wrapping g_strsplit()) */
gchar **buffer_split(const void *buf, gsize buflen, const gchar * separator, gint max_tokens);

gchar** metautils_decode_lines(const gchar *start, const gchar *end);

GByteArray* metautils_encode_lines(gchar **strv);

gsize metautils_hash_content_path(const gchar *src, gsize src_size,
	gchar *dst, gsize dst_size, gsize dst_bitlength);

/** Calls g_strcmp0(a,b) and ignores its third argument. */
int metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored);

/** Returns the boolean value of the textual and human readable boolean
 * string (yes, true, on, yes, 1) */
gboolean metautils_cfg_get_bool(const gchar *value, gboolean def);

/* g_free(p) if p is not NULL */
void g_free0(gpointer p);

/* g_free0(p1) and ignores p2 */
void g_free1(gpointer p1, gpointer p2);

/* g_free0(p2) and ignores p1 */
void g_free2(gpointer p1, gpointer p2);

gboolean metautils_str_has_caseprefix (const char *str, const char *prefix);

#endif /*OIO_SDS__metautils__lib__metautils_strings_h*/
