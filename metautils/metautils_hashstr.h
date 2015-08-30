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

#ifndef OIO_SDS__metautils__lib__metautils_hashstr_h
# define OIO_SDS__metautils__lib__metautils_hashstr_h 1

# include <string.h>
# include <glib.h>
# include <metautils/metautils_bits.h>

typedef struct hashstr_s
{
	struct hash_len_s hl;
	gchar s0[]; /* the first character of the inner string */
} hashstr_t;

hashstr_t* hashstr_create(const gchar *s);

hashstr_t* hashstr_create_len(const gchar *s, gsize l);

void hashstr_upper(hashstr_t *hs);

void hashstr_lower(hashstr_t *hs);

hashstr_t* hashstr_printf(const gchar *fmt, ...) __attribute__ ((format (printf, 1, 2))) ;

hashstr_t* hashstr_create_from_gstring(GString *gstr);

hashstr_t* hashstr_dup(const hashstr_t *hs);

const gchar * hashstr_str(const hashstr_t *hs);

guint hashstr_hash(const hashstr_t *hs);

guint hashstr_ulen(const hashstr_t *hs);

gsize hashstr_len(const hashstr_t *hs);

gsize hashstr_struct_size(const struct hashstr_s *hs);

gboolean hashstr_equal(const hashstr_t *hs1, const hashstr_t *hs2);

gint hashstr_cmp(const hashstr_t *hs1, const hashstr_t *hs2);

/* First sort using the hash, then calling hashstr_hash()
 * in case of hash equality */
gint hashstr_quick_cmp(const hashstr_t *hs1, const hashstr_t *hs2);

/* Wrappers around hashstr_quick_cmp(), useful with GLib2 associative
 * containers. */
gint hashstr_quick_cmpdata(gconstpointer p1, gconstpointer p2, gpointer u);

gchar* hashstr_dump(const hashstr_t *hs);

#define HASHSTR_PREFIX offsetof(struct hashstr_s, s0)

#define HASHSTR_ALLOCA(R,S) do { \
	struct hash_len_s hl = djb_hash_str(S); \
	(R) = g_alloca(HASHSTR_PREFIX + hl.l + 1); \
	(R)->hl = hl; \
	if (hl.l) memcpy((R)->s0, (S), hl.l + 1); \
} while (0)

#define HASHSTR_ALLOCA_LEN(R,S,L) do { \
	gsize _l = (L); \
	guint32 h = djb_hash_buf((guint8*)(S), _l); \
	(R) = g_alloca(HASHSTR_PREFIX + _l + 1); \
	(R)->hl.h = h; \
	(R)->hl.l = _l; \
	if (_l) memcpy((R)->s0, (S), _l); \
	(R)->s0[_l] = '\0'; \
} while (0)

#define HASHSTR_ALLOCA_DUP(R,S) do { \
	(R) = g_alloca(HASHSTR_PREFIX + (S)->len + 1); \
	memcpy((R), (S), HASHSTR_PREFIX + (S)->len + 1); \
	((guint8*)(S))[ HASHSTR_PREFIX + (S)->len] = '\0'; \
} while (0)

#endif /*OIO_SDS__metautils__lib__metautils_hashstr_h*/
