/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file hashstr.h
 * A {CPU,RAM} efficient structure and its associated functions to plays
 * with ASCII strings.
 */

#ifndef HASHSTR_H
# define HASHSTR_H 1
# include <string.h>

/**
 * @defgroup metautils_hashstr HashStr, handy string features
 * @ingroup metautils_utils
 * @{
 */

# ifdef HAVE_ASSERT_HASHSTR
#  define HASHSTR_ASSERT(X) g_assert(X)
# else
#  define HASHSTR_ASSERT(X)
# endif

typedef struct hashstr_s {
	guint h; /**< the hashcode of the string */
	guint16 len; /**< the length of the string */
	gchar s0[]; /**< the first character of the inner string */
} hashstr_t;

/**
 * @param s
 * @return
 */
hashstr_t* hashstr_create(const gchar *s);

/**
 * @param s
 * @param l
 * @return
 */
hashstr_t* hashstr_create_len(const gchar *s, gsize l);

/**
 * @param hs
 */
void hashstr_upper(hashstr_t *hs);

/**
 * @param hs
 */
void hashstr_lower(hashstr_t *hs);

/**
 * @param fmt
 * @param ...
 * @return
 */
hashstr_t* hashstr_printf(const gchar *fmt, ...);

/**
 * @param gstr
 * @return
 */
hashstr_t* hashstr_create_from_gstring(GString *gstr);

/**
 * @param hs
 * @return
 */
hashstr_t* hashstr_dup(const hashstr_t *hs);

/**
 * @param hs
 * @return
 */
const gchar * hashstr_str(const hashstr_t *hs);

/**
 * @param hs
 * @return
 */
guint hashstr_hash(const hashstr_t *hs);

/**
 * @param hs
 * @return
 */
guint hashstr_ulen(const hashstr_t *hs);

/**
 * @param hs
 * @return
 */
gsize hashstr_len(const hashstr_t *hs);

/**
 * @param hs
 * @return
 */
gsize hashstr_struct_size(const struct hashstr_s *hs);

/**
 * @param hs1
 * @param hs2
 * @return
 */
gboolean hashstr_equal(const hashstr_t *hs1, const hashstr_t *hs2);

/**
 * @param hs1
 * @param hs2
 * @return
 */
gint hashstr_cmp(const hashstr_t *hs1, const hashstr_t *hs2);

/**
 * First sort using the hash, then calling hashstr_hash()
 * in case of hash equality
 *
 * @param hs1
 * @param hs2
 * @return
 */
gint hashstr_quick_cmp(const hashstr_t *hs1, const hashstr_t *hs2);

/**
 * Wrappers around hashstr_quick_cmp(), useful with GLib2 associative
 * containers.
 *
 * @see hashstr_quick_cmp()
 * @param p1
 * @param p2
 * @param u ignored
 * @return
 */
gint hashstr_quick_cmpdata(gconstpointer p1, gconstpointer p2, gpointer u);

/**
 * @param hs
 * @return
 */
gchar* hashstr_dump(const hashstr_t *hs);

/* ------------------------------------------------------------------------- */

/**
 * inlined hoping a speedup, even the smallest. Just because this
 * might be called really often.
 * Thanks to Daniel J. Bernstein for this function.
 *
 * @param s
 * @param p_len
 * @return
 */
static inline guint
_str_hash(const gchar *s, size_t *p_len)
{
	register const gchar *p; 
	guint32 h = 5381;

	for (p=s; *p != '\0' ;)
		h = (h << 5) + h + *(p++);

	if (p_len)
		*p_len = (p - s);
	return h;
}

/**
 * @param s
 * @param max
 * @param p_len
 * @return
 */
static inline guint
_str_hash2(const gchar *s, size_t max, size_t *p_len)
{
	register int imax = max;
	register const gchar *p; 
	guint32 h = 5381;

	for (p=s; *p != '\0' && (p-s) < imax;)
		h = (h << 5) + h + *(p++);

	if (p_len)
		*p_len = (p - s);
	return h;
}

#define HASHSTR_ALLOCA(R,S) do { \
	gsize len; guint h = _str_hash((char*)(S), &len); \
	len = strlen(S); \
	g_assert(len < 65536); \
	(R) = g_alloca(offsetof(struct hashstr_s, s0) + len + 1); \
	(R)->h = h; \
	(R)->len = len; \
	if (len) memcpy((R)->s0, (S), len+1); \
} while (0)

#define HASHSTR_ALLOCA_LEN(R,S,L) do { \
	gsize _l = 0; guint h = _str_hash2((char*)(S), (gsize)(L), &_l); \
	g_assert(_l < 65536); \
	(R) = g_alloca(offsetof(struct hashstr_s, s0) + _l + 1); \
	(R)->h = h; \
	(R)->len = _l; \
	if (_l) memcpy((R)->s0, (S), _l); \
	(R)->s0[_l] = '\0'; \
} while (0)

#define HASHSTR_ALLOCA_DUP(R,S) do { \
	(R) = g_alloca(offsetof(struct hashstr_s, s0) + (S)->len + 1); \
	memcpy((R), (S), offsetof(struct hashstr_s, s0) + (S)->len + 1); \
	((guint8*)(S))[ offsetof(struct hashstr_s, s0) + (S)->len] = '\0'; \
} while (0)

/** @} */

#endif /*HASHSTR_H*/
