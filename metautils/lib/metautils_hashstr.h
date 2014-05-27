/**
 * @file hashstr.h
 * A {CPU,RAM} efficient structure and its associated functions to plays
 * with ASCII strings.
 */

#ifndef HASHSTR_H
# define HASHSTR_H 1
# include <string.h>
# include <glib.h>
# include <metautils/lib/metautils_bits.h>

/**
 * @defgroup metautils_hashstr HashStr, handy string features
 * @ingroup metautils_utils
 * @{
 */


typedef struct hashstr_s
{
	struct hash_len_s hl;
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

/** @} */

#endif /*HASHSTR_H*/
