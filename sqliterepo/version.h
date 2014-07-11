/**
 * @file version.h
 */

#ifndef HC__SQLX_VERSION__H
# define HC__SQLX_VERSION__H 1
# include <glib.h>

/**
 * @defgroup sqliterepo_version Databases versioning
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

struct TableSequence;

/**
 *
 */
struct object_version_s
{
	gint64 version; /**<  */
	gint64 when;    /**<  */
};

struct sqlx_sqlite3_s;

/** Wraps version_extract_from_admin_tree() called on the admin table
 * cache. */
GTree* version_extract_from_admin(struct sqlx_sqlite3_s *sq3);

/** For testing purposes, prefer version_extract_from_admin()
 * for production code.
 * @see version_extract_from_admin() */
GTree* version_extract_from_admin_tree(GTree *t);

/**
 * @param t
 * @return
 */
gchar* version_dump(GTree *t);

/**
 * @param tag
 * @param versions
 */
void version_debug(const gchar *tag, GTree *sq3);

/**
 * @param t
 */
void version_increment_all(GTree *t);

/**
 * Computes what would be the version if the 'changes' were applied to a
 * base with the 'current' version.
 *
 * @param current
 * @param changes
 * @return
 */
GTree* version_extract_expected(GTree *current, struct TableSequence *changes);

/**
 * Compute the diff between both versions, and returns an error if the worst
 * version is > 1 in basolute value.
 *
 * @param src
 * @param dst
 * @param worst the worst difference matched, with the considering 'src - dst'
 * @return the error that occured
 */
GError* version_validate_diff(GTree *src, GTree *dst, gint64 *worst);

GTree* version_empty(void);

/**
 * @param t
 * @return
 */
GByteArray* version_encode(GTree *t);

/**
 * @param raw
 * @param rawsize
 * @return
 */
GTree* version_decode(guint8 *raw, gsize rawsize);

/**
 * @param version
 * @return
 */
GTree* version_dup(GTree *version);

/** @} */

#endif
