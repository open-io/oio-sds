/**
 * @file hash.h
 */

#ifndef HC__SQLITEREPO_HASH__H
# define HC__SQLITEREPO_HASH__H 1
# include <glib/gtypes.h>

struct hashstr_s;

/**
 * @addtogroup sqliterepo_misc
 * @param n
 * @param t
 * @return
 */
struct hashstr_s * sqliterepo_hash_name(const gchar *n, const gchar *t);

#endif /* HC__SQLITEREPO_HASH__H */
