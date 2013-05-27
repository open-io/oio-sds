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

#ifndef SQLX__INTERNALS_H
# define SQLX__INTERNALS_H 1

/**
 * @defgroup sqliterepo_misc Misc. features
 * @ingroup sqliterepo
 * @{
 */

# include "../metautils/lib/loggers.h"

# include <sqlite3.h>

# include <RowName.h>
# include <RowField.h>
# include <Row.h>
# include <Table.h>
# include <TableSequence.h>

# ifdef HAVE_ASSERT_SQLX
#  define SQLX_ASSERT(X) g_assert(X)
# else
#  define SQLX_ASSERT(X)
# endif

# ifndef SQLX_MAX_COND
#  define SQLX_MAX_COND 64
# endif

# ifndef SQLX_MAX_BASES
#  define SQLX_MAX_BASES 2048
# endif

#define MEMBER(D)   ((struct election_member_s*)(D))
#define MMANAGER(D) MEMBER(D)->manager
#define MKEY(D)     MEMBER(D)->key
#define MCFG(D)     MMANAGER(D)->config
#define MKEY_S(D)   hashstr_str(MEMBER(D)->key)

/**
 * @param C
 */
#define CONFIG_CHECK(C) do {\
	SQLX_ASSERT((C) != NULL);\
	SQLX_ASSERT((C)->get_peers != NULL); \
	SQLX_ASSERT((C)->get_manager_url != NULL); \
	SQLX_ASSERT((C)->get_local_url != NULL); \
	SQLX_ASSERT((C)->get_ns_name != NULL); \
} while (0)

/**
 * @param M
 */
#define MANAGER_CHECK(M) do {\
	SQLX_ASSERT((M) != NULL);\
	SQLX_ASSERT((M)->lock != NULL);\
	SQLX_ASSERT((M)->lrutree_members != NULL);\
	CONFIG_CHECK((M)->config); \
} while (0)

/**
 * @param M
 */
#define MEMBER_CHECK(M) do {\
	SQLX_ASSERT(MEMBER(M) != NULL);\
	SQLX_ASSERT(MEMBER(M)->name != NULL);\
	SQLX_ASSERT(MEMBER(M)->type != NULL);\
	SQLX_ASSERT(MEMBER(M)->key != NULL);\
	MANAGER_CHECK(MMANAGER(M));\
} while (0)


/**
 * @param t0
 * @param t1
 * @return
 */
static inline gboolean
gtv_bigger(const GTimeVal *t0, const GTimeVal *t1)
{
	if (t0->tv_sec > t1->tv_sec)
		return TRUE;
	if (t0->tv_sec == t1->tv_sec && t0->tv_usec > t1->tv_usec)
		return TRUE;
	return FALSE;
}

/**
 * @param i1
 * @param i2
 * @return
 */
static inline int
gint64_cmp(gint64 i1, gint64 i2)
{
	return (i1==i2) ? 0 : (i1<i2 ? -1 : 1);
}

/**
 * @param p1
 * @param p2
 * @return
 */
static inline int
gint64_sort(gconstpointer p1, gconstpointer p2)
{
	return gint64_cmp(*(gint64*)p1, *(gint64*)p2);
}

/**
 * @param b
 * @param bs
 * @param u
 * @return
 */
static inline int
write_to_gba(const void *b, size_t bs, void *u)
{
	if (b && bs && u)
		g_byte_array_append((GByteArray*)u, b, bs);
	return 1;
}

/**
 * @param stmt
 * @param r
 * @param t
 */
void load_statement(sqlite3_stmt *stmt, Row_t *r, Table_t *t,
		gboolean noreal);

struct election_manager_s;

/**
 *
 * @param m may be NULL
 * @return
 */
gboolean election_manager_configured(const struct election_manager_s *m);

/**
 * @param op
 * @return
 */
const gchar * sqlite_op2str(int op);

struct sqlx_repository_s;
struct election_manager_s;

/**
 * @param repo
 * @return
 */
struct election_manager_s* sqlx_repository_get_elections_manager(struct sqlx_repository_s *r);

/** @} */

#endif
