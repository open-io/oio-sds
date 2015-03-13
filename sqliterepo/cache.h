/*
OpenIO SDS sqliterepo
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

#ifndef OIO_SDS__sqliterepo__cache_h
# define OIO_SDS__sqliterepo__cache_h 1

/**
 * @defgroup sqliterepo_cache Cache of databases
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

# include <metautils/lib/metautils.h>

/**
 * Default timeout when trying to open a base
 * currently in use by another thread (milliseconds)
 */
#define DEFAULT_CACHE_OPEN_TIMEOUT 15000

struct hashstr_s;

/**
 * @param hs
 * @param u
 */
typedef void (*sqlx_cache_close_hook)(gpointer);

typedef struct sqlx_cache_s sqlx_cache_t;

/**
 * Returns the arbitrary user handle associated to the given base
 */
gpointer sqlx_cache_get_handle(sqlx_cache_t *cache, gint bd);

/**
 * Attach a new DB handle to this database. The handle previously
 * attached is retruned.
 *
 * @param cache
 * @param bd the descriptor to an open base
 * @param handle the DB handle
 */
void sqlx_cache_set_handle(sqlx_cache_t *cache, gint bd, gpointer handle);

/**
 * @return
 */
sqlx_cache_t * sqlx_cache_init(void);

/**
 * @param cache
 * @param hook
 * @return the cache
 */
sqlx_cache_t * sqlx_cache_set_close_hook(sqlx_cache_t *cache,
	sqlx_cache_close_hook hook);

/**
 * @param cache
 * @param max
 * @return the cache
 */
sqlx_cache_t * sqlx_cache_set_max_bases(sqlx_cache_t *cache, guint max);

/**
 * Set the timeout for opening a base currently in use by another thread.
 *
 * @param cache A valid sqlx_cache_t pointer.
 * @param timeout The timeout in milliseconds. If negative, wait forever.
 * @return the cache.
 */
sqlx_cache_t * sqlx_cache_set_open_timeout(sqlx_cache_t *cache, glong timeout);

/**
 * @param cache
 */
void sqlx_cache_clean(sqlx_cache_t *cache);

/**
 * @param cache
 */
void sqlx_cache_debug(sqlx_cache_t *cache);

/** Similar to sqlx_cache_open_base2() and sqlx_cache_lock_base()
 * but in the same critical section. */
GError * sqlx_cache_open_and_lock_base(sqlx_cache_t *cache,
		const struct hashstr_s *key, gint *result);

/** The invert of sqlx_cache_open_and_lock_base() */
GError * sqlx_cache_unlock_and_close_base(sqlx_cache_t *cache, gint bd,
		gboolean force);

guint sqlx_cache_expire_all(sqlx_cache_t *cache);

/** Check for expired bases, then close them */
guint sqlx_cache_expire(sqlx_cache_t *cache, guint max, GTimeVal *end);

/** One statistics for each possible base's status */
struct cache_counts_s
{
	guint max;
	guint cold;
	guint hot;
	guint used;
};

/** Returns several statistics about the current cache. Returns zeroed
 * stats is 'cache' is NULL. */
struct cache_counts_s sqlx_cache_count(sqlx_cache_t *cache);

/** @} */

#endif /*OIO_SDS__sqliterepo__cache_h*/