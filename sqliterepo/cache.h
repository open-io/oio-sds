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
 * @file cache.h
 */

#ifndef SQLX__CACHE_H
# define SQLX__CACHE_H 1

/**
 * @defgroup sqliterepo_cache Cache of databases
 * @ingroup sqliterepo
 * @brief
 * @details
 *
 * @{
 */

# include <metautils.h>

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
 * @param cache
 */
void sqlx_cache_clean(sqlx_cache_t *cache);

/**
 * @param cache
 */
void sqlx_cache_debug(sqlx_cache_t *cache);

/**
 * Similar to sqlx_cache_open_base2() and sqlx_cache_lock_base()
 * but in the same critical section.
 *
 * @param cache
 * @param key
 * @param lock
 * @param result
 * @return
 */
GError * sqlx_cache_open_and_lock_base(sqlx_cache_t *cache,
		const hashstr_t *key, gint *result);

/**
 *
 * @param cache
 * @param bd
 * @param force
 * @return
 */
GError * sqlx_cache_unlock_and_close_base(sqlx_cache_t *cache, gint bd,
		gboolean force);


/** Check for expired bases
 * @param cache
 * @param max_actions
 * @param pivot
 * @param end
 */
guint sqlx_cache_expire(sqlx_cache_t *cache, guint max_actions,
		GTimeVal *pivot, GTimeVal *end);

/** @} */

#endif
