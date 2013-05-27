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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.cache"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <glib.h>

#include "../metautils/lib/hashstr.h"
#include "../metautils/lib/metautils.h"

#include "./internals.h"
#include "./sqliterepo.h"
#include "./cache.h"

#define GET(R,I) ((R)->bases + (I))

#define BEACON_RESET(B) do { (B)->first = (B)->last = -1; } while (0)

struct beacon_s
{
	gint first;
	gint last;
};

enum sqlx_base_status_e
{
	SQLX_BASE_FREE=1,
	SQLX_BASE_IDLE,	  /*!< without user */
	SQLX_BASE_USED,	  /*!< with users. count_open then
						 * tells how many threads have marked the base
						 * to be kept open, and owner tells if the lock
						 * os currently owned by a thread. */
};

struct sqlx_base_s
{
	hashstr_t *name; /*!< This is registered in the DB */

	gint index; /*!< self reference */

	guint32 count_locks; /*!< Counts the number of locks asked by the same
						   user. This is the way we manage recursive locks.
						   Changed under the global lock. */

	guint32 count_open; /*!< Counts the number of times this base has been
						  explicitely opened by the user. Changed under the
						  base-local lock. */

	enum sqlx_base_status_e status; /*!< Changed under the global lock */

	GTimeVal last_update; /*!< Changed under the global lock */

	GThread *owner; /*!< The current owner of the database. Changed under the
					  global lock */
	GCond *cond;

	gpointer handle;

	struct {
		gint prev;
		gint next;
	} link; /*< Used to build a doubly-linked list */
};

typedef struct sqlx_base_s sqlx_base_t;

struct sqlx_cache_s
{
	gboolean used;

	GMutex *lock;
	GHashTable *bases_by_name;
	guint bases_count;
	sqlx_base_t *bases;
	GCond **cond_array;
	gsize cond_count;

	/* Doubly linked lists of tables, one by status */
	struct beacon_s beacon_free;
	struct beacon_s beacon_idle;
	struct beacon_s beacon_used;

	sqlx_cache_close_hook close_hook;
};

static GQuark gquark_log = 0;

/* ------------------------------------------------------------------------- */

static inline int
i_have_the_lock(sqlx_base_t *base)
{
	if (!base->count_locks || !base->owner)
		return 0;
	return base->owner == g_thread_self();
}

static inline gboolean
base_id_out(sqlx_cache_t *cache, gint bd)
{
	return bd<0 || (guint)bd >= cache->bases_count;
}

static inline const gchar *
sqlx_status_to_str(enum sqlx_base_status_e status)
{
	switch (status) {
		case SQLX_BASE_FREE:
			return "FREE";
		case SQLX_BASE_IDLE:
			return "IDLE";
		case SQLX_BASE_USED:
			return "USED";
		default:
			return "?";
	}
}

#ifdef HAVE_EXTRA_DEBUG
static void
sqlx_base_debug_func(const gchar *from, sqlx_base_t *base)
{
	(void) from;
	(void) base;

	SQLX_ASSERT(base);
	GRID_TRACE2("BASE [%d/%s]"
			" %"G_GUINT32_FORMAT"/%"G_GUINT32_FORMAT
			" LIST=%s [%d,%d]"
			" (%s)",
			base->index, (base->name ? hashstr_str(base->name) : ""),
			base->count_open, base->count_locks,
			sqlx_status_to_str(base->status),
			base->link.prev, base->link.next,
			from);
}

# define sqlx_base_debug(From,Base) do { sqlx_base_debug_func(From,Base); } while (0)
#else
# define sqlx_base_debug(From,Base) do {  } while (0)
#endif

static inline sqlx_base_t *
sqlx_get_by_id(sqlx_cache_t *cache, gint i)
{
	return base_id_out(cache, i) ? NULL : cache->bases + i;
}

static inline sqlx_base_t *
sqlx_next_by_id(sqlx_cache_t *cache, gint i)
{
	sqlx_base_t *current;

	return (current = sqlx_get_by_id(cache, i))
		? sqlx_get_by_id(cache, current->link.next)
		: NULL;
}

static inline sqlx_base_t *
sqlx_prev_by_id(sqlx_cache_t *cache, gint i)
{
	sqlx_base_t *current;

	return (current = sqlx_get_by_id(cache, i))
		? sqlx_get_by_id(cache, current->link.prev)
		: NULL;
}

static inline gint
sqlx_base_get_id(sqlx_base_t *base)
{
	return base ? base->index : -1;
}

static inline void
SQLX_REMOVE(sqlx_cache_t *cache, sqlx_base_t *base,
		struct beacon_s *beacon)
{
	sqlx_base_t *next, *prev;

	/* Update the beacon */
	if (beacon->first == base->index)
		beacon->first = sqlx_base_get_id(sqlx_next_by_id(cache, beacon->first));
	if (beacon->last == base->index)
		beacon->last = sqlx_base_get_id(sqlx_prev_by_id(cache, beacon->last));

	/* Update the previous and next */
	next = sqlx_get_by_id(cache, base->link.next);
	prev = sqlx_get_by_id(cache, base->link.prev);

	if (prev)
		prev->link.next = sqlx_base_get_id(next);
	if (next)
		next->link.prev = sqlx_base_get_id(prev);

	/* Update the base itself */
	base->status = 0;
	base->link.prev = -1;
	base->link.next = -1;
}

static inline void
SQLX_UNSHIFT(sqlx_cache_t *cache, sqlx_base_t *base,
		struct beacon_s *beacon, enum sqlx_base_status_e status)
{
	sqlx_base_t *first;

	base->link.prev = base->link.next = -1;
	base->link.next = beacon->first;

	first = sqlx_get_by_id(cache, beacon->first);
	if (first)
		first->link.prev = base->index;
	beacon->first = base->index;

	if (beacon->last < 0)
		beacon->last = base->index;

	base->status = status;
	g_get_current_time(&(base->last_update));
}

static inline void
sqlx_save_id(sqlx_cache_t *cache, sqlx_base_t *base)
{
	gpointer pointer_index;

	pointer_index = GINT_TO_POINTER(base->index + 1);
	g_hash_table_insert(cache->bases_by_name, base->name, pointer_index);
}

static inline gint
sqlx_lookup_id(sqlx_cache_t *cache, const hashstr_t *hs)
{
	gint result = -1;
	gpointer lookup_result;

	lookup_result = g_hash_table_lookup(cache->bases_by_name, hs);
	if (lookup_result != NULL)
		result = GPOINTER_TO_INT(lookup_result);

	return result - 1;
}

static inline void
sqlx_base_remove_from_list(sqlx_cache_t *cache, sqlx_base_t *base)
{
	enum sqlx_base_status_e status = base->status;

	switch (status) {
		case SQLX_BASE_FREE:
			SQLX_REMOVE(cache, base, &(cache->beacon_free));
			return;
		case SQLX_BASE_IDLE:
			SQLX_REMOVE(cache, base, &(cache->beacon_idle));
			return;
		case SQLX_BASE_USED:
			SQLX_REMOVE(cache, base, &(cache->beacon_used));
			return;
	}
}

static inline void
sqlx_base_add_to_list(sqlx_cache_t *cache, sqlx_base_t *base,
		enum sqlx_base_status_e status)
{
	SQLX_ASSERT(base->link.prev < 0);
	SQLX_ASSERT(base->link.next < 0);

	switch (status) {
		case SQLX_BASE_FREE:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_free), SQLX_BASE_FREE);
			return;
		case SQLX_BASE_IDLE:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_idle), SQLX_BASE_IDLE);
			g_get_current_time(&(base->last_update));
			return;
		case SQLX_BASE_USED:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_used), SQLX_BASE_USED);
			return;
	}
}

static inline void
sqlx_base_move_to_list(sqlx_cache_t *cache, sqlx_base_t *base,
		enum sqlx_base_status_e status)
{
	enum sqlx_base_status_e status0 = base->status;
	sqlx_base_remove_from_list(cache, base);
	sqlx_base_add_to_list(cache, base, status);

	(void) status0;
	GRID_TRACE2("BASE [%d/%s] moved from %s to %s",
			base->index,
			hashstr_str(base->name),
			sqlx_status_to_str(status0),
			sqlx_status_to_str(status));
}

static inline sqlx_base_t*
sqlx_poll_free_base(sqlx_cache_t *cache)
{
	sqlx_base_t *base;

	base = sqlx_get_by_id(cache, cache->beacon_free.first);
	if (!base) {
		errno = ENOENT;
		return NULL;
	}

	return base;
}

static inline GError *
sqlx_base_reserve(sqlx_cache_t *cache, const hashstr_t *hs,
		sqlx_base_t **result)
{
	sqlx_base_t *base;

	if (!(base = sqlx_poll_free_base(cache)))
		return g_error_new(gquark_log, SQLX_RC_TOOMANY, "too many bases");

	/* base reserved and in PENDING state */
	base->name = hashstr_dup(hs);
	base->count_locks = 0;
	base->count_open = 0;
	base->handle = NULL;
	g_get_current_time(&(base->last_update));
	base->owner = g_thread_self();
	sqlx_base_move_to_list(cache, base, SQLX_BASE_USED);
	sqlx_save_id(cache, base);

	sqlx_base_debug(__FUNCTION__, base);
	*result = base;
	return NULL;
}

static void
__base_lock(sqlx_cache_t *cache, sqlx_base_t *base)
{
	GThread *self = g_thread_self();

	if (!base->owner) {
		base->owner = self;
		base->count_locks = 1;
	}
	else if (base->owner == self)
		base->count_locks ++;
	else {
		while (base->owner && base->owner != self)
			g_cond_wait(base->cond, cache->lock);
		base->count_locks = 1;
		base->owner = self;
	}
}

static void
__base_unlock(sqlx_base_t *base)
{
	if (base->count_locks) {
		if (-- base->count_locks)
			return;
	}
	base->owner = NULL;
}

/**
 * PRE:
 * - The base must be owned by the current thread
 * - it must be opened only once and locked only once
 * - the cache-wide lock must be owned by the current thread
 *
 * POST:
 * - The base is returned to the FREE list
 * - the base is not owned by any thread
 * - The cache-wide lock is still owned
 */
static void
_expire_base(sqlx_cache_t *cache, sqlx_base_t *b)
{
	hashstr_t *n;

	sqlx_base_debug("FREEING", b);
	SQLX_ASSERT(b->owner != NULL);

	/* the base is for the given thread, it is time to REALLY close it.
	 * But this can take a lot of time. So we can release the pool,
	 * free the handlei and unlock the cache */
	g_cond_signal(b->cond);
	g_mutex_unlock(cache->lock);
	if (cache->close_hook)
		cache->close_hook(b->handle);
	b->handle = NULL;
	g_mutex_lock(cache->lock);

	n = b->name;
	b->count_locks = 0;
	b->owner = NULL;
	b->name = NULL;
	b->count_locks = 0;
	b->count_open = 0;
	b->last_update.tv_sec = b->last_update.tv_usec = 0;
	sqlx_base_move_to_list(cache, b, SQLX_BASE_FREE);
	g_hash_table_remove(cache->bases_by_name, n);

	g_free(n);
}

static gint
sqlx_expire_first_idle_base(const gchar *func, sqlx_cache_t *cache, GTimeVal *pivot)
{
	gint bd_idle;
	sqlx_base_t *b;

	(void) func;
	GRID_TRACE2("%s(%p,[%ld,%ld])", __FUNCTION__, (void*)cache,
			pivot?pivot->tv_sec:0, pivot?pivot->tv_usec:0);

	SQLX_ASSERT(cache != NULL);

	/* Poll the next idle base */
	bd_idle = cache->beacon_idle.last;
	if (bd_idle < 0) {
		GRID_TRACE2("No idle base");
		return 0;
	}

	b = GET(cache, bd_idle);

	if (pivot && gtv_bigger(&(b->last_update), pivot))
		return 0;

	/* At this point, I have the global lock, and the base is IDLE.
	 * We know no one have the lock on it. So we make the base USED
	 * and we get the lock on it. because we have the lock, it is
	 * protected from other uses */

	SQLX_ASSERT(b->count_open == 0);
	SQLX_ASSERT(b->count_locks == 0);
	SQLX_ASSERT(b->owner == NULL);

	b->count_open = 1; /* make it used ... */
	b->owner = g_thread_self(); /* ...by the current thread */
	sqlx_base_move_to_list(cache, b, SQLX_BASE_USED);
	b->count_locks = 1; /* make it locked */

	_expire_base(cache, b);
	return 1;
}

static void
sqlx_cache_reset_bases(sqlx_cache_t *cache, guint max)
{
	guint old, i;

	g_mutex_lock(cache->lock);

	if (cache->used) {
		GRID_WARN("SQLX base cahce cannot be reset: already in use");
	}
	else {
		BEACON_RESET(&(cache->beacon_free));
		BEACON_RESET(&(cache->beacon_idle));
		BEACON_RESET(&(cache->beacon_used));

		if (cache->bases)
			g_free(cache->bases);

		old = cache->bases_count;
		cache->bases_count = max;
		cache->bases = g_malloc0(cache->bases_count * sizeof(sqlx_base_t));

		for (i = cache->bases_count - 1; i!=0 ;i--) {
			sqlx_base_t *base = cache->bases + i;
			base->index = i;
			base->link.prev = base->link.next = -1;
			SQLX_UNSHIFT(cache, base, &(cache->beacon_free), SQLX_BASE_FREE);
			base->cond = cache->cond_array[i % cache->cond_count];
		}

		GRID_INFO("SQLX cache size change from %u to %u", old,
				cache->bases_count);
	}

	g_mutex_unlock(cache->lock);
}

/* ------------------------------------------------------------------------- */

sqlx_cache_t *
sqlx_cache_set_max_bases(sqlx_cache_t *cache, guint max)
{
	GRID_TRACE2("%s(%p,%u)", __FUNCTION__, cache, max);
	SQLX_ASSERT(cache != NULL);
	SQLX_ASSERT(max < 65536);
	sqlx_cache_reset_bases(cache, max);
	return cache;
}

sqlx_cache_t *
sqlx_cache_set_close_hook(sqlx_cache_t *cache,
		sqlx_cache_close_hook hook)
{
	SQLX_ASSERT(cache != NULL);
	cache->close_hook = hook;
	return cache;
}

sqlx_cache_t *
sqlx_cache_init(void)
{
	guint i;
	sqlx_cache_t *cache;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	cache = g_malloc0(sizeof(*cache));
	cache->used = FALSE;
	cache->lock = g_mutex_new();
	cache->bases_by_name = g_hash_table_new_full(
			(GHashFunc)hashstr_hash,
			(GEqualFunc)hashstr_equal,
			NULL, NULL);
	cache->bases_count = SQLX_MAX_BASES;
	cache->cond_count = SQLX_MAX_COND;
	cache->cond_array = g_malloc0(cache->cond_count * sizeof(void*));
	BEACON_RESET(&(cache->beacon_free));
	BEACON_RESET(&(cache->beacon_idle));
	BEACON_RESET(&(cache->beacon_used));

	for (i=0; i<cache->cond_count ;i++)
		cache->cond_array[i] = g_cond_new();

	sqlx_cache_reset_bases(cache, cache->bases_count);
	return cache;
}

void
sqlx_cache_clean(sqlx_cache_t *cache)
{
	guint i, bd;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	GRID_DEBUG("%s(%p) *** CLEANUP ***", __FUNCTION__, (void*)cache);
	if (!cache)
		return;

	if (cache->bases) {
		for (bd=0; bd < cache->bases_count ;bd++) {
			sqlx_base_t *base = cache->bases + bd;

			switch (base->status) {
				case SQLX_BASE_FREE:
					break;
				case SQLX_BASE_IDLE:
				case SQLX_BASE_USED:
					sqlx_base_debug(__FUNCTION__, base);
					break;
			}
		}
		g_free(cache->bases);
	}

	if (cache->lock)
		g_mutex_free(cache->lock);
	if (cache->cond_array) {
		for (i=0; i<cache->cond_count ;i++)
			g_cond_free(cache->cond_array[i]);
		g_free(cache->cond_array);
	}
	if (cache->bases_by_name)
		g_hash_table_destroy(cache->bases_by_name);

	g_free(cache);
}

GError *
sqlx_cache_open_and_lock_base(sqlx_cache_t *cache, const hashstr_t *hname,
		gint *result)
{
	gint bd;
	GError *err = NULL;
	sqlx_base_t *base = NULL;

	GRID_TRACE2("%s(%p,%s,%p)", __FUNCTION__, (void*)cache,
			hname ? hashstr_str(hname) : "NULL", (void*)result);
	SQLX_ASSERT(cache != NULL);
	SQLX_ASSERT(hname != NULL);
	SQLX_ASSERT(result != NULL);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;
retry:
	bd = sqlx_lookup_id(cache, hname);
	if (bd < 0) {
		if (!(err = sqlx_base_reserve(cache, hname, &base))) {
			bd = base->index;
			base->count_open = 1;
			sqlx_base_debug("OPEN", base);
			__base_lock(cache, base);
			sqlx_base_debug("LOCKED", base);
			*result = base->index;
		}
		else {
			GRID_DEBUG("No base available for [%s] (%d %s)",
					hashstr_str(hname), err->code, err->message);
			if (sqlx_expire_first_idle_base(__FUNCTION__, cache, NULL) >= 0) {
				g_clear_error(&err);
				goto retry;
			}
		}
	}
	else {
		base = GET(cache, bd);
		sqlx_base_debug("FOUND", base);
		switch (base->status) {
			case SQLX_BASE_FREE:
				err = g_error_new(gquark_log, SQLX_RC_DESIGN_ERROR,
						"free base referenced");
				break;
			case SQLX_BASE_IDLE:
				sqlx_base_move_to_list(cache, base, SQLX_BASE_USED);
			case SQLX_BASE_USED:
				base->count_open ++;
				sqlx_base_debug("OPENED", base);
				__base_lock(cache, base);
				sqlx_base_debug("LOCKED", base);
				*result = base->index;
				break;
		}
	}

	if (base && !err)
		sqlx_base_debug(__FUNCTION__, base);
	if (base)
		g_cond_signal(base->cond);
	g_mutex_unlock(cache->lock);
	return err;
}

GError *
sqlx_cache_unlock_and_close_base(sqlx_cache_t *cache, gint bd, gboolean force)
{
	GError *err = NULL;
	sqlx_base_t *base;

	GRID_TRACE2("%s(%p,%d,%d)", __FUNCTION__, (void*)cache, bd, force);

	SQLX_ASSERT(cache != NULL);
	if (base_id_out(cache, bd))
		return g_error_new(gquark_log, SQLX_RC_INVALID_BASE_ID,
				"invalid base id=%d", bd);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;

	base = GET(cache,bd);
	switch (base->status) {
		case SQLX_BASE_FREE:
			err = g_error_new(gquark_log, SQLX_RC_BASE_CLOSED, "invalid base");
			break;
		case SQLX_BASE_IDLE:
			err = g_error_new(gquark_log, SQLX_RC_BASE_CLOSED, "base closed");
			break;
		case SQLX_BASE_USED:

			if (!i_have_the_lock(base)) {
				err = g_error_new(gquark_log, SQLX_RC_DESIGN_ERROR,
						"base not locked");
				break;
			}

			__base_lock(cache, base);
			if (-- base->count_open <= 0) { /* to be closed */
				SQLX_ASSERT(base->count_locks == 2);
				if (force) {
					_expire_base(cache, base);
				}
				else {
					sqlx_base_debug("CLOSING", base);
					base->owner = NULL;
					base->count_locks = 0;
					sqlx_base_move_to_list(cache, base, SQLX_BASE_IDLE);
				}
			}
			else { /* to be kept open */
				if (base->count_locks < 2) {
					err = g_error_new(gquark_log, SQLX_RC_DESIGN_ERROR,
							"base not locked");
					++ base->count_open;
				}
				else
					__base_unlock(base);
			}
			__base_unlock(base);
			break;
	}

	if (base && !err)
		sqlx_base_debug(__FUNCTION__, base);
	g_cond_signal(base->cond);
	g_mutex_unlock(cache->lock);
	return err;
}

void
sqlx_cache_debug(sqlx_cache_t *cache)
{
	GHashTableIter iter;
	gpointer k, v;
	guint bd;

	SQLX_ASSERT(cache != NULL);

	GRID_DEBUG("--- REPO %p -----------------", (void*)cache);
	GRID_DEBUG(" > used [%d, %d]",
			cache->beacon_used.first, cache->beacon_used.last);
	GRID_DEBUG(" > idle [%d, %d]",
			cache->beacon_idle.first, cache->beacon_idle.last);
	GRID_DEBUG(" > free [%d, %d]",
			cache->beacon_free.first, cache->beacon_free.last);

	/* Dump all the bases */
	for (bd=0; bd < cache->bases_count ;bd++)
		sqlx_base_debug(__FUNCTION__, GET(cache,bd));

	/* Now dump all te references in the hashtable */
	g_hash_table_iter_init(&iter, cache->bases_by_name);
	while (g_hash_table_iter_next(&iter, &k, &v))
		GRID_DEBUG("REF %d <- %s", GPOINTER_TO_INT(v), hashstr_str(k));
}

guint
sqlx_cache_expire(sqlx_cache_t *cache, guint max, GTimeVal *pivot,
		GTimeVal *end)
{
	guint nb;
	GTimeVal now;

	GRID_TRACE2("%s(%p,%u,%p,%p)", __FUNCTION__, (void*)cache, max, pivot, end);
	SQLX_ASSERT(cache != NULL);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;

	for (nb=0; !max || nb < max ; nb++) {
		g_get_current_time(&now);
		if (end && gtv_bigger(&now, end))
			break;
		if (!sqlx_expire_first_idle_base(__FUNCTION__, cache, pivot))
			break;
	}

	g_mutex_unlock(cache->lock);
	return nb;
}

gpointer
sqlx_cache_get_handle(sqlx_cache_t *cache, gint bd)
{
	sqlx_base_t *base;

	SQLX_ASSERT(cache != NULL);
	SQLX_ASSERT(bd >= 0);

	base = GET(cache,bd);
	SQLX_ASSERT(base != NULL);

	return base->handle;
}

void
sqlx_cache_set_handle(sqlx_cache_t *cache, gint bd, gpointer sq3)
{
	sqlx_base_t *base;

	SQLX_ASSERT(cache != NULL);
	SQLX_ASSERT(bd >= 0);

	base = GET(cache,bd);
	SQLX_ASSERT(base != NULL);

	base->handle = sq3;
}

