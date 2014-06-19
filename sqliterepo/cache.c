#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqliterepo"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <malloc.h>

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "cache.h"
#include "internals.h"

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
	SQLX_BASE_IDLE_HOT,	  /*!< without user */
	SQLX_BASE_USED,	  /*!< with users. count_open then
						 * tells how many threads have marked the base
						 * to be kept open, and owner tells if the lock
						 * os currently owned by a thread. */
	SQLX_BASE_CLOSING, // base being closed, wait for notification and retry on it
};

struct sqlx_base_s
{
	hashstr_t *name; /*!< This is registered in the DB */

	GThread *owner; /*!< The current owner of the database. Changed under the
					  global lock */
	GCond *cond;

	gpointer handle;

	GTimeVal last_update; /*!< Changed under the global lock */

	struct {
		gint prev;
		gint next;
	} link; /*< Used to build a doubly-linked list */

	guint32 heat;

	guint32 count_open; /*!< Counts the number of times this base has been
						  explicitely opened and locked by the user. */

	gint index; /*!< self reference */

	enum sqlx_base_status_e status; /*!< Changed under the global lock */
};

typedef struct sqlx_base_s sqlx_base_t;

struct sqlx_cache_s
{
	gboolean used;

	GMutex *lock;
	GTree *bases_by_name;
	guint bases_count;
	sqlx_base_t *bases;
	GCond **cond_array;
	gsize cond_count;
	glong open_timeout; // milliseconds

	guint32 heat_threshold;
	time_t cool_grace_delay;
	time_t hot_grace_delay;

	/* Doubly linked lists of tables, one by status */
	struct beacon_s beacon_free;
	struct beacon_s beacon_idle;
	struct beacon_s beacon_idle_hot;
	struct beacon_s beacon_used;

	sqlx_cache_close_hook close_hook;
};

/* ------------------------------------------------------------------------- */

static inline gboolean
base_id_out(sqlx_cache_t *cache, gint bd)
{
	return (bd < 0) || ((guint)bd) >= cache->bases_count;
}

static inline const gchar *
sqlx_status_to_str(enum sqlx_base_status_e status)
{
	switch (status) {
		case SQLX_BASE_FREE:
			return "FREE";
		case SQLX_BASE_IDLE:
			return "IDLE";
		case SQLX_BASE_IDLE_HOT:
			return "IDLE_HOT";
		case SQLX_BASE_USED:
			return "USED";
		case SQLX_BASE_CLOSING:
			return "CLOSING";
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

	EXTRA_ASSERT(base);
	GRID_TRACE2("BASE [%d/%s]"
			" %"G_GUINT32_FORMAT
			" LIST=%s [%d,%d]"
			" (%s)",
			base->index, (base->name ? hashstr_str(base->name) : ""),
			base->count_open,
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
	gpointer pointer_index = GINT_TO_POINTER(base->index + 1);
	g_tree_replace(cache->bases_by_name, base->name, pointer_index);
}

static inline gint
sqlx_lookup_id(sqlx_cache_t *cache, const hashstr_t *hs)
{
	gpointer lookup_result = g_tree_lookup(cache->bases_by_name, hs);
	return !lookup_result ? -1 : (GPOINTER_TO_INT(lookup_result) - 1);
}

static inline void
sqlx_base_remove_from_list(sqlx_cache_t *cache, sqlx_base_t *base)
{
	switch (base->status) {
		case SQLX_BASE_FREE:
			SQLX_REMOVE(cache, base, &(cache->beacon_free));
			return;
		case SQLX_BASE_IDLE:
			SQLX_REMOVE(cache, base, &(cache->beacon_idle));
			return;
		case SQLX_BASE_IDLE_HOT:
			SQLX_REMOVE(cache, base, &(cache->beacon_idle_hot));
			return;
		case SQLX_BASE_USED:
			SQLX_REMOVE(cache, base, &(cache->beacon_used));
			return;
		case SQLX_BASE_CLOSING:
			EXTRA_ASSERT(base->link.prev < 0);
			EXTRA_ASSERT(base->link.next < 0);
			return;
	}
}

static inline void
sqlx_base_add_to_list(sqlx_cache_t *cache, sqlx_base_t *base,
		enum sqlx_base_status_e status)
{
	EXTRA_ASSERT(base->link.prev < 0);
	EXTRA_ASSERT(base->link.next < 0);

	switch (status) {
		case SQLX_BASE_FREE:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_free), SQLX_BASE_FREE);
			return;
		case SQLX_BASE_IDLE:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_idle), SQLX_BASE_IDLE);
			return;
		case SQLX_BASE_IDLE_HOT:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_idle_hot), SQLX_BASE_IDLE_HOT);
			return;
		case SQLX_BASE_USED:
			SQLX_UNSHIFT(cache, base, &(cache->beacon_used), SQLX_BASE_USED);
			return;
		case SQLX_BASE_CLOSING:
			base->status = status;
			return;
	}
}

static inline void
sqlx_base_move_to_list(sqlx_cache_t *cache, sqlx_base_t *base,
		enum sqlx_base_status_e status)
{
	register enum sqlx_base_status_e status0;

	if (status != (status0 = base->status)) {
		sqlx_base_remove_from_list(cache, base);
		sqlx_base_add_to_list(cache, base, status);
	}

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
		return NEWERROR(500, "too many bases");

	/* base reserved and in PENDING state */
	base->name = hashstr_dup(hs);
	base->count_open = 1;
	base->handle = NULL;
	base->owner = g_thread_self();
	sqlx_base_move_to_list(cache, base, SQLX_BASE_USED);
	sqlx_save_id(cache, base);

	sqlx_base_debug(__FUNCTION__, base);
	*result = base;
	return NULL;
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
	hashstr_t *n = b->name;
	gpointer handle = b->handle;

	sqlx_base_debug("FREEING", b);
	EXTRA_ASSERT(b->owner != NULL);
	EXTRA_ASSERT(b->count_open == 0);
	EXTRA_ASSERT(b->status == SQLX_BASE_USED);

	sqlx_base_move_to_list(cache, b, SQLX_BASE_CLOSING);

	/* the base is for the given thread, it is time to REALLY close it.
	 * But this can take a lot of time. So we can release the pool,
	 * free the handle and unlock the cache */
	g_cond_signal(b->cond);
	g_mutex_unlock(cache->lock);
	if (cache->close_hook)
		cache->close_hook(handle);
	g_mutex_lock(cache->lock);

	b->handle = NULL;
	b->owner = NULL;
	b->name = NULL;
	b->count_open = 0;
	b->last_update.tv_sec = b->last_update.tv_usec = 0;
	sqlx_base_move_to_list(cache, b, SQLX_BASE_FREE);

	g_tree_remove(cache->bases_by_name, n);

	g_free(n);
}

static gint
_expire_specific_base(sqlx_cache_t *cache, sqlx_base_t *b, GTimeVal *now,
		time_t grace_delay)
{
	if (now) {
		GTimeVal pivot;
		memcpy(&pivot, now, sizeof(GTimeVal));
		g_time_val_add(&pivot, grace_delay * -1000000L);
		if (gtv_bigger(&(b->last_update), &pivot))
			return 0;
	}

	/* At this point, I have the global lock, and the base is IDLE.
	 * We know no one have the lock on it. So we make the base USED
	 * and we get the lock on it. because we have the lock, it is
	 * protected from other uses */

	EXTRA_ASSERT(b->status == SQLX_BASE_IDLE || b->status == SQLX_BASE_IDLE_HOT);
	EXTRA_ASSERT(b->count_open == 0);
	EXTRA_ASSERT(b->owner == NULL);

	/* make it used and locked by the current thread */
	b->owner = g_thread_self();
	sqlx_base_move_to_list(cache, b, SQLX_BASE_USED);

	_expire_base(cache, b);
	return 1;
}

static gint
sqlx_expire_first_idle_base(sqlx_cache_t *cache, GTimeVal *now)
{
	gint rc = 0, bd_idle;

	/* Poll the next idle base, and respect the increasing order of the 'heat' */
	if (0 <= (bd_idle = cache->beacon_idle.last))
		rc = _expire_specific_base(cache, GET(cache, bd_idle), now,
				cache->cool_grace_delay);

	if (!rc && 0 <= (bd_idle = cache->beacon_idle_hot.last))
		rc = _expire_specific_base(cache, GET(cache, bd_idle), now,
				cache->hot_grace_delay);

	return rc;
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
		BEACON_RESET(&(cache->beacon_idle_hot));
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
	EXTRA_ASSERT(cache != NULL);
	EXTRA_ASSERT(max < 65536);
	sqlx_cache_reset_bases(cache, max);
	return cache;
}

sqlx_cache_t *
sqlx_cache_set_close_hook(sqlx_cache_t *cache,
		sqlx_cache_close_hook hook)
{
	EXTRA_ASSERT(cache != NULL);
	cache->close_hook = hook;
	return cache;
}

sqlx_cache_t *
sqlx_cache_set_open_timeout(sqlx_cache_t *cache, glong timeout)
{
	EXTRA_ASSERT(cache != NULL);
	cache->open_timeout = timeout;
	return cache;
}

sqlx_cache_t *
sqlx_cache_init(void)
{
	guint i;
	sqlx_cache_t *cache;

	cache = g_malloc0(sizeof(*cache));
	cache->cool_grace_delay = SQLX_GRACE_DELAY_COOL;
	cache->hot_grace_delay = SQLX_GRACE_DELAY_HOT;
	cache->heat_threshold = 1;
	cache->used = FALSE;
	cache->lock = g_mutex_new();
	cache->bases_by_name = g_tree_new_full(hashstr_quick_cmpdata,
			NULL, NULL, NULL);
	cache->bases_count = SQLX_MAX_BASES;
	cache->cond_count = SQLX_MAX_COND;
	cache->cond_array = g_malloc0(cache->cond_count * sizeof(void*));
	cache->open_timeout = DEFAULT_CACHE_OPEN_TIMEOUT;
	BEACON_RESET(&(cache->beacon_free));
	BEACON_RESET(&(cache->beacon_idle));
	BEACON_RESET(&(cache->beacon_idle_hot));
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
				case SQLX_BASE_IDLE_HOT:
				case SQLX_BASE_USED:
					sqlx_base_debug(__FUNCTION__, base);
					break;
				case SQLX_BASE_CLOSING:
					GRID_ERROR("Base being closed while the cache is being cleaned");
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
		g_tree_destroy(cache->bases_by_name);

	g_free(cache);
}

GError *
sqlx_cache_open_and_lock_base(sqlx_cache_t *cache, const hashstr_t *hname,
		gint *result)
{
	gint bd;
	GError *err = NULL;
	sqlx_base_t *base = NULL;
	GTimeVal *deadline = g_alloca(sizeof(GTimeVal));

	GRID_TRACE2("%s(%p,%s,%p)", __FUNCTION__, (void*)cache,
			hname ? hashstr_str(hname) : "NULL", (void*)result);
	EXTRA_ASSERT(cache != NULL);
	EXTRA_ASSERT(hname != NULL);
	EXTRA_ASSERT(result != NULL);

	if (cache->open_timeout >= 0) {
		g_get_current_time(deadline);
		g_time_val_add(deadline, cache->open_timeout * 1000);
	} else {
		// wait forever
		deadline = NULL;
	}

	g_mutex_lock(cache->lock);
	cache->used = TRUE;
retry:
	bd = sqlx_lookup_id(cache, hname);
	if (bd < 0) {
		if (!(err = sqlx_base_reserve(cache, hname, &base))) {
			bd = base->index;
			*result = base->index;
			sqlx_base_debug("OPEN", base);
		}
		else {
			GRID_DEBUG("No base available for [%s] (%d %s)",
					hashstr_str(hname), err->code, err->message);
			if (sqlx_expire_first_idle_base(cache, NULL) >= 0) {
				g_clear_error(&err);
				goto retry;
			}
		}
	}
	else {
		base = GET(cache, bd);
		switch (base->status) {

			case SQLX_BASE_FREE:
				EXTRA_ASSERT(base->count_open == 0);
				EXTRA_ASSERT(base->owner == NULL);
				GRID_ERROR("free base referenced");
				g_assert_not_reached();
				break;

			case SQLX_BASE_IDLE:
			case SQLX_BASE_IDLE_HOT:
				EXTRA_ASSERT(base->count_open == 0);
				EXTRA_ASSERT(base->owner == NULL);
				sqlx_base_move_to_list(cache, base, SQLX_BASE_USED);
				base->count_open ++;
				base->owner = g_thread_self();
				*result = base->index;
				break;

			case SQLX_BASE_USED:
				EXTRA_ASSERT(base->count_open > 0);
				EXTRA_ASSERT(base->owner != NULL);
				if (base->owner != g_thread_self()) {
					GRID_DEBUG("Base [%s] in use by another thread (%X), waiting...",
							hashstr_str(hname), compute_thread_id(base->owner));
					// The lock is held by another thread/request
					if (g_cond_timed_wait(base->cond, cache->lock, deadline)) {
						GRID_DEBUG("Retrying to open [%s]", hashstr_str(hname));
						goto retry;
					} else {
						if (cache->open_timeout > 0) {
							err = NEWERROR(CODE_UNAVAILABLE,
								"database currently in use by another request"
								" (we waited %ldms)",
								cache->open_timeout);
						} else {
							err = NEWERROR(CODE_UNAVAILABLE,
								"database currently in use by another request");
						}
						GRID_DEBUG("failed to open base: "
								"in use by another request (thread %X)",
								compute_thread_id(base->owner));
						break;
					}
				}
				base->owner = g_thread_self();
				base->count_open ++;
				*result = base->index;
				break;

			case SQLX_BASE_CLOSING:
				EXTRA_ASSERT(base->owner != NULL);
				// Just wait for a notification then retry
				if (g_cond_timed_wait(base->cond, cache->lock, deadline))
					goto retry;
				else {
					err = NEWERROR(CODE_UNAVAILABLE,
							"Database stuck in closing state");
					break;
				}
		}
	}

	if (base) {
		if (!err) {
			sqlx_base_debug(__FUNCTION__, base);
			EXTRA_ASSERT(base->owner == g_thread_self());
			EXTRA_ASSERT(base->count_open > 0);
		}
		g_cond_signal(base->cond);
	}
	g_mutex_unlock(cache->lock);
	return err;
}

GError *
sqlx_cache_unlock_and_close_base(sqlx_cache_t *cache, gint bd, gboolean force)
{
	GError *err = NULL;
	sqlx_base_t *base;

	GRID_TRACE2("%s(%p,%d,%d)", __FUNCTION__, (void*)cache, bd, force);

	EXTRA_ASSERT(cache != NULL);
	if (base_id_out(cache, bd))
		return NEWERROR(500, "invalid base id=%d", bd);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;

	base = GET(cache,bd);
	switch (base->status) {

		case SQLX_BASE_FREE:
			EXTRA_ASSERT(base->count_open == 0);
			EXTRA_ASSERT(base->owner == NULL);
			GRID_ERROR("Trying to close a free base");
			g_assert_not_reached();
			break;

		case SQLX_BASE_IDLE:
		case SQLX_BASE_IDLE_HOT:
			EXTRA_ASSERT(base->count_open == 0);
			EXTRA_ASSERT(base->owner == NULL);
			GRID_ERROR("Trying to close a closed base");
			g_assert_not_reached();
			break;

		case SQLX_BASE_USED:
			EXTRA_ASSERT(base->count_open > 0);
			// held by the current thread
			if (!(-- base->count_open)) { // to be closed
				if (force) {
					_expire_base(cache, base);
				}
				else {
					sqlx_base_debug("CLOSING", base);
					base->owner = NULL;
					if (base->heat >= cache->heat_threshold)
						sqlx_base_move_to_list(cache, base, SQLX_BASE_IDLE_HOT);
					else
						sqlx_base_move_to_list(cache, base, SQLX_BASE_IDLE);
				}
			}
			break;

		case SQLX_BASE_CLOSING:
			EXTRA_ASSERT(base->owner != NULL);
			EXTRA_ASSERT(base->owner != g_thread_self());
			GRID_ERROR("Trying to close a base being closed");
			g_assert_not_reached();
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
	EXTRA_ASSERT(cache != NULL);

	if (!GRID_DEBUG_ENABLED())
		return;

	GRID_DEBUG("--- REPO %p -----------------", (void*)cache);
	GRID_DEBUG(" > used     [%d, %d]",
			cache->beacon_used.first, cache->beacon_used.last);
	GRID_DEBUG(" > idle     [%d, %d]",
			cache->beacon_idle.first, cache->beacon_idle.last);
	GRID_DEBUG(" > idle_hot [%d, %d]",
			cache->beacon_idle_hot.first, cache->beacon_idle_hot.last);
	GRID_DEBUG(" > free     [%d, %d]",
			cache->beacon_free.first, cache->beacon_free.last);

	/* Dump all the bases */
	for (guint bd=0; bd < cache->bases_count ;bd++)
		sqlx_base_debug(__FUNCTION__, GET(cache,bd));

	/* Now dump all te references in the hashtable */
	gboolean runner(gpointer k, gpointer v, gpointer u) {
		(void) u;
		GRID_DEBUG("REF %d <- %s", GPOINTER_TO_INT(v), hashstr_str(k));
		return FALSE;
	}
	g_tree_foreach(cache->bases_by_name, runner, NULL);
}

guint
sqlx_cache_expire_all(sqlx_cache_t *cache)
{
	guint nb;

	EXTRA_ASSERT(cache != NULL);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;
	for (nb=0; sqlx_expire_first_idle_base(cache, NULL) ;nb++) { }
	g_mutex_unlock(cache->lock);

	return nb;
}

guint
sqlx_cache_expire(sqlx_cache_t *cache, guint max, GTimeVal *end)
{
	guint nb;

	EXTRA_ASSERT(cache != NULL);

	g_mutex_lock(cache->lock);
	cache->used = TRUE;

	for (nb=0; !max || nb < max ; nb++) {
		GTimeVal now;
		g_get_current_time(&now);
		if (end && gtv_bigger(&now, end))
			break;
		if (!sqlx_expire_first_idle_base(cache, &now))
			break;
	}

	g_mutex_unlock(cache->lock);

	/* Force malloc to release memory to the system.
	 * Allow 1MiB of unused but not released memory. */
	malloc_trim(1024 * 1024);

	return nb;
}

gpointer
sqlx_cache_get_handle(sqlx_cache_t *cache, gint bd)
{
	sqlx_base_t *base;

	EXTRA_ASSERT(cache != NULL);
	EXTRA_ASSERT(bd >= 0);

	base = GET(cache,bd);
	EXTRA_ASSERT(base != NULL);

	return base->handle;
}

void
sqlx_cache_set_handle(sqlx_cache_t *cache, gint bd, gpointer sq3)
{
	sqlx_base_t *base;

	EXTRA_ASSERT(cache != NULL);
	EXTRA_ASSERT(bd >= 0);

	base = GET(cache,bd);
	EXTRA_ASSERT(base != NULL);

	base->handle = sq3;
}

static guint
_count_beacon(sqlx_cache_t *cache, struct beacon_s *beacon)
{
	guint count = 0;
	g_mutex_lock(cache->lock);
	for (gint idx = beacon->first; idx != -1 ;) {
		++ count;
		idx = GET(cache, idx)->link.next;
	}
	g_mutex_unlock(cache->lock);
	return count;
}

struct cache_counts_s
sqlx_cache_count(sqlx_cache_t *cache)
{
	struct cache_counts_s count;

	memset(&count, 0, sizeof(count));
	if (cache) {
		count.max = cache->bases_count;
		count.cold = _count_beacon(cache, &cache->beacon_idle);
		count.hot = _count_beacon(cache, &cache->beacon_idle_hot);
		count.used = _count_beacon(cache, &cache->beacon_used);
	}

	return count;
}

