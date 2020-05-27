/*
OpenIO SDS load-balancing
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oio_core.h>

#include <string.h>

#include <json-c/json.h>

#include <core/lb_variables.h>

#include "internals.h"

typedef guint32 generation_t;

#define OIO_LB_SHUFFLE_JUMP ((1UL << 31) - 1)

/* This special target matches any service, any location. */
#define OIO_LB_JOKER_SVC_TARGET "__any_slot"

#define PREFIX_SLOT_SKEW ".rawx-"
#define SUFFIX_SLOT_SKEW "XXXXXXXX"
#define HEXA "0123456789ABCDEF"

guint64 _prime_numbers[] = {
	524269u, 524261u, 524257u,
	2147483629u, 2147483587u, 2147483579u, 2147483563u,
	0u
};

typedef guint16 oio_refcount_t;

struct oio_lb_pool_vtable_s
{
	void (*destroy) (struct oio_lb_pool_s *self);

	GError* (*poll) (struct oio_lb_pool_s *self,
			const oio_location_t * avoids,
			oio_lb_on_id_f on_id, gboolean *flawed);

	GError* (*patch) (struct oio_lb_pool_s *self,
			const oio_location_t * avoids,
			const oio_location_t * known,
			oio_lb_on_id_f on_id, gboolean *flawed);

	struct oio_lb_item_s* (*get_item) (struct oio_lb_pool_s *self,
			const char *id);
};

struct oio_lb_pool_abstract_s
{
	struct oio_lb_pool_vtable_s *vtable;
	gchar *name;
};

#define WRITER_LOCK_DO(Lock,Action) do { \
	g_rw_lock_writer_lock(Lock);\
	gint64 _lock_start = oio_ext_monotonic_time();\
	Action;\
	gint64 _lock_elapsed = oio_ext_monotonic_time() - _lock_start;\
	g_rw_lock_writer_unlock(Lock);\
	if (_lock_elapsed > oio_lb_writer_lock_alert_delay) {\
		GRID_NOTICE("LOCK total=%"G_GINT64_FORMAT" (%"G_GINT64_FORMAT"/%s:%d)",\
			_lock_elapsed, _lock_elapsed, __FUNCTION__, __LINE__);\
	}\
} while (0)

#define CFG_CALL(self,F) VTABLE_CALL(self,struct oio_lb_pool_abstract_s*,F)

void
oio_lb_pool__destroy (struct oio_lb_pool_s *self)
{
	CFG_CALL(self,destroy)(self);
}

GError*
oio_lb_pool__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	CFG_CALL(self,poll)(self, avoids, on_id, flawed);
}

GError*
oio_lb_pool__patch(struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		const oio_location_t * known,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	CFG_CALL(self, patch)(self, avoids, known, on_id, flawed);
}

struct oio_lb_item_s *
oio_lb_pool__get_item(struct oio_lb_pool_s *self,
		const char *id)
{
	CFG_CALL(self, get_item)(self, id);
}


/* -------------------------------------------------------------------------- */

/* Map service IDs to addresses <service_id, (addr, tls)> */

static GRWLock service_id_to_addr_lock;

static GTree *service_id_to_addr = NULL;  /* <gchar*> -> <gchar*> */

struct addr_and_tls_s {
	gchar addr[STRLEN_ADDRINFO];
	gchar tls[STRLEN_ADDRINFO];
};

static void __attribute__ ((constructor))
_oio_service_id_cache_constructor(void)
{
	static volatile guint lazy_init = 1;
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_rw_lock_init(&service_id_to_addr_lock);
			service_id_to_addr =
				g_tree_new_full(oio_str_casecmp3, NULL, g_free, g_free);
		}
	}
}

static const gchar *
_oio_service_id_parse(const gchar* service_id)
{
	/* FIXME(mb): we should use meta1_url_shift_addr
	 * but it would add a dependency on metautils */

	const gchar *s = strchr(service_id, '|');
	if (s)
		s = strchr(s+1, '|');
	if (s)
		s++;

	return s;
}

static void
_oio_service_id_cache_add_addr(const gchar* service_id, const gchar* addr, const gchar *tls)
{
	const gchar *id = _oio_service_id_parse(service_id);
	if (id) {
		g_rw_lock_writer_lock(&service_id_to_addr_lock);
		struct addr_and_tls_s *srvid_tls = g_malloc0(sizeof(struct addr_and_tls_s));
		g_strlcpy(srvid_tls->addr, addr, sizeof(srvid_tls->addr));
		if (tls) {
			g_strlcpy(srvid_tls->tls, tls, sizeof(srvid_tls->addr));
		}

		g_tree_replace(service_id_to_addr, g_strdup(id), srvid_tls);
		g_rw_lock_writer_unlock(&service_id_to_addr_lock);
	}
}

/* FIXME(mb) should be called when removing items from LB will be implemented */
__attribute__ ((unused))
static void
_oio_service_id_cache_remove(const gchar* service_id)
{
	const gchar *id = _oio_service_id_parse(service_id);
	if (id) {
		g_rw_lock_writer_lock(&service_id_to_addr_lock);
		g_tree_remove(service_id_to_addr, id);
		g_rw_lock_writer_unlock(&service_id_to_addr_lock);
	}
}

static void
_oio_service_id_cache_flush(void)
{
	g_rw_lock_writer_lock(&service_id_to_addr_lock);

	g_tree_destroy(service_id_to_addr);
	service_id_to_addr = g_tree_new_full(
			oio_str_casecmp3, NULL, g_free, g_free);

	g_rw_lock_writer_unlock(&service_id_to_addr_lock);
}

static void __attribute__ ((destructor))
_oio_service_id_cache_destroy(void)
{
	g_rw_lock_writer_lock(&service_id_to_addr_lock);

	EXTRA_ASSERT(service_id_to_addr != NULL);

	g_tree_destroy(service_id_to_addr);
	service_id_to_addr = NULL;
	g_rw_lock_writer_unlock(&service_id_to_addr_lock);

	g_rw_lock_clear(&service_id_to_addr_lock);
}

gchar*
oio_lb_resolve_service_id(const gchar* service_id, gboolean upgrade_to_tls)
{
	EXTRA_ASSERT(service_id != NULL);

	struct addr_and_tls_s *res;
	gchar *str = NULL;
	g_rw_lock_reader_lock(&service_id_to_addr_lock);
	if (service_id_to_addr &&
			(res = g_tree_lookup(service_id_to_addr, service_id))) {
		if (upgrade_to_tls) {
			if (oio_str_is_set(res->tls)) {
				str = g_strdup(res->tls);
			}
		} else {
			EXTRA_ASSERT(res->addr);
			str = g_strdup(res->addr);
		}
	}
	g_rw_lock_reader_unlock(&service_id_to_addr_lock);
	return str;
}

/* -------------------------------------------------------------------------- */

// TODO(FVE): reorganize fields, but keep compatibility with the other struct.
/* A service item, as known by the world.
 * See struct oio_lb_item_s. */
struct _lb_item_s
{
	oio_location_t location;
	oio_weight_t weight;
	gchar addr[STRLEN_ADDRINFO];
	gchar id[LIMIT_LENGTH_SRVID];
	gchar tls[STRLEN_ADDRINFO];
	oio_refcount_t refcount;
};

/* An indirection to the service item, as known by a slot.
 * This indirection is necessary to let the slot give its own weight to each
 * item, independently of the presence of the item in others slots.
 */
struct _slot_item_s
{
	struct _lb_item_s *item;
	oio_weight_acc_t acc_weight;
	generation_t generation;
};

/* Set of services matching the same macro "everything-but-the-location"
 * criteria. */
struct oio_lb_slot_s
{
	/* A pointer to the world owning this slot. */
	struct oio_lb_world_s *world;

	/* the sum of all the individual weights. */
	oio_weight_acc_t sum_weight;

	/* Array of inline <struct _slot_item_s> sorted by location. No real
	 * need to complexify by a secondary sort by ID, especially if the number
	 * of services at the same location is rather small.*/
	GArray *items;

	/* Total number of items per location, for each level.
	 * We do not use level 0 at the moment. */
	GData *items_by_loc[OIO_LB_LOC_LEVELS];

	/* Total number of different locations for each level. */
	guint locs_by_level[OIO_LB_LOC_LEVELS];

	gchar *name;

	generation_t generation;

	/* Does the slot need to be re-handled to computed accumulated scores.
	 * When set, the slot cannot be used for polling elements. */
	guint8 flag_dirty_weights : 1;

	/* Does the slot need to be re-sorted by location.
	 * When set, the slot cannot be used to be searched by location */
	guint8 flag_dirty_order : 1;

	guint8 flag_rehash_on_update : 1;

	guint64 jump;
};

/* All the load-balancing information:
 * - all the services in the 'world'
 * - all the slots that gather services with the same characteristics
 * - generation of the services in the 'world' (incr by 1 at each reload)
 * - absolute maximum distance between services in the 'world'
 */
struct oio_lb_world_s
{
	GRWLock lock;
	GTree *slots;
	GTree *items;
	generation_t generation;
	guint16 abs_max_dist;
};

/* A pool describes a preset configuration for the polling of several services.
 * So, a pool is composed of several members:
 * - the set of targets that must bring a service in the result set
 * - a pointer to the world to map the targets into LB slots.
 * - operations to apply on locations to check how close the services are
 */
struct oio_lb_pool_LOCAL_s
{
	struct oio_lb_pool_vtable_s *vtable;
	gchar *name;

	/* A back-pointer to the world the current 'pool' is valid on */
	struct oio_lb_world_s *world;

	/* An array with the name of all the targets of the pool, where a target is
	 * a coma-separated list of 'slot' names (the slots come from the 'world'). */
	gchar ** targets;

	/* Distance between services that the pool will try to ensure. */
	guint16 initial_dist;

	/* Distance between services that, when reached, will make the
	 * poll functions set the 'flawed' parameter to true. */
	guint16 warn_dist;

	/* Absolute minimum distance between services returned by the pool.
	 * Cannot be 0. */
	guint16 min_dist;

	/* If true, look for items close to each other. */
	gboolean nearby_mode : 16;
};

struct polling_ctx_s
{
	/* Locations that should be avoided. */
	const oio_location_t * avoids;
	/* Locations that have already been selected
	 * (before or during the request). */
	const oio_location_t * polled;
	/* Pointer where to save the next selected location.
	 * At the beginning, it may point to already selected services.
	 * In that case, these have to be checked and reorganized to
	 * match targets. */
	oio_location_t *next_polled;
	/* Number of services to select. */
	guint n_targets;

	/* Count how often each location has been chosen. */
	GData *counters[OIO_LB_LOC_LEVELS];

	/* Result from the selection of services.
	 * Array<struct oio_lb_selected_item_s *> */
	GPtrArray *selection;

	/* Did we use a fallback slot while polling? */
	gboolean fallback_used : 8;

	/* Shall we check the distance requirements? This will be disabled
	 * automagically if we detect a case where it is not possible to
	 * strictly meet the requirements. */
	gboolean check_distance : 8;

	/* Shall we check the "popularity" of locations when picking
	 * a new item? This is useful to ensure a good balancing on
	 * platforms where there is less locations than targets
	 * (for the specified distance). */
	gboolean check_popularity : 8;

	/* Maximum achievable distance between selected services. */
	guint16 max_dist;

	/* Minimum acceptable distance between selected services. */
	guint16 min_dist;
};

static void _local__destroy (struct oio_lb_pool_s *self);

static GError *_local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id, gboolean *flawed);

static GError *_local__patch(struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		const oio_location_t * known,
		oio_lb_on_id_f on_id, gboolean *flawed);

static struct oio_lb_item_s *_local__get_item(struct oio_lb_pool_s *self,
		const char *id);

static struct oio_lb_pool_vtable_s vtable_LOCAL =
{
	.destroy = _local__destroy,
	.poll = _local__poll,
	.patch = _local__patch,
	.get_item = _local__get_item
};

static struct _lb_item_s *
_item_make (oio_location_t location, const char *id, const char *addr, const char *tls)
{
	struct _lb_item_s *out = g_malloc0(sizeof(struct _lb_item_s));
	out->location = location;
	g_strlcpy(out->addr, addr, sizeof(out->addr));
	g_strlcpy(out->id, id, sizeof(out->id));
	g_strlcpy(out->tls, tls, sizeof(out->tls));
	return out;
}

void
oio_lb_selected_item_free(struct oio_lb_selected_item_s *sel)
{
	g_free(sel->item);
	g_free(sel->expected_slot);
	g_free(sel->final_slot);
	g_free(sel);
}

static struct oio_lb_selected_item_s *
_item_dup(const struct oio_lb_selected_item_s *sel)
{
	struct oio_lb_selected_item_s *res = g_memdup(sel, sizeof(*sel));
	res->expected_slot = g_strdup(sel->expected_slot);
	res->final_slot = g_strdup(sel->final_slot);
	res->item = g_memdup(sel->item, sizeof(*sel->item));
	return res;
}

static struct oio_lb_selected_item_s *
_item_select(const struct _lb_item_s *src)
{
	struct oio_lb_selected_item_s *res =  g_malloc0(sizeof *res);
	if (src != NULL) {
		res->item = g_malloc0(sizeof(struct oio_lb_item_s));
		g_strlcpy(res->item->addr, src->addr, sizeof(res->item->addr));
		g_strlcpy(res->item->id, src->id, sizeof(res->item->id));
		res->item->location = src->location;
		res->item->weight = src->weight;
	}
	return res;
}

static struct oio_lb_slot_s *
oio_lb_world__get_slot_unlocked(struct oio_lb_world_s *world, const char *name)
{
	EXTRA_ASSERT (world != NULL);
	EXTRA_ASSERT (oio_str_is_set(name));
	return g_tree_lookup (world->slots, name);
}

static guint
oio_lb_world__count_slot_items_unlocked(struct oio_lb_world_s *self,
		const char *name)
{
	guint len = 0;
	struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(self, name);
	if (slot)
		len = slot->items->len;
	return len;
}

#define CSLOT(p) ((const struct _slot_item_s*)(p))
#define CITEM(p) CSLOT(p)->item
#define TAB_ITEM(t,i)  g_array_index ((t), struct _slot_item_s, i)
#define SLOT_ITEM(s,i) TAB_ITEM (s->items, i)

static guint _search_first_at_location(GArray *tab,
		const oio_location_t needle, const enum oio_loc_proximity_level_e lvl,
		const guint start, const guint end);

guint32
djb_hash_str0(const gchar *str)
{
	guint32 hash = 5381;
	guint32 c = 0;
	while ((c = *str++))
		hash = ((hash << 5) + hash) + c;
	return hash;
}

struct hash_len_s
djb_hash_str(const gchar * b)
{
	struct hash_len_s hl = {.h = 5381,.l = 0 };
	for (; b[hl.l]; ++hl.l)
		hl.h = ((hl.h << 5) + hl.h) ^ (guint32) (b[hl.l]);
	return hl;
}

guint32
djb_hash_buf(const guint8 * b, register gsize bs)
{
	register guint32 h = 5381;
	for (register gsize i = 0; i < bs; ++i)
		h = ((h << 5) + h) ^ (guint32) (b[i]);
	return h;
}

/** Gets the number of elements in a GData. */
static guint
oio_ext_gdatalist_length(GData **datalist)
{
	guint counter = 0;
	void _datalist_count(GQuark key_id UNUSED,
			gpointer data UNUSED, gpointer udata UNUSED) {
		counter++;
	}
	g_datalist_foreach(datalist, _datalist_count, NULL);
	return counter;
}

uint32_t
key_from_loc_level(oio_location_t loc, int level)
{
	uint32_t key =
			((loc >> (level * OIO_LB_BITS_PER_LOC_LEVEL)) + 1) & 0xFFFFFFFF;
	if (level < 2)
		key += (loc >> (2 * OIO_LB_BITS_PER_LOC_LEVEL)) * OIO_LB_SHUFFLE_JUMP;
	return key;
}

static int
_compare_stored_items_by_location (const void *k0, const void *k)
{
	register const oio_location_t v0 = CITEM(k0)->location;
	register const oio_location_t v = CITEM(k)->location;
	return CMP(v0,v);
}

static inline guint16
_dist_to_bit_shift(guint16 dist, gboolean nearby_mode)
{
	return (dist - (!nearby_mode)) * OIO_LB_BITS_PER_LOC_LEVEL;
}

static gboolean
_item_is_too_close(const oio_location_t * avoids,
		const oio_location_t item, const guint16 distance)
{
	if (!avoids || distance == 0)
		return FALSE;
	const guint16 bit_shift = _dist_to_bit_shift(distance, FALSE);
	const oio_location_t loc = item >> bit_shift;
	for (const oio_location_t *pp=avoids; *pp; ++pp) {
		if (loc == (*pp >> bit_shift))
			return TRUE;
	}
	return FALSE;
}

static gboolean
_item_is_too_far(const oio_location_t *known,
		const oio_location_t item, const guint16 distance)
{
	if (!known || distance > OIO_LB_LOC_LEVELS)
		return FALSE;
	const guint16 bit_shift = _dist_to_bit_shift(distance, TRUE);
	const oio_location_t loc = item >> bit_shift;
	for (const oio_location_t *pp=known; *pp; ++pp) {
		if (loc != (*pp >> bit_shift))
			return TRUE;
	}
	return FALSE;
}

static guint16
_find_min_dist(const oio_location_t *known,
		const oio_location_t item, guint16 max_dist)
{
	guint16 dist = max_dist;
	while (_item_is_too_close(known, item, dist)) {
		dist--;
	}
	return dist;
}

static void
__attribute__ ((format (printf, 1, 2)))
_warn_dirty_poll(const char *fmt, ...)
{
	/* Initiate the mutex */
	static volatile guint lazy_init = 1;
	static GMutex lock = {};
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0))
			g_mutex_init(&lock);
	}

	if (g_mutex_trylock(&lock)) {
		/* If the mutex is already held by another thread, an alert is maybe
		 * going to be sent. No need to check if we need a strong level, that
		 * check will be performed by the other thread, and there is even no
		 * need to send any trace... */
		static volatile gint64 last_alert = 0;
		const gint64 now = oio_ext_monotonic_time();

		GLogLevelFlags lvl = GRID_LOGLVL_DEBUG;
		if (last_alert < OLDEST(now, 5 * G_TIME_SPAN_MINUTE))
			lvl = GRID_LOGLVL_WARN;
		last_alert = now;
		g_mutex_unlock(&lock);

		va_list va;
		va_start(va, fmt);
		g_logv(G_LOG_DOMAIN, lvl, fmt, va);
		va_end(va);
	}
}

static gboolean
_item_is_too_popular(struct polling_ctx_s *ctx, const oio_location_t item,
		struct oio_lb_slot_s *slot)
{
	for (int level = 1; level <= 3; level++) {
		GQuark key = key_from_loc_level(item, level);
		// How many different items there is under this level
		guint32 n_leafs = GPOINTER_TO_UINT(
				g_datalist_id_get_data(&(slot->items_by_loc[level]), key));
		if (unlikely(n_leafs == 0)) {
			_warn_dirty_poll("BUG: %s: LB reload not followed by rehash, "
					"item %"OIO_LOC_FORMAT" not found at level %d",
					__FUNCTION__, item, level);
			n_leafs = 1;
		} else if (unlikely(n_leafs > slot->items->len)) {
			_warn_dirty_poll("BUG: %s: LB reload not followed by rehash, "
					"more different locations than items in the slot %s "
					"(%u/%u)",
					__FUNCTION__, slot->name, n_leafs, slot->items->len);
			n_leafs = slot->items->len;
		}
		// How often the location has been chosen
		guint32 popularity = GPOINTER_TO_UINT(
				g_datalist_id_get_data(ctx->counters + level, key));
		// Maximum number of elements with this location that we can take
		guint32 max = 1 + (ctx->n_targets - 1) / (slot->items->len / n_leafs);

		// This gives better results on well balanced platforms,
		// but is not resilient to service failures.
		//guint32 max = 1 + (ctx->n_targets - 1) / slot->locs_by_level[level];

		GRID_TRACE("At level %d, %08X has popularity: %u, leafs: %u, max: %u",
				level, key, popularity, n_leafs, max);
		if (popularity >= max) {
			// TODO: return the level to optimize the next jump
			return TRUE;
		}
	}
	return FALSE;
}

static void
_slot_flush(struct oio_lb_slot_s *slot)
{
	if (!slot)
		return;
	if (slot->items) {
		const guint max = slot->items->len;
		for (guint i = 0; i<max; ++i) { /* unref all the elements */
			struct _slot_item_s *si = &SLOT_ITEM(slot,i);
			struct _lb_item_s *it = si->item;
			if (NULL != it) {
				EXTRA_ASSERT(it->refcount > 0);
				-- it->refcount;
			}
			si->acc_weight = 0;
			si->item = NULL;
		}
		g_array_set_size(slot->items, 0);
	}
}

static void
_slot_destroy (struct oio_lb_slot_s *slot)
{
	if (!slot)
		return;
	if (slot->items) {
		_slot_flush(slot);
		g_array_free (slot->items, TRUE);
		slot->items = NULL;
	}
	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		g_datalist_clear(&(slot->items_by_loc[level]));
	}
	oio_str_clean (&slot->name);
	slot->world = NULL;
	g_free (slot);
}


static const struct _lb_item_s *
_slot_get (struct oio_lb_slot_s *slot, const int i)
{
	return SLOT_ITEM(slot,i).item;
}

static inline gboolean
_slot_needs_rehash (const struct oio_lb_slot_s * const slot)
{
	return BOOL(slot->flag_dirty_order) || BOOL(slot->flag_dirty_weights);
}

static void
_level_datalist_incr_loc(GData **counters, oio_location_t loc)
{
	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		GData **counter = counters + level;
		GQuark key = key_from_loc_level(loc, level);
		// Will be 0 (NULL) if key does not exist
		guint32 count = GPOINTER_TO_UINT(
				g_datalist_id_get_data(counter, key));
		count++;
		g_datalist_id_set_data(counter, key, GUINT_TO_POINTER(count));
	}
}

static void
_slot_rehash (struct oio_lb_slot_s *slot)
{
	if (slot->flag_dirty_order) {
		slot->flag_dirty_order = 0;
		slot->flag_dirty_weights = 1;
		g_array_sort(slot->items, _compare_stored_items_by_location);

		for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
			g_datalist_clear(&(slot->items_by_loc[level]));
			// No need to call g_datalist_init()
		}
		for (guint i = 0; i < slot->items->len; i++) {
			struct _slot_item_s *si = &SLOT_ITEM(slot, i);
			_level_datalist_incr_loc(slot->items_by_loc, si->item->location);
		}
		for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
			slot->locs_by_level[level] =
					oio_ext_gdatalist_length(&(slot->items_by_loc[level]));
		}

# ifdef HAVE_EXTRA_DEBUG
		if (unlikely(GRID_TRACE_ENABLED())) {
			void _display(GQuark k, gpointer data, gpointer u) {
				guint level = GPOINTER_TO_UINT(u);
				oio_location_t loc = (GPOINTER_TO_UINT(k) - 1);
				GRID_TRACE("%0*lX prefix has %u services",
						4 * (OIO_LB_LOC_LEVELS - level),
						loc, GPOINTER_TO_UINT(data));
			}
			for (int i = 1; i < OIO_LB_LOC_LEVELS; i++)
				g_datalist_foreach(
						&slot->items_by_loc[i], _display, GUINT_TO_POINTER(i));
		}
#endif
	}

	if (slot->flag_dirty_weights) {
		slot->flag_dirty_weights = 0;
		guint32 sum = 0;
		const guint max = slot->items->len;
		for (guint i=0; i<max ;++i) {
			struct _slot_item_s *si = &SLOT_ITEM(slot,i);
			sum += si->item->weight;
			si->acc_weight = sum;
		}
		slot->sum_weight = sum;
	}

	/* 2^31-1 used to be the default jump, and was giving good results,
	 * except in some situations.
	 * Now we try to find a number which is:
	 * - prime with the number of items;
	 * - about in the middle of the range. */
	slot->jump = OIO_LB_SHUFFLE_JUMP;
	guint64 low = slot->items->len / 3;
	guint64 high = slot->items->len - low;
	for (int i = 0; slot->items->len > 0 && _prime_numbers[i] != 0u; i++) {
		guint64 jump_mod = _prime_numbers[i] % slot->items->len;
		if (jump_mod != 1 && jump_mod != slot->items->len - 1 &&
				jump_mod > low && jump_mod < high) {
			slot->jump = jump_mod;
			GRID_TRACE("Selected jump: %"G_GUINT64_FORMAT
					" (low=%"G_GUINT64_FORMAT", high=%"G_GUINT64_FORMAT", "
					"len=%u, prime=%"G_GUINT64_FORMAT")",
					jump_mod, low, high, slot->items->len, _prime_numbers[i]);
			break;
		}
	}
}

static guint
_count_similar_target_slots(struct oio_lb_pool_LOCAL_s *lb,
		const char *target)
{
	guint count = 0;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		/* The format of target and *ptarget is weird: they contain
		 * a null character and then regular characters (the slot fallbacks).
		 * We choose to compare only the main slot. */
		count += !g_strcmp0(target, *ptarget);
	}
	return count;
}

/* return the position of the stored_item with the closest <acc_weight> to
 * the value of <needle> */
static int
_search_closest_weight (GArray *tab, const guint32 needle,
		const guint start, const guint end)
{
	EXTRA_ASSERT (start < tab->len);
	EXTRA_ASSERT (end < tab->len);
	if (start >= end)
		return end;
	const guint i_pivot = start + ((end - start) / 2);
	const guint32 w_pivot = TAB_ITEM(tab,i_pivot).acc_weight;
	GRID_TRACE2("%s needle=%"G_GUINT32_FORMAT" start=%u end=%u"
			" i=%d w_pivot=%"G_GUINT32_FORMAT,
			__FUNCTION__, needle, start, end, i_pivot, w_pivot);
	if (w_pivot == needle)
		return i_pivot;
	if (w_pivot > needle)
		return _search_closest_weight (tab, needle, start, i_pivot);
	return _search_closest_weight (tab, needle, i_pivot+1, end);
}

static struct oio_lb_selected_item_s *
_accept_item(struct oio_lb_slot_s *slot, const guint16 distance,
		gboolean reversed, struct polling_ctx_s *ctx, guint i)
{
	const struct _lb_item_s *item = _slot_get (slot, i);
	const oio_location_t loc = item->location;
	// Check the item is not in "avoids" list
	if (_item_is_too_close(ctx->avoids, loc, 1))
		return NULL;
	if (reversed) {
		// Check the item is not too far from already polled items
		if (_item_is_too_far(ctx->polled, loc, distance))
			return NULL;
		// Check item has not been already polled
		if (_item_is_too_close(ctx->polled, loc, 1))
			return NULL;
	} else {
		// Check the item is not too close to already polled items
		if (_item_is_too_close(ctx->polled, loc,
				ctx->check_distance? distance : 1))
			return NULL;
		// Check the item has not been chosen too much already
		if (ctx->check_popularity && _item_is_too_popular(ctx, loc, slot))
			return NULL;
	}
	GRID_TRACE("Accepting item %s (0x%"OIO_LOC_FORMAT") from slot %s",
			item->id, loc, slot->name);

	struct oio_lb_selected_item_s *selected = _item_select(item);
	/* In case we do not enforce the distance check, we still need to find
	 * the lowest distance reached, for hypothetical future improvement. */
	if (ctx->check_distance) {
		selected->final_dist = distance;
	} else {
		selected->final_dist = _find_min_dist(ctx->polled,
				selected->item->location, ctx->max_dist);
	}

	*(ctx->next_polled) = loc;

	_level_datalist_incr_loc(ctx->counters, loc);

	return selected;
}

/* Perform a weighted-random polling in the slot.
 * Starting at the "closest" match, perform a shuffled lookup and for
 * each item check the polled item is not in the set to be avoided.
 * The purpose of the shuffled lookup is to jump to an item with
 * a distant location. */
static struct oio_lb_selected_item_s *
_local_slot__poll(struct oio_lb_slot_s *slot, guint16 distance,
		gboolean reversed, struct polling_ctx_s *ctx, guint n_targets)
{
	if (unlikely(_slot_needs_rehash(slot)))
		_warn_dirty_poll("BUG: %s: LB reload not followed by rehash", __FUNCTION__);

	GRID_TRACE2(
			"%s slot=%s sum=%"G_GUINT32_FORMAT
			" items=%d dist=%"G_GUINT16_FORMAT,
			__FUNCTION__, slot->name, slot->sum_weight, slot->items->len,
			distance);

	if (slot->items->len == 0) {
		GRID_TRACE2("%s slot empty", __FUNCTION__);
		return NULL;
	}
	if (slot->sum_weight == 0) {
		GRID_TRACE2("%s no service available", __FUNCTION__);
		return NULL;
	}

	/* If we need to pick more items than the number of different locations,
	 * we can slacken the distance checks, and rely only on the "popularity"
	 * mechanism. */
	if (oio_lb_allow_distance_bypass &&
			!reversed && ctx->check_distance && distance > 1) {
		guint16 level = distance - 1;
		if (n_targets > slot->locs_by_level[level]) {
			GRID_TRACE("%u targets, distance %u and %u locations at level %u: "
					"reducing required distance",
					n_targets, distance, slot->locs_by_level[level], level);
			/* Reducing the distance constrain locally gives better results
			 * than completely disabling the distance checks. */
			// ctx->check_distance = FALSE;
			distance = MAX(distance - 1, ctx->min_dist);
		}
	}

	int i = 0;
	struct oio_lb_selected_item_s *selected = NULL;
	for (gint64 attempt = 0;
			attempt < oio_lb_weighted_random_attempts;
			attempt++) {
		/* get the closest */
		guint32 random_weight = oio_ext_rand_int_range(0, slot->sum_weight);
		i = _search_closest_weight(slot->items, random_weight, 0,
				slot->items->len - 1);
		GRID_TRACE2("%s random_weight=%"G_GUINT32_FORMAT" at %d",
				__FUNCTION__, random_weight, i);
		EXTRA_ASSERT(i >= 0);
		EXTRA_ASSERT((guint)i < slot->items->len);
		if ((selected =
				_accept_item(slot, distance, reversed, ctx, i))) {
			return selected;
		}
	}

	/* Shuffled lookup */
	guint iter = 0;
	while (iter++ < slot->items->len) {
		i = (i + slot->jump) % slot->items->len;
		if ((selected =
				_accept_item(slot, distance, reversed, ctx, i))) {
			return selected;
		}
	}

	GRID_TRACE("%s avoided everything in slot=%s", __FUNCTION__, slot->name);
	return NULL;
}

static struct oio_lb_selected_item_s *
_local_target__poll(struct oio_lb_pool_LOCAL_s *lb,
		const char *target, guint16 distance, struct polling_ctx_s *ctx)
{
	GRID_TRACE2("%s pool=%s dist=%u target=%s",
			__FUNCTION__, lb->name, distance, target);
	gboolean fallback = FALSE;
	struct oio_lb_selected_item_s *selected = NULL;

	/* Each target is a sequence of '\0'-separated strings, terminated with
	 * an empty string. Each string is the name of a slot.
	 * In most case we should not loop and consider only the first slot.
	 * The other slots are fallbacks. */
	guint n_targets = _count_similar_target_slots(lb, target);
	for (const char *name = target; *name; name += 1+strlen(name)) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, name);
		if (!slot) {
			GRID_DEBUG ("Slot [%s] not ready", name);
		} else if ((selected =
				_local_slot__poll(slot, distance,
						lb->nearby_mode, ctx, n_targets))) {
			selected->expected_slot = g_strdup(target);
			selected->final_slot = g_strdup(name);
			break;
		}
		fallback = TRUE;
	}
	if (selected && fallback)
		ctx->fallback_used = TRUE;
	return selected;
}

static GError*
_local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id,
		gboolean *flawed)
{
	return _local__patch(self, avoids, NULL, on_id, flawed);
}

static struct oio_lb_selected_item_s*
_local_target__is_satisfied(struct oio_lb_pool_LOCAL_s *lb,
		const char *target, struct polling_ctx_s *ctx,
		gboolean strict)
{
	struct oio_lb_selected_item_s *selected = NULL;

	if (!*(ctx->next_polled))
		return NULL;

	/* Whatever the service is, the client provided it only for its location.
	 * We don't check if it really exists, and consider this special target
	 * as satisfied by default. */
	if (!g_strcmp0(target, OIO_LB_JOKER_SVC_TARGET)) {
		selected = _item_select(NULL);
		selected->expected_slot = g_strdup(target);
		return selected;
	}

	/* Iterate over the slots of the target to find if one of the
	** already known locations is inside, and thus satisfies the target. */
	for (const char *name = target; *name; name += strlen(name)+1) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, name);
		if (!slot) {
			GRID_DEBUG ("Slot [%s] not ready", name);
			continue;
		}
		if (unlikely(_slot_needs_rehash(slot))) {
			_warn_dirty_poll("BUG: %s: LB reload not followed by rehash",
					__FUNCTION__);
		}
		// FIXME(FVE): input should be service IDs, not locations.
		oio_location_t *known = ctx->next_polled;
		do {
			guint pos = _search_first_at_location(slot->items,
					*known, OIO_LOC_PROX_VOLUME,
					0, slot->items->len-1);
			if (pos != (guint)-1) {
				/* The current item is in a slot referenced by our target.
				** Place this item at the beginning of ctx->next_polled so
				** we won't consider it during the next call. */
				if (known != ctx->next_polled) {
					oio_location_t prev = *(ctx->next_polled);
					*(ctx->next_polled) = *known;
					*known = prev;
				}
				// The client does not expect already known services.
				//const struct _lb_item_s *item = _slot_get(slot, pos);
				//selected = _item_select(item);
				selected = _item_select(NULL);
				selected->expected_slot = g_strdup(target);
				selected->final_slot = g_strdup(name);
				return selected;
			}
		} while (*(++known));

		if (strict) {
			// Fallbacks not allowed.
			break;
		}
	}
	return NULL;
}

static void
_match_known_services_with_targets(struct oio_lb_pool_LOCAL_s *lb,
		struct polling_ctx_s *ctx, gchar **unmatched)
{
	EXTRA_ASSERT(unmatched != NULL);
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		struct oio_lb_selected_item_s *selected = NULL;
		selected = _local_target__is_satisfied(lb, *ptarget, ctx, TRUE);
		if (selected) {
			++(ctx->next_polled);
			g_ptr_array_add(ctx->selection, selected);
		} else {
			*unmatched = *ptarget;
			unmatched++;
		}
	}
	*unmatched = NULL;
}

static gboolean
_match_item_with_targets(struct oio_lb_pool_LOCAL_s *lb,
		struct oio_lb_selected_item_s *selected)
{
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		// Lookup only the first slot of each target.
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, *ptarget);
		guint pos = _search_first_at_location(slot->items,
				selected->item->location, OIO_LOC_PROX_VOLUME,
				0, slot->items->len-1);
		if (pos != (guint)-1) {
			oio_str_replace(&(selected->expected_slot), *ptarget);
			oio_str_replace(&(selected->final_slot), *ptarget);
			return TRUE;
		}
	}
	return FALSE;
}

static void
_debug_service_selection(struct polling_ctx_s *ctx)
{
	// FIXME: there is similar code in _slot_rehash()
	void _display(GQuark k, gpointer data, gpointer u) {
		guint level = GPOINTER_TO_UINT(u);
		oio_location_t loc = (GPOINTER_TO_UINT(k) - 1);
		GRID_DEBUG("%0*" G_GINT64_MODIFIER "X selected %u times",
				4 * (OIO_LB_LOC_LEVELS - level),
				loc, GPOINTER_TO_UINT(data));
	}
	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++)
		g_datalist_foreach(&(ctx->counters[level]),
				_display, GUINT_TO_POINTER(level));
	guint i = 0;
	void _display_selected(gpointer element, gpointer udata UNUSED) {
		struct oio_lb_selected_item_s *sel = element;
		GRID_DEBUG("Selected %s at loc %016"G_GINT64_MODIFIER
				"X, dist: %u/%u/%u, slot: %s/%s",
				sel->item? sel->item->id : "known service",
				sel->item? sel->item->location : ctx->polled[i],
				sel->final_dist, sel->warn_dist, sel->expected_dist,
				sel->final_slot, sel->expected_slot);
		i++;
	}
	g_ptr_array_foreach(ctx->selection, _display_selected, NULL);
}

static GError*
_local__patch(struct oio_lb_pool_s *self,
		const oio_location_t *avoids, const oio_location_t *known,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(lb->vtable == &vtable_LOCAL);
	EXTRA_ASSERT(lb->world != NULL);
	EXTRA_ASSERT(lb->targets != NULL);
	EXTRA_ASSERT(lb->min_dist >= 1);

	/* Count the expected targets to build a temp storage for
	 * polled locations */
	guint count_targets = oio_lb_world__count_pool_targets(self);

	/* Copy the array of known locations because we don't know
	 * if its allocated length is big enough */
	oio_location_t polled[count_targets+1];
	guint i = 0;
	for (; known && known[i]; i++)
		if (i < count_targets)
			polled[i] = known[i];
	guint count_known_targets = i;
	if (count_known_targets >= count_targets)
		return NEWERROR(CODE_BAD_REQUEST,
			"too many locations already known (%u), "
			"maximum %u locations for this storage policy",
			count_known_targets, count_targets);
	for (; i < count_targets+1; i++)
		polled[i] = 0;

	/* In normal mode (resp. nearby mode), distance starts high
	 * (resp. low), because we want services far from (resp. close to)
	 * each other. Then we reduce (resp. increase) the distance and thus
	 * have more chances to find services matching the other criteria. */
	guint16 max_dist = MIN(lb->world->abs_max_dist, lb->initial_dist);
	guint16 start_dist = lb->nearby_mode? lb->min_dist : max_dist;
	guint16 end_dist = (lb->nearby_mode? max_dist + 1 : lb->min_dist - 1);
	guint16 reached_dist = start_dist;

	struct polling_ctx_s ctx = {
		.avoids = avoids,
		.polled = (const oio_location_t *) polled,
		.next_polled = polled,
		.n_targets = count_targets,
		.check_distance = TRUE,
		.check_popularity = TRUE,
		.max_dist = max_dist,
		.min_dist = lb->min_dist,
		.selection = g_ptr_array_new_with_free_func(
			(GDestroyNotify)oio_lb_selected_item_free),
	};

	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		g_datalist_init(&ctx.counters[level]);
	}

	g_rw_lock_reader_lock(&lb->world->lock);
	gchar *unmatched_targets[count_targets+1];
	_match_known_services_with_targets(lb, &ctx, unmatched_targets);

	gint16 incr = lb->nearby_mode? 1 : -1;
	guint count = 0;
	GError *err = NULL;
	for (gchar **ptarget = unmatched_targets; *ptarget; ++ptarget) {
		struct oio_lb_selected_item_s *selected = NULL;
		selected = _local_target__is_satisfied(lb, *ptarget, &ctx, FALSE);
		guint16 dist;
		for (dist = start_dist; !selected && dist != end_dist; dist += incr) {
			selected = _local_target__poll(lb, *ptarget, dist, &ctx);
		}
		if (selected) {
			/* Do not trust the loop counter, we may have slackened
			 * the distance constraint in the polling function. */
			dist = selected->final_dist;
			if ((lb->nearby_mode && dist > reached_dist) ||
					(!lb->nearby_mode && dist < reached_dist))
				reached_dist = dist;
		} else {
			/* the strings are '\0' separated, printf won't display them */
			err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "no service polled "
					"from [%s], %u/%u services polled, %u known services, "
					"%u services in slot", *ptarget, count,
					count_targets - count_known_targets, count_known_targets,
					oio_lb_world__count_slot_items_unlocked(
						lb->world, *ptarget));
			break;
		}
		++ctx.next_polled;
		++count;
		g_ptr_array_add(ctx.selection, selected);
	}
	g_rw_lock_reader_unlock(&lb->world->lock);

	void _set_dists(gpointer element, guint cur) {
		struct oio_lb_selected_item_s *sel = element;
		sel->expected_dist = start_dist;
		sel->warn_dist = lb->warn_dist;
		if (sel->item) {
			/* Recompute the distance between chunks.
			 * FIXME(FVE): this is necessary only on the first selected item. */
			oio_location_t old = ctx.polled[cur];
			polled[cur] = (oio_location_t)-1;
			sel->final_dist = _find_min_dist(
					polled, sel->item->location, ctx.max_dist);
			polled[cur] = old;
		}
	}
	for (i = 0; i < ctx.selection->len; i++)
		_set_dists(g_ptr_array_index(ctx.selection, i), i);

	if (unlikely(GRID_DEBUG_ENABLED())) {
		_debug_service_selection(&ctx);
	}

	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		g_datalist_clear(&ctx.counters[level]);
	}
	if (err != NULL) {
		GRID_WARN("%s", err->message);
	} else {
		if (flawed) {
			GRID_DEBUG(
					"nearby_mode=%d, reached_dist=%u, "
					"warn_dist=%u, fallbacks=%d",
					lb->nearby_mode, reached_dist,
					lb->warn_dist, ctx.fallback_used);
			*flawed = (lb->nearby_mode && reached_dist >= lb->warn_dist) ||
					(!lb->nearby_mode && reached_dist <= lb->warn_dist) ||
					ctx.fallback_used;
		}
		void _forward(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
			if (sel->item)
				on_id(sel, NULL);
			// Do not forward "known" items (sel->item == NULL)
		}
		// FIXME(FVE): change signature, specify last parameter
		g_ptr_array_foreach(ctx.selection, (GFunc)_forward, NULL);
	}
	g_ptr_array_free(ctx.selection, TRUE);
	return err;
}

struct oio_lb_item_s *
_local__get_item(struct oio_lb_pool_s *self,
		const char *id)
{
	EXTRA_ASSERT (self != NULL);
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	// TODO: refine this: look only in slots targeted by the pool
	return oio_lb_world__get_item(lb->world, id);
}

static void
_local__destroy (struct oio_lb_pool_s *self)
{
	EXTRA_ASSERT (self != NULL);
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT (lb->vtable == &vtable_LOCAL);
	g_strfreev (lb->targets);
	oio_str_clean (&lb->name);
	g_free (lb);
}

void
oio_lb_world__add_pool_target (struct oio_lb_pool_s *self, const char *to)
{
	EXTRA_ASSERT (self != NULL);
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT (lb->vtable == &vtable_LOCAL);
	EXTRA_ASSERT (lb->world != NULL);
	EXTRA_ASSERT (lb->targets != NULL);

	/* Prepare the string to be easy to parse:
	 * replace commas with null characters. */
	const size_t tolen = strlen (to);
	gchar *copy = g_malloc (tolen + 2);
	memcpy (copy, to, tolen + 1);
	copy [tolen+1] = '\0';
	for (gchar *p = copy; *p; ) {
		if (!(p = strchr(p, OIO_CSV_SEP_C)))
			break;
		else
			*(p++) = '\0';
	}

	const gsize len = g_strv_length (lb->targets);
	lb->targets = g_realloc (lb->targets, (len+2) * sizeof(gchar*));
	lb->targets [len] = copy;
	lb->targets [len+1] = NULL;
}

void
oio_lb_world__set_pool_option(struct oio_lb_pool_s *self, const char *key,
		const char *value)
{
	EXTRA_ASSERT (self != NULL);
	gchar *endptr = NULL;
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	if (!key || !*key)
		return;
	if (!strcmp(key, OIO_LB_OPT_MIN_DIST)) {
		guint64 min = g_ascii_strtoull(value, &endptr, 10u);
		if (endptr == value) {
			GRID_WARN("Invalid %s [%s] for pool [%s]",
					OIO_LB_OPT_MIN_DIST, value, lb->name);
		} else if (min < 1 || min > OIO_LB_LOC_LEVELS) {
			GRID_WARN("%s [%s] for pool [%s] out of range [1, %d]",
					OIO_LB_OPT_MIN_DIST, value, lb->name,
					OIO_LB_LOC_LEVELS);
		} else {
			lb->min_dist = min;
		}
	} else if (!strcmp(key, OIO_LB_OPT_MAX_DIST)) {
		guint64 max = g_ascii_strtoull(value, &endptr, 10u);
		if (endptr == value) {
			GRID_WARN("Invalid %s [%s] for pool [%s]",
					OIO_LB_OPT_MAX_DIST, value, lb->name);
		} else if (max < 1 || max > OIO_LB_LOC_LEVELS) {
			GRID_WARN("%s [%s] for pool [%s] out of range [1, %d]",
					OIO_LB_OPT_MAX_DIST, value, lb->name,
					OIO_LB_LOC_LEVELS);
		} else {
			lb->initial_dist = max;
		}
	} else if (!strcmp(key, OIO_LB_OPT_WARN_DIST)) {
		guint64 warn = g_ascii_strtoull(value, &endptr, 10u);
		if (endptr == value) {
			GRID_WARN("Invalid %s [%s] for pool [%s]",
					OIO_LB_OPT_WARN_DIST, value, lb->name);
		} else if (warn > OIO_LB_LOC_LEVELS + 1) {
			GRID_WARN("%s [%s] for pool [%s] out of range [0, %d]",
					OIO_LB_OPT_WARN_DIST, value, lb->name,
					OIO_LB_LOC_LEVELS + 1);
		} else {
			lb->warn_dist = warn;
		}
	} else if (!strcmp(key, OIO_LB_OPT_NEARBY)) {
		lb->nearby_mode = oio_str_parse_bool(value, FALSE);
	} else {
		GRID_WARN("Invalid pool option: %s", key);
	}
}

void
oio_lb_world__add_pool_targets(struct oio_lb_pool_s *self,
		const gchar *targets)
{
	gchar **toks = g_strsplit(targets, OIO_CSV_SEP2, -1);
	for (gchar **num_target = toks; *num_target; num_target++) {
		/* the string is supposed to start with either:
		 * - a number and a comma,
		 * - a parameter key and an equal sign */
		char *equal = strchr(*num_target, '=');
		if (equal) {
			*equal = '\0';
			oio_lb_world__set_pool_option(self, *num_target, equal + 1);
			continue;
		} else if (**num_target == '\0') {
			struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *)self;
			GRID_DEBUG("Pool %s has empty targets or a trailing separator",
					lb->name);
			continue;
		}
		const char *target = strchr(*num_target, OIO_CSV_SEP_C);
		char *end = NULL;
		gint64 count = g_ascii_strtoll(*num_target, &end, 10u);
		if (end != target) {
			/* Number conversion failed.
			 * Either there was no separator (target == NULL),
			 * or there was garbage before the separator.
			 * Consider the string as the name of a target. */
			count = 1;
			target = *num_target;
		} else {
			/* Number conversion ended on the separator, the name
			 * of the target starts one character further. */
			target++;
		}
		for (int j = 0; j < count; j++)
			oio_lb_world__add_pool_target(self, target);
	}
	g_strfreev(toks);
}

GString *
oio_lb_world__dump_pool_options(struct oio_lb_pool_s *self)
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	GString *dump = g_string_sized_new(128);
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		if (dump->len > 0)
			g_string_append_c(dump, OIO_CSV_SEP2_C);
		g_string_append(dump, "1"OIO_CSV_SEP);
		for (const char *name = *ptarget; *name; name += 1 + strlen(name)) {
			if (name != *ptarget)
				g_string_append_c(dump, OIO_CSV_SEP_C);
			g_string_append(dump, name);
		}
	}

	if (lb->nearby_mode)
		g_string_append_static(dump, OIO_CSV_SEP2"nearby_mode=true");

	g_string_append_printf(dump, "%c%s=%u%c%s=%u",
			OIO_CSV_SEP2_C, OIO_LB_OPT_WARN_DIST, lb->warn_dist,
			OIO_CSV_SEP2_C, OIO_LB_OPT_MIN_DIST, lb->min_dist);

	return dump;
}

guint
oio_lb_world__count_pool_targets(struct oio_lb_pool_s *self)
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *)self;
	guint count_targets = 0;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget)
		count_targets++;
	return count_targets;
}

/* -------------------------------------------------------------------------- */

struct oio_lb_world_s *
oio_lb_local__create_world (void)
{
	struct oio_lb_world_s *self = g_malloc0 (sizeof(*self));
	g_rw_lock_init(&self->lock);
	self->slots = g_tree_new_full (oio_str_cmp3, NULL,
			g_free, (GDestroyNotify) _slot_destroy);
	self->items = g_tree_new_full (oio_str_cmp3, NULL,
			g_free, g_free);

	/* See at the end of oio_lb_world__feed_slot_unlocked()
	 * for an explanation. */
# ifndef __GNUC__
	self->abs_max_dist = OIO_LB_LOC_LEVELS;
# else
	/* Keep it 0, we will increase it when adding items. */
# endif
	return self;
}

static gboolean
_slot_flush_cb(gpointer k UNUSED, gpointer value, gpointer u UNUSED)
{
	_slot_flush((struct oio_lb_slot_s*)value);
	return FALSE;
}

void
oio_lb_world__flush(struct oio_lb_world_s *self)
{
	if (!self)
		return;

	g_rw_lock_writer_lock(&self->lock);

	if (self->slots) {
		g_tree_foreach(self->slots, _slot_flush_cb, NULL);
	}

	if (self->items) {
		g_tree_unref(self->items);
		self->items = g_tree_new_full (oio_str_cmp3, NULL,
				g_free, g_free);
	}
	_oio_service_id_cache_flush();

	g_rw_lock_writer_unlock(&self->lock);
}

void
oio_lb_world__destroy (struct oio_lb_world_s *self)
{
	if (!self)
		return;
	g_rw_lock_writer_lock(&self->lock);
	if (self->slots) {
		g_tree_destroy (self->slots);
		self->slots = NULL;
	}
	if (self->items) {
		g_tree_destroy (self->items);
		self->items = NULL;
	}
	g_rw_lock_writer_unlock(&self->lock);
	g_rw_lock_clear(&self->lock);
	g_free (self);

	_oio_service_id_cache_flush();
}

struct oio_lb_pool_s *
oio_lb_world__create_pool (struct oio_lb_world_s *world, const char *name)
{
	EXTRA_ASSERT (world != NULL);
	struct oio_lb_pool_LOCAL_s *lb = g_malloc0 (sizeof(struct oio_lb_pool_LOCAL_s));
	lb->vtable = &vtable_LOCAL;
	lb->name = g_strdup (name);
	lb->world = world;
	lb->targets = g_malloc0 (4 * sizeof(gchar*));
	lb->initial_dist = OIO_LB_LOC_LEVELS;
	lb->min_dist = 1;
	lb->nearby_mode = FALSE;
	return (struct oio_lb_pool_s*) lb;
}

static struct oio_lb_slot_s *
_world_create_slot (struct oio_lb_world_s *self, const char *name)
{
	struct oio_lb_slot_s *slot = NULL;
	g_rw_lock_reader_lock(&self->lock);
	slot = oio_lb_world__get_slot_unlocked(self, name);
	g_rw_lock_reader_unlock(&self->lock);
	if (!slot) {
		slot = g_malloc0(sizeof(*slot));
		slot->world = self;
		slot->name = g_strdup(name);
		slot->items = g_array_new(FALSE, TRUE, sizeof(struct _slot_item_s));
		for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
			g_datalist_init(&(slot->items_by_loc[level]));
		}
		slot->jump = OIO_LB_SHUFFLE_JUMP;
		GRID_INFO("Creating service slot [%s]", name);
		g_rw_lock_writer_lock(&self->lock);
		g_tree_replace(self->slots, g_strdup(name), slot);
		g_rw_lock_writer_unlock(&self->lock);
	} else {
		GRID_TRACE("Slot [%s] already exists", name);
	}
	return slot;
}

guint
oio_lb_world__count_slots (struct oio_lb_world_s *self)
{
	EXTRA_ASSERT (self != NULL);
	gint nnodes = 0;
	g_rw_lock_reader_lock(&self->lock);
	nnodes = g_tree_nnodes (self->slots);
	g_rw_lock_reader_unlock(&self->lock);
	return nnodes;
}

guint
oio_lb_world__count_items (struct oio_lb_world_s *self)
{
	EXTRA_ASSERT (self != NULL);
	gint nnodes = 0;
	g_rw_lock_reader_lock(&self->lock);
	nnodes = g_tree_nnodes (self->items);
	g_rw_lock_reader_unlock(&self->lock);
	return nnodes;
}

guint
oio_lb_world__count_slot_items(struct oio_lb_world_s *self, const char *name)
{
	EXTRA_ASSERT (self != NULL);
	guint len = 0;
	g_rw_lock_reader_lock(&self->lock);
	len = oio_lb_world__count_slot_items_unlocked(self, name);
	g_rw_lock_reader_unlock(&self->lock);
	return len;
}

struct oio_lb_item_s*
oio_lb_world__get_item(struct oio_lb_world_s *self, const char *id)
{
	struct oio_lb_item_s *item = NULL;
	g_rw_lock_reader_lock(&self->lock);
	struct _lb_item_s *item0 = g_tree_lookup(self->items, id);
	if (item0) {
		item = g_malloc0(sizeof(struct oio_lb_item_s));
		item->location = item0->location;
		item->weight = item0->weight;
		memcpy(item->addr, item0->addr, sizeof(item->addr));
		g_strlcpy(item->id, id, sizeof(item->id));
	}
	g_rw_lock_reader_unlock(&self->lock);
	return item;
}

void
oio_lb_world__create_slot (struct oio_lb_world_s *self, const char *name)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT (oio_str_is_set(name));
	(void) _world_create_slot (self, name);
}

static oio_location_t
_location_at_position (GArray *tab, const guint i)
{
	EXTRA_ASSERT (i < tab->len);
	return TAB_ITEM(tab,i).item->location;
}

#define M(loc) oio_location_mask_after(loc,lvl)

static guint
_slide_to_first_at_location (GArray *tab,
		const oio_location_t needle, const enum oio_loc_proximity_level_e lvl,
		guint i)
{
	EXTRA_ASSERT (M(needle) == M(_location_at_position(tab,i)));
	for (; i>0 ;--i) {
		if (M(needle) != M(_location_at_position (tab, i-1)))
			return i;
	}
	return i;
}

/* return the position of the first item with the same location as the
 * value of <needle> */
static guint
_search_first_at_location (GArray *tab,
		const oio_location_t needle, const enum oio_loc_proximity_level_e lvl,
		const guint start, const guint end)
{
	/* No item, answer "not found" */
	if (tab->len == 0)
		return (guint)-1;

	EXTRA_ASSERT (start < tab->len);
	EXTRA_ASSERT (end < tab->len);

	if (start == end) {
		/* not found ? */
		if (M(needle) != M(_location_at_position(tab, start)))
			return (guint)-1;
		return _slide_to_first_at_location (tab, needle, lvl, start);
	}

	const int i_pivot = start + ((end - start) / 2);
	if (M(needle) > M(_location_at_position(tab, i_pivot)))
		return _search_first_at_location (tab, needle, lvl, i_pivot+1, end);
	return _search_first_at_location (tab, needle, lvl, start, i_pivot);
}
#undef M

static void
oio_lb_world__feed_slot_unlocked(struct oio_lb_world_s *self,
		struct oio_lb_slot_s *slot, const struct oio_lb_item_s *item)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT (item != NULL);
	GRID_TRACE2("> Feeding [%s,%"G_GUINT64_FORMAT"] in slot=%s",
			item->id, item->location, slot->name);

	gboolean found = FALSE;

	slot->generation = self->generation;

	/* ensure the item is known by the world */
	struct _lb_item_s *item0 = g_tree_lookup (self->items, item->id);
	if (!item0) {

		/* Item unknown in the world, so we add it */
		item0 = _item_make (item->location, item->id, item->addr, item->tls);
		item0->weight = item->weight;
		g_tree_replace (self->items, g_strdup(item0->id), item0);
		_oio_service_id_cache_add_addr(item0->id, item0->addr, item0->tls);

	} else {

		/* Item already known in the world, so update it */
		if (item0->weight != item->weight) {
			item0->weight = item->weight;
			slot->flag_dirty_weights = 1;
		}

		/* Address may have changed. If so, update the cache. */
		if (g_strcmp0(item0->addr, item->addr)) {
			g_strlcpy(item0->addr, item->addr, sizeof(item0->addr));
			_oio_service_id_cache_add_addr(item0->id, item0->addr, item0->tls);
		}

		/* look for the slice of items AT THE OLD LOCATION (maybe it changed) */
		guint i0 = (guint)-1;
		if (slot->flag_dirty_order) {
			/* Linear search from the beginning */
			i0 = 0;
		} else if (slot->items->len) {
			/* Binary search, faster when items are sorted */
			i0 = _search_first_at_location (slot->items,
					item0->location, OIO_LOC_PROX_VOLUME,
					0, slot->items->len-1);
		}

		if (i0 != (guint)-1) {
			/* then iterate on the location to find it precisely. */
			for (guint i=i0; !found && i<slot->items->len ;++i) {
				if (item0 == _slot_get(slot,i)) {
					found = TRUE;
					/* we found the old item, now check the loca matches */
					if (item0->weight <= 0) {
						g_array_remove_index_fast(slot->items, i);
						slot->flag_dirty_order = 1;
					} else {
						SLOT_ITEM(slot,i).generation = self->generation;
						if (item0->location != item->location) {
							item0->location = item->location;
							slot->flag_dirty_order = 1;
						}
					}
				}
			}
		}
	}
	EXTRA_ASSERT (item0 != NULL);

	if (!found && item0->weight > 0) {
		++ item0->refcount;
		struct _slot_item_s fake = {item0, 0, self->generation};
		g_array_append_vals (slot->items, &fake, 1);
		item0 = NULL;
		found = TRUE;
		slot->flag_dirty_order = 1;
		slot->flag_dirty_weights = 1;
	}

	if (slot->flag_rehash_on_update && _slot_needs_rehash (slot))
		_slot_rehash(slot);

	/* This is an optimization to speedup the locations comparisons.
	 * It needs __builtin_clzll which is a GCC builtin. */
# ifdef __GNUC__
	// Actual number of bits used by the location.
	const int n_bits = sizeof(oio_location_t) * 8 -
			__builtin_clzll(item->location? : 1u);
	// Maximum distance between items with this number of bits.
	guint16 max_dist = 1 + (n_bits - 1) / OIO_LB_BITS_PER_LOC_LEVEL;
	if (self->abs_max_dist < max_dist) {
		self->abs_max_dist = max_dist;
		GRID_DEBUG("Absolute max_dist set to %u", max_dist);
	}
# endif
}

void
oio_lb_world__feed_slot (struct oio_lb_world_s *self, const char *name,
		const struct oio_lb_item_s *item)
{
	EXTRA_ASSERT(oio_str_is_set(name));
	g_rw_lock_writer_lock(&self->lock);
	struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(self, name);
	if (slot)
		oio_lb_world__feed_slot_unlocked(self, slot, item);
	g_rw_lock_writer_unlock(&self->lock);
}

void
oio_lb_world__feed_slot_with_list(struct oio_lb_world_s *self,
		const char *name, GSList *items)
{
	EXTRA_ASSERT(oio_str_is_set(name));
	g_rw_lock_writer_lock(&self->lock);
	struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(self, name);
	if (slot) {
		for (GSList *cur = items; cur; cur = cur->next) {
			struct oio_lb_item_s *item = cur->data;
			oio_lb_world__feed_slot_unlocked(self, slot, item);
		}
		_slot_rehash(slot);
	}
	g_rw_lock_writer_unlock(&self->lock);
}

void
oio_lb_world__foreach(struct oio_lb_world_s *self, void *udata,
		void (*on_item)(const char *id, const char *addr, void *user_data))
{
	gboolean _on_id(gpointer _key UNUSED, gpointer _item, gpointer data) {
		struct _lb_item_s *item = _item;
		(*on_item)(item->id, item->addr, data);
		return FALSE;
	}
	g_rw_lock_writer_lock(&self->lock);
	g_tree_foreach(self->items, (GTraverseFunc) _on_id, udata);
	g_rw_lock_writer_unlock(&self->lock);
}

static void
_slot_debug (struct oio_lb_slot_s *slot)
{
	GRID_DEBUG("slot=%s num=%u sum=%"G_GUINT32_FORMAT" flags=%d jump=%"
			G_GUINT64_FORMAT" content:",
			slot->name, slot->items->len, slot->sum_weight,
			slot->flag_dirty_weights | slot->flag_dirty_order<<1 |
			slot->flag_rehash_on_update<<2, slot->jump);
	for (guint i = 0; i < slot->items->len; ++i) {
		const struct _slot_item_s *si = &SLOT_ITEM(slot,i);
		GRID_DEBUG ("- [%s,0x%"OIO_LOC_FORMAT"] w=%u/%"G_GUINT32_FORMAT,
				si->item->id, si->item->location, si->item->weight, si->acc_weight);
	}
}

void
oio_lb_world__debug (struct oio_lb_world_s *self)
{
	EXTRA_ASSERT (self != NULL);
	gboolean _on_slot (gchar *name UNUSED, struct oio_lb_slot_s *slot,
			void *i UNUSED) {
		_slot_debug (slot);
		return FALSE;
	}
	g_rw_lock_reader_lock(&self->lock);
	g_tree_foreach (self->slots, (GTraverseFunc)_on_slot, NULL);
	g_rw_lock_reader_unlock(&self->lock);
}

void
oio_lb_world__increment_generation(struct oio_lb_world_s *self)
{
	EXTRA_ASSERT(self != NULL);
	self->generation ++;
}

static inline guint
absolute_delta(register const guint32 u0, register const guint32 u1)
{
	return MIN((u1-u0),(u0-u1));
}

static void
_world_rehash_slots(struct oio_lb_world_s *self)
{
	gboolean _on_slot_rehash(gpointer k UNUSED,
			struct oio_lb_slot_s *slot, gpointer w UNUSED) {
		if (_slot_needs_rehash(slot))
			_slot_rehash(slot);
		return FALSE;
	}
	WRITER_LOCK_DO(&self->lock,
			g_tree_foreach(self->slots, (GTraverseFunc)_on_slot_rehash, self));
}

static void
_world_purge_slot_items(struct oio_lb_world_s *self, guint32 age)
{
	gboolean _on_slot_purge_inside(gpointer k UNUSED,
			struct oio_lb_slot_s *slot, struct oio_lb_world_s *world) {

		guint pre = slot->items->len;
		for (guint i=0; i<slot->items->len ;++i) {
			struct _slot_item_s *si = &SLOT_ITEM(slot, i);
			if (absolute_delta(si->generation, world->generation) > age) {
				EXTRA_ASSERT(si->item->refcount > 0);
				-- si->item->refcount;
				g_array_remove_index_fast(slot->items, i);
				-- i;
			}
		}

		if (pre != slot->items->len) {
			GRID_DEBUG("%u services removed from %s (%u remain)",
					pre - slot->items->len, slot->name, slot->items->len);
			slot->flag_dirty_weights = 1;
			slot->flag_dirty_order = 1;
		}

		if (_slot_needs_rehash(slot))
			_slot_rehash(slot);

		return FALSE;
	}


	WRITER_LOCK_DO(&self->lock, g_tree_foreach(self->slots,
			(GTraverseFunc)_on_slot_purge_inside, self));
}

static void
_world_purge_slots(struct oio_lb_world_s *self, guint32 age)
{
	GSList *slots = NULL;

	gboolean _on_slot_extract(gpointer k UNUSED, struct oio_lb_slot_s *slot,
			gpointer i UNUSED) {
		if (absolute_delta(slot->generation, self->generation) > age)
			slots = g_slist_prepend(slots, slot);
		return FALSE;
	}

	g_rw_lock_writer_lock(&self->lock);
	g_tree_foreach(self->slots, (GTraverseFunc)_on_slot_extract, &slots);
	for (GSList *l=slots; l ;l=l->next) {
		struct oio_lb_slot_s *slot = l->data;
		_slot_flush(slot);
		GRID_DEBUG("LB removed slot %s", slot->name);
		g_tree_remove(self->slots, slot->name);
	}
	g_rw_lock_writer_unlock(&self->lock);

	g_slist_free(slots);
}

void
oio_lb_world__purge_old_generations(struct oio_lb_world_s *self)
{
	EXTRA_ASSERT(self != NULL);

	/* TODO(jfs): make that magic numbers become a variable */
	_world_purge_slot_items(self, 0);
	_world_purge_slots(self, 0);

	/* it is currently highly probable a service that disappeared will come
	 * back soon. So we don't purge the items yet. */
}

void
oio_lb_world__rehash_all_slots(struct oio_lb_world_s *self)
{
	EXTRA_ASSERT(self != NULL);

	_world_rehash_slots(self);
}


/* -- LB pools management ------------------------------------------------- */

struct oio_lb_s *
oio_lb__create()
{
	struct oio_lb_s *lb = g_malloc0(sizeof(struct oio_lb_s));
	g_rw_lock_init(&lb->lock);
	lb->pools = g_hash_table_new_full(g_str_hash, g_str_equal,
			NULL, (GDestroyNotify)oio_lb_pool__destroy);
	return lb;
}

void
oio_lb__clear(struct oio_lb_s **lb)
{
	struct oio_lb_s *lb2 = *lb;
	g_rw_lock_writer_lock(&lb2->lock);
	*lb = NULL;
	g_hash_table_destroy(lb2->pools);
	lb2->pools = NULL;
	g_rw_lock_writer_unlock(&lb2->lock);
	g_rw_lock_clear(&lb2->lock);
	g_free(lb2);
}

void
oio_lb__force_pool(struct oio_lb_s *lb, struct oio_lb_pool_s *pool)
{
	struct oio_lb_pool_abstract_s *apool = (struct oio_lb_pool_abstract_s *)pool;
	g_rw_lock_writer_lock(&lb->lock);
	g_hash_table_replace(lb->pools, (gpointer)apool->name, apool);
	g_rw_lock_writer_unlock(&lb->lock);
}

gboolean
oio_lb__has_pool(struct oio_lb_s *lb, const char *name)
{
	EXTRA_ASSERT(name != NULL);
	gboolean res = FALSE;
	g_rw_lock_reader_lock(&lb->lock);
	res = (g_hash_table_lookup(lb->pools, name) != NULL);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

GError*
oio_lb__poll_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t * avoids, oio_lb_on_id_f on_id,
		gboolean *flawed)
{
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(name != NULL);
	GError *res = NULL;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = oio_lb_pool__poll(pool, avoids, on_id, flawed);
	else
		res = BADREQ("pool [%s] not found", name);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

GError*
oio_lb__patch_with_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t *avoids, const oio_location_t *known,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	EXTRA_ASSERT(name != NULL);
	GError *res = NULL;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = oio_lb_pool__patch(pool, avoids, known, on_id, flawed);
	else
		res = BADREQ("pool [%s] not found", name);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

struct oio_lb_item_s *
oio_lb__get_item_from_pool(struct oio_lb_s *lb, const char *name,
		const char *id)
{
	EXTRA_ASSERT(name != NULL);
	struct oio_lb_item_s *res = NULL;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = oio_lb_pool__get_item(pool, id);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

static gchar **
_unique_slotnames(gchar **targets)
{
	GTree *t = g_tree_new_full(oio_str_cmp3, NULL, NULL, NULL);
	for (gchar **ptarget = targets; *ptarget; ++ptarget) {
		for (gchar *name = *ptarget; *name; name += 1+strlen(name)) {
			g_tree_replace(t, name, GINT_TO_POINTER(1));
		}
	}

	gboolean _add_key (gpointer *k, gpointer v UNUSED, GPtrArray *out) {
		g_ptr_array_add(out, k);
		return FALSE;
	}
	GPtrArray *out = g_ptr_array_sized_new(g_tree_nnodes(t) + 1);
	g_tree_foreach(t, (GTraverseFunc)_add_key, out);
	g_tree_destroy(t);
	g_ptr_array_add(out, NULL);
	return (gchar**) g_ptr_array_free(out, FALSE);
}

static GPtrArray *
_unique_services(struct oio_lb_pool_LOCAL_s *lb, gchar **slots, oio_location_t pin)
{
	pin = oio_location_mask_after(pin, OIO_LOC_DIST_HOST);

	GTree *t = g_tree_new_full(oio_str_cmp3, NULL, NULL, NULL);
	for (gchar **pname = slots; *pname; ++pname) {
		struct oio_lb_slot_s *slot =
			oio_lb_world__get_slot_unlocked(lb->world, *pname);
		if (!slot)
			continue;
		if (slot->flag_dirty_order) {
			// Linear total collection of items
			for (guint i=0; i < slot->items->len; ++i) {
				struct _lb_item_s *item = SLOT_ITEM(slot,i).item;
				if (pin == oio_location_mask_after(item->location, OIO_LOC_DIST_HOST))
					g_tree_replace(t, item->addr, item);
			}
		} else {
			// Binary lookup of the first item. If not found, it returns -1,
			// e.g. the biggest integer possible that will prevent the loop.
			guint i = _search_first_at_location(slot->items,
					pin, OIO_LOC_PROX_HOST, 0, slot->items->len-1);

#ifdef HAVE_EXTRA_ASSERT
#define CHECK_HLOC(pin,op,i) g_assert_cmpuint(pin, op, \
		oio_location_mask_after(SLOT_ITEM(slot,(i)).item->location, OIO_LOC_DIST_HOST))
			if (i != (guint)-1) {
				// check this is well the first item of its slice
				if (i > 0)
					CHECK_HLOC(pin, !=, i-1);
				CHECK_HLOC(pin, ==, i);
			}
#endif

			for (; i < slot->items->len; ++i) {
				struct _lb_item_s *item = SLOT_ITEM(slot, i).item;
				if (pin != oio_location_mask_after(item->location, OIO_LOC_DIST_HOST))
					break;
				g_tree_replace(t, item->id, item);
			}
		}
	}

	gboolean _add_val (gpointer *k UNUSED, gpointer v, GPtrArray *out) {
		g_ptr_array_add(out, v);
		return FALSE;
	}
	GPtrArray *out = g_ptr_array_sized_new(g_tree_nnodes(t));
	g_tree_foreach(t, (GTraverseFunc)_add_val, out);
	g_tree_destroy(t);
	return out;
}

static GError*
_local__poll_around(struct oio_lb_pool_s *self,
		const oio_location_t pin, int mode,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(lb->vtable == &vtable_LOCAL);
	EXTRA_ASSERT(lb->world != NULL);
	EXTRA_ASSERT(lb->targets != NULL);

	guint count_targets = oio_lb_world__count_pool_targets(self);
#ifdef HAVE_EXTRA_DEBUG
	guint count_slots = 0;
#endif

	GPtrArray *selection = g_ptr_array_new_with_free_func(
			(GDestroyNotify)oio_lb_selected_item_free);

	g_rw_lock_reader_lock(&lb->world->lock);

	// First we collect all the unique targets names in the pool
	GPtrArray *suspects = NULL;
	do {
		gchar **slotnames = _unique_slotnames(lb->targets);
#ifdef HAVE_EXTRA_DEBUG
		count_slots = g_strv_length(slotnames);
#endif
		suspects = _unique_services(lb, slotnames, pin);
		g_free(slotnames);
	} while (0);

	const guint max_suspects = suspects->len;

	// Secondly poll as many pinned services as wanted AND possible.
	if (max_suspects > 0) {
		// Build a slot name that can be recognized as a special name pattern
		// indicating an evil-placement
		gchar slot[] = PREFIX_SLOT_SKEW SUFFIX_SLOT_SKEW;
		oio_str_randomize(slot + sizeof(PREFIX_SLOT_SKEW) - 1,
				sizeof(SUFFIX_SLOT_SKEW) - 1, HEXA);

		guint16 max_dist = MIN(lb->world->abs_max_dist, lb->initial_dist);
		guint i = max_suspects > 1
			? oio_ext_rand_int_range(0, max_suspects) : 0;
		if (mode == 1) {
			// Poll one weighted random service under the pin
			// OSEF the weight -> the other chunks will respect a weighted random
			struct oio_lb_selected_item_s *selected = \
					_item_select(suspects->pdata[i]);
			if (!_match_item_with_targets(lb, selected)) {
				selected->expected_slot = g_strdup("rawx");
				selected->final_slot = g_strdup(slot);
			}
			selected->expected_dist = max_dist;
			// Consider this chunk is well placed in terms of distance.
			selected->final_dist = max_dist;
			selected->warn_dist = lb->warn_dist;
			g_ptr_array_add(selection, selected);
		} else {
			// Poll as many services as possible under the pin
			for (guint nb=0; nb < count_targets && nb < max_suspects; ++nb) {
				struct oio_lb_selected_item_s *selected = \
						_item_select(suspects->pdata[i]);
				// FIXME(FVE): this is broken since we may match several times
				// the same target (which should be matched only once).
				if (!_match_item_with_targets(lb, selected)) {
					selected->expected_slot = g_strdup("rawx");
					selected->final_slot = g_strdup(slot);
				}
				selected->expected_dist = max_dist;
				selected->final_dist = 1;  // on the same host by definition
				selected->warn_dist = lb->warn_dist;
				g_ptr_array_add(selection, selected);
				i = (i+1) % max_suspects;
			}
		}
	}

	g_rw_lock_reader_unlock(&lb->world->lock);

	const guint nb_locals = selection->len;
	GRID_TRACE("%s pin=%" G_GINT64_MODIFIER "x mode=%d targets=%u slots=%u suspects=%u locals=%u",
			__FUNCTION__, pin, mode,
			count_targets, count_slots, max_suspects, nb_locals);

	// Eventually complete with traditionnally polled services
	GError *err = NULL;
	if (selection->len < count_targets) {
		void _select(struct oio_lb_selected_item_s *sel, gpointer u UNUSED) {
			if (sel->item) {
				g_ptr_array_add(selection, _item_dup(sel));
			}
		}
		oio_location_t known[selection->len + 1];
		for (guint i=0; i < selection->len ;++i) {
			struct oio_lb_selected_item_s *sel = selection->pdata[i];
			known[i] = sel->item->location;
		}
		known[selection->len] = 0;
		err = _local__patch(self, NULL, known, _select, flawed);
	}

	if (flawed && nb_locals > 0)
		*flawed = TRUE;

	// If no error occured, we can upstream the polled services
	for (guint i=0; !err && i < selection->len; ++i)
		on_id(selection->pdata[i], NULL);

	g_ptr_array_free(selection, TRUE);
	g_ptr_array_free(suspects, TRUE);
	return err;
}

GError*
oio_lb__poll_pool_around(struct oio_lb_s *lb, const char *name,
		const oio_location_t pin, int mode,
		oio_lb_on_id_f on_id, gboolean *flawed)
{
	if (!pin || !mode)
		return oio_lb__poll_pool(lb, name, NULL, on_id, NULL);

	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(oio_str_is_set(name));

	GRID_TRACE("%s pin=%"G_GINT64_MODIFIER"x mode=%d", __FUNCTION__, pin, mode);

	GError *res = NULL;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = _local__poll_around(pool, pin, mode, on_id, flawed);
	else
		res = BADREQ("pool [%s] not found", name);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

GString*
oio_selected_item_quality_to_json(GString *inout,
		struct oio_lb_selected_item_s *sel)
{
	GString *qual = inout? : g_string_sized_new(128);
	g_string_append_c(qual, '{');
	oio_str_gstring_append_json_pair_int(qual,
			"expected_dist", sel->expected_dist);
	g_string_append_c(qual, ',');
	oio_str_gstring_append_json_pair_int(qual,
			"final_dist", sel->final_dist);
	g_string_append_c(qual, ',');
	oio_str_gstring_append_json_pair_int(qual,
			"warn_dist", sel->warn_dist);
	g_string_append_c(qual, ',');
	oio_str_gstring_append_json_pair(qual,
			"expected_slot", sel->expected_slot);
	g_string_append_c(qual, ',');
	oio_str_gstring_append_json_pair(qual,
			"final_slot", sel->final_slot);
	g_string_append_c(qual, '}');
	return qual;
}

