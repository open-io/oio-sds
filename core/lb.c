/*
OpenIO SDS load-balancing
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <core/oiolb.h>

#include <string.h>

#include <json-c/json.h>

#include <core/oiostr.h>
#include <core/oioext.h>
#include <core/oiolog.h>

#include "internals.h"

typedef guint32 generation_t;

#define OIO_LB_SHUFFLE_JUMP ((1UL << 31) - 1)
#define OIO_LB_LOC_LEVELS 4
#define OIO_LB_BITS_PER_LOC_LEVEL (sizeof(oio_location_t)*8/OIO_LB_LOC_LEVELS)

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

/* A service item, as known by the world. */
struct _lb_item_s
{
	oio_location_t location;
	oio_refcount_t refcount;
	oio_weight_t weight;
	gchar id[];
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
	void (*on_id) (oio_location_t location, const char *id);
	const oio_location_t * avoids;
	const oio_location_t * polled;
	oio_location_t *next_polled;
	guint n_targets;

	/* Count how often each location has been chosen. */
	GData *counters[OIO_LB_LOC_LEVELS];

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
_item_make (oio_location_t location, const char *id)
{
	int len = strlen (id);
	struct _lb_item_s *out = g_malloc0 (sizeof(struct _lb_item_s) + len + 1);
	out->location = location;
	strcpy (out->id, id);
	return out;
}

static struct oio_lb_slot_s *
oio_lb_world__get_slot_unlocked(struct oio_lb_world_s *world, const char *name)
{
	EXTRA_ASSERT (world != NULL);
	EXTRA_ASSERT (oio_str_is_set(name));
	return g_tree_lookup (world->slots, name);
}

#define CSLOT(p) ((const struct _slot_item_s*)(p))
#define CITEM(p) CSLOT(p)->item
#define TAB_ITEM(t,i)  g_array_index ((t), struct _slot_item_s, i)
#define SLOT_ITEM(s,i) TAB_ITEM (s->items, i)

static guint _search_first_at_location(GArray *tab, const oio_location_t needle,
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

/* Take djb2 hash of each part of the '.'-separated string,
 * keep the 16 LSB of each hash to build a 64b integer. */
oio_location_t
location_from_dotted_string(const char *dotted)
{
	gchar **toks = g_strsplit(dotted, ".", OIO_LB_LOC_LEVELS);
	oio_location_t location = 0;
	int ntoks = 0;
	// according to g_strsplit documentation, toks cannot be NULL
	for (gchar **tok = toks; *tok; tok++, ntoks++) {
		location = (location << OIO_LB_BITS_PER_LOC_LEVEL) |
				(djb_hash_str0(*tok) & 0xFFFF);
	}
	g_strfreev(toks);
	return location;
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

static gboolean
_item_is_too_close(const oio_location_t * avoids,
		const oio_location_t item, const guint16 bit_shift)
{
	if (!avoids)
		return FALSE;
	const oio_location_t loc = item >> bit_shift;
	for (const oio_location_t *pp=avoids; *pp; ++pp) {
		if (loc == (*pp >> bit_shift))
			return TRUE;
	}
	return FALSE;
}

static gboolean
_item_is_too_far(const oio_location_t *known,
		const oio_location_t item, const guint16 bit_shift)
{
	if (!known)
		return FALSE;
	const oio_location_t loc = item >> bit_shift;
	for (const oio_location_t *pp=known; *pp; ++pp) {
		if (loc != (*pp >> bit_shift))
			return TRUE;
	}
	return FALSE;
}

static gboolean
_item_is_too_popular(struct polling_ctx_s *ctx, const oio_location_t item,
		struct oio_lb_slot_s *slot)
{
	for (int level = 1; level <= 3; level++) {
		GQuark key = key_from_loc_level(item, level);
		// How many different locations there is under this level
		guint32 n_leafs = GPOINTER_TO_UINT(
				g_datalist_id_get_data(&(slot->items_by_loc[level]), key));
		// How often the location has been chosen
		guint32 popularity = GPOINTER_TO_UINT(
				g_datalist_id_get_data(ctx->counters + level, key));
		// Maximum number of elements with this location that we can take
		guint32 max = 1 + (ctx->n_targets - 1) / (slot->items->len / n_leafs);

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
	/* TODO maybe quicker to have all the flags in a single <guint8> and then
	 * check for a given MASK */
	return BOOL(slot->flag_dirty_order) || BOOL(slot->flag_dirty_weights);
}

static void
_level_datalist_incr_loc(GData **counters, oio_location_t loc)
{
	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		GData **counter = counters + level;
		GQuark key = key_from_loc_level(loc, level);
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

static gboolean
_accept_item(struct oio_lb_slot_s *slot, const guint16 bit_shift,
		gboolean reversed, struct polling_ctx_s *ctx, guint i)
{
	const struct _lb_item_s *item = _slot_get (slot, i);
	const oio_location_t loc = item->location;
	// Check the item is not in "avoids" list
	if (_item_is_too_close(ctx->avoids, loc, 0))
		return FALSE;
	if (reversed) {
		// Check the item is not too far from already polled items
		if (_item_is_too_far(ctx->polled, loc, bit_shift))
			return FALSE;
		// Check item has not been already polled
		if (_item_is_too_close(ctx->polled, loc, 0))
			return FALSE;
	} else {
		// Check the item is not too close to already polled items
		if (_item_is_too_close(ctx->polled, loc,
				ctx->check_distance? bit_shift : 0))
			return FALSE;
		// Check the item has not been chosen too much already
		if (ctx->check_popularity && _item_is_too_popular(ctx, loc, slot))
			return FALSE;
	}
	GRID_TRACE("Accepting item %s (0x%"OIO_LOC_FORMAT") from slot %s",
			item->id, loc, slot->name);
	ctx->on_id((oio_location_t)loc, item->id);
	*(ctx->next_polled) = loc;

	_level_datalist_incr_loc(ctx->counters, loc);

	return TRUE;
}

/* Perform a weighted-random polling in the slot.
 * Starting at the "closest" match, perform a shuffled lookup and for
 * each item check the polled item is not in the set to be avoided.
 * The purpose of the shuffled lookup is to jump to an item with
 * a distant location. */
static gboolean
_local_slot__poll(struct oio_lb_slot_s *slot, const guint16 bit_shift,
		gboolean reversed, struct polling_ctx_s *ctx)
{
	if (_slot_needs_rehash (slot))
		_slot_rehash (slot);

	GRID_TRACE2(
			"%s slot=%s sum=%"G_GUINT32_FORMAT
			" items=%d shift=%"G_GUINT16_FORMAT,
			__FUNCTION__, slot->name, slot->sum_weight, slot->items->len,
			bit_shift);

	if (slot->items->len == 0) {
		GRID_TRACE2("%s slot empty", __FUNCTION__);
		return FALSE;
	}
	if (slot->sum_weight == 0) {
		GRID_TRACE2("%s no service available", __FUNCTION__);
		return FALSE;
	}

	/* If we need to pick more items than the number of different locations,
	 * we can disable the distance checks, and rely only on the "popularity"
	 * mechanism.
	 * XXX: here we compare the overall number of targets to the number
	 * of different locations IN THE CURRENT SLOT. We bet that in most
	 * pools there will be only one targetted slot. */
	if (!reversed && ctx->check_distance &&
			bit_shift >= OIO_LB_BITS_PER_LOC_LEVEL) {
		guint16 level = bit_shift / OIO_LB_BITS_PER_LOC_LEVEL;
		if (ctx->n_targets > slot->locs_by_level[level]) {
			GRID_TRACE("%u targets and %u locations at level %u: "
					"disabling distance check",
					ctx->n_targets, slot->locs_by_level[level], level);
			ctx->check_distance = FALSE;
		}
	}

	/* get the closest */
	guint32 random_weight = g_random_int_range (0, slot->sum_weight);
	int i = _search_closest_weight (slot->items, random_weight, 0,
			slot->items->len - 1);
	GRID_TRACE2("%s random_weight=%"G_GUINT32_FORMAT" at %d",
			__FUNCTION__, random_weight, i);
	EXTRA_ASSERT (i >= 0);
	EXTRA_ASSERT ((guint)i < slot->items->len);

	guint iter = 0;
	while (iter++ < slot->items->len) {
		if (_accept_item(slot, bit_shift, reversed, ctx, i))
			return TRUE;
		i = (i + OIO_LB_SHUFFLE_JUMP) % slot->items->len;
	}

	GRID_TRACE("%s avoided everything in slot=%s", __FUNCTION__, slot->name);
	return FALSE;
}

static gboolean
_local_target__poll(struct oio_lb_pool_LOCAL_s *lb,
		const char *target, guint16 bit_shift, struct polling_ctx_s *ctx)
{
	GRID_TRACE2("%s pool=%s shift=%d target=%s",
			__FUNCTION__, lb->name, bit_shift, target);
	gboolean res = FALSE;
	gboolean fallback = FALSE;

	g_rw_lock_reader_lock(&lb->world->lock);
	/* Each target is a sequence of '\0'-separated strings, terminated with
	 * an empty string. Each string is the name of a slot.
	 * In most case we should not loop and consider only the first slot.
	 * The other slots are fallbacks. */
	for (const char *name = target; *name; name += 1+strlen(name)) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, name);
		if (!slot) {
			GRID_DEBUG ("Slot [%s] not ready", name);
		} else if (_local_slot__poll(slot, bit_shift, lb->nearby_mode, ctx)) {
			res = TRUE;
			break;
		}
		fallback = TRUE;
	}
	g_rw_lock_reader_unlock(&lb->world->lock);
	if (res && fallback)
		ctx->fallback_used = TRUE;
	return res;
}

static GError*
_local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		void (*on_id) (oio_location_t, const char *),
		gboolean *flawed)
{
	return _local__patch(self, avoids, NULL, on_id, flawed);
}

static gboolean
_local_target__is_satisfied(struct oio_lb_pool_LOCAL_s *lb,
		const char *target, struct polling_ctx_s *ctx)
{
	if (!*(ctx->next_polled))
		return FALSE;

	/* Iterate over the slots of the target to find if one of the
	** already known locations is inside, and thus satisfies the target. */
	for (const char *name = target; *name; name += strlen(name)+1) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, name);
		if (!slot) {
			GRID_DEBUG ("Slot [%s] not ready", name);
			continue;
		}
		if (_slot_needs_rehash(slot)) {
			_slot_rehash(slot);
		}
		oio_location_t *known = ctx->next_polled;
		do {
			guint pos = _search_first_at_location(slot->items,
					*known, 0, slot->items->len-1);
			if (pos != (guint)-1) {
				/* The current item is in a slot referenced by our target.
				** Place this item at the beginning of ctx->next_polled so
				** we won't consider it during the next call. */
				if (known != ctx->next_polled) {
					oio_location_t prev = *(ctx->next_polled);
					*(ctx->next_polled) = *known;
					*known = prev;
				}
				return TRUE;
			}
		} while (*(++known));
	}
	return FALSE;
}

static inline guint16
_dist_to_bit_shift(guint16 dist, gboolean nearby_mode)
{
	return (dist - (!nearby_mode)) * OIO_LB_BITS_PER_LOC_LEVEL;
}

static GError*
_local__patch(struct oio_lb_pool_s *self,
		const oio_location_t *avoids, const oio_location_t *known,
		void (*on_id) (oio_location_t location, const char *id),
		gboolean *flawed)
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(lb->vtable == &vtable_LOCAL);
	EXTRA_ASSERT(lb->world != NULL);
	EXTRA_ASSERT(lb->targets != NULL);
	EXTRA_ASSERT(lb->min_dist >= 1);

	/* Count the expected targets to build a temp storage for
	 * polled locations */
	guint count_targets = 0;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget)
		count_targets++;

	/* Copy the array of known locations because we don't know
	 * if its allocated length is big enough */
	oio_location_t polled[count_targets+1];
	guint i = 0;
	for (; known && known[i]; i++)
		polled[i] = known[i];
	for (; i < count_targets; i++)
		polled[i] = 0;

	struct polling_ctx_s ctx = {
		.on_id = on_id,
		.avoids = avoids,
		.polled = (const oio_location_t *) polled,
		.next_polled = polled,
		.n_targets = count_targets,
		.check_distance = TRUE,
		.check_popularity = TRUE,
	};

	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		g_datalist_init(&ctx.counters[level]);
	}

	/* In normal mode (resp. nearby mode), bit shifts start high
	 * (resp. low), because we want services with different
	 * (resp. equal) most significant bits. Then we reduce (resp. increase)
	 * the shifting so we compare more (resp. less) bits of the locations,
	 * and thus have more chances to find differences (resp. similarities)
	 * between service locations. */
	guint16 max_dist = MIN(lb->world->abs_max_dist, lb->initial_dist);
	guint16 start_dist = lb->nearby_mode? lb->min_dist : max_dist;
	guint16 end_dist = (lb->nearby_mode? max_dist + 1 : lb->min_dist - 1);
	guint16 reached_dist = start_dist;
	gint16 incr = lb->nearby_mode? 1 : -1;
	guint count = 0;
	GError *err = NULL;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		gboolean done = _local_target__is_satisfied(lb, *ptarget, &ctx);
		guint16 dist;
		for (dist = start_dist; !done && dist != end_dist; dist += incr) {
			done = _local_target__poll(lb, *ptarget,
					_dist_to_bit_shift(dist, lb->nearby_mode), &ctx);
		}
		dist -= incr;
		if ((lb->nearby_mode && dist > reached_dist) ||
				(!lb->nearby_mode && dist < reached_dist))
			reached_dist = dist;
		if (!done) {
			/* the strings are '\0' separated, printf won't display them */
			err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE, "no service polled "
					"from [%s], %u/%d services polled, %u services in slot",
					*ptarget, count, count_targets,
					oio_lb_world__count_slot_items(lb->world, *ptarget));
			break;
		}
		++ctx.next_polled;
		++count;
	}

	if (unlikely(GRID_DEBUG_ENABLED())) {
		// FIXME: there is similar code in _slot_rehash()
		void _display(GQuark k, gpointer data, gpointer u) {
			guint level = GPOINTER_TO_UINT(u);
			oio_location_t loc = (GPOINTER_TO_UINT(k) - 1);
			GRID_DEBUG("%0*lX selected %u times",
					4 * (OIO_LB_LOC_LEVELS - level),
					loc, GPOINTER_TO_UINT(data));
		}
		for (int level = 1; level < OIO_LB_LOC_LEVELS; level++)
			g_datalist_foreach(&ctx.counters[level],
					_display, GUINT_TO_POINTER(level));
	}

	for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
		g_datalist_clear(&ctx.counters[level]);
	}
	if (err != NULL) {
		GRID_WARN("%s", err->message);
		return err;
	}
	if (flawed) {
		GRID_DEBUG(
				"nearby_mode=%d, reached_dist=%u, warn_dist=%u, fallbacks=%d",
				lb->nearby_mode, reached_dist, lb->warn_dist,
				ctx.fallback_used);
		*flawed = (lb->nearby_mode && reached_dist >= lb->warn_dist) ||
				(!lb->nearby_mode && reached_dist <= lb->warn_dist) ||
				ctx.fallback_used;
	}
	return NULL;
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

	/* prepare the string to be easy to parse. */
	gsize tolen = strlen (to);
	gchar *copy = g_malloc (tolen + 2);
	memcpy (copy, to, tolen + 1);
	copy [tolen+1] = '\0';
	for (gchar *p=copy; *p ;) {
		if (!(p = strchr (p, OIO_CSV_SEP_C))) break; else *(p++) = '\0';
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
		}
		const char *target = strchr(*num_target, OIO_CSV_SEP_C);
		char *end = NULL;
		gint64 count = g_ascii_strtoll(*num_target, &end, 10u);
		if (end != target) {
			count = 1;
			target = *num_target;
		} else {
			target++;
		}
		for (int j = 0; j < count; j++)
			oio_lb_world__add_pool_target(self, target);
	}
	g_strfreev(toks);
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
		slot->name = g_strdup(name);
		slot->items = g_array_new(FALSE, TRUE, sizeof(struct _slot_item_s));
		for (int level = 1; level < OIO_LB_LOC_LEVELS; level++) {
			g_datalist_init(&(slot->items_by_loc[level]));
		}
		g_rw_lock_writer_lock(&self->lock);
		g_tree_replace(self->slots, g_strdup(name), slot);
		g_rw_lock_writer_unlock(&self->lock);
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
	struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(self, name);
	if (slot)
		len = slot->items->len;
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
		item = g_malloc0(sizeof(struct oio_lb_item_s) + strlen(id) + 1);
		item->location = item0->location;
		item->weight = item0->weight;
		strcpy(item->id, id);
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

static int
_slide_to_first_at_location (GArray *tab, const oio_location_t needle,
		guint i)
{
	EXTRA_ASSERT (needle == _location_at_position(tab,i));
	for (; i>0 ;--i) {
		if (needle != _location_at_position (tab, i-1))
			return i;
	}
	return i;
}

/* return the position of the first item with the same location as the
 * value of <needle> */
static guint
_search_first_at_location (GArray *tab, const oio_location_t needle,
		const guint start, const guint end)
{
	/* No item, answer "not found" */
	if (tab->len == 0)
		return (guint)-1;

	EXTRA_ASSERT (start < tab->len);
	EXTRA_ASSERT (end < tab->len);

	if (start == end) {
		/* not found ? */
		if (needle != _location_at_position (tab, start))
			return (guint)-1;
		return _slide_to_first_at_location (tab, needle, start);
	}

	const int i_pivot = start + ((end - start) / 2);
	if (needle > _location_at_position (tab, i_pivot))
		return _search_first_at_location (tab, needle, i_pivot+1, end);
	return _search_first_at_location (tab, needle, start, i_pivot);
}

static void
oio_lb_world__feed_slot_unlocked(struct oio_lb_world_s *self,
		const char *name, const struct oio_lb_item_s *item)
{
	EXTRA_ASSERT (self != NULL);
	EXTRA_ASSERT (item != NULL);
	EXTRA_ASSERT (oio_str_is_set(name));
	GRID_TRACE2 ("> Feeding [%s,%"G_GUINT64_FORMAT"] in slot=%s",
			item->id, item->location, name);

	gboolean found = FALSE;

	struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(self, name);
	if (!slot)
		return;

	slot->generation = self->generation;

	/* ensure the item is known by the world */
	struct _lb_item_s *item0 = g_tree_lookup (self->items, item->id);
	if (!item0) {

		/* Item unknown in the world, so we add it */
		item0 = _item_make (item->location, item->id);
		item0->weight = item->weight;
		g_tree_replace (self->items, g_strdup(item0->id), item0);

	} else {

		/* Item already known in the world, so update it */
		if (item0->weight != item->weight) {
			item0->weight = item->weight;
			slot->flag_dirty_weights = 1;
		}

		/* look for the slice of items AT THE OLD LOCATION (maybe it changed) */
		guint i0 = (guint)-1;
		if (slot->flag_dirty_order) {
			/* Linear search from the beginning */
			i0 = 0;
		} else if (slot->items->len) {
			/* Binary search, faster when items are sorted */
			i0 = _search_first_at_location (slot->items, item0->location,
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
		_slot_rehash (slot);

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
	g_rw_lock_writer_lock(&self->lock);
	oio_lb_world__feed_slot_unlocked(self, name, item);
	g_rw_lock_writer_unlock(&self->lock);
}

static void
_slot_debug (struct oio_lb_slot_s *slot)
{
	GRID_DEBUG("slot=%s num=%u sum=%"G_GUINT32_FORMAT" flags=%d content:",
			slot->name, slot->items->len, slot->sum_weight,
			slot->flag_dirty_weights | slot->flag_dirty_order<<1 |
			slot->flag_rehash_on_update<<2);
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

		return FALSE;
	}

	g_rw_lock_writer_lock(&self->lock);
	g_tree_foreach(
			self->slots, (GTraverseFunc)_on_slot_purge_inside, self);
	g_rw_lock_writer_unlock(&self->lock);
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
	memset(lb2, 0, sizeof(struct oio_lb_s));
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
