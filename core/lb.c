/*
OpenIO SDS load-balancing
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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

#include <string.h>

#include <glib.h>
#include <json.h>

#include "oiolb.h"
#include "oiostr.h"
#include "oioext.h"
#include "oiolog.h"
#include "internals.h"

typedef guint32 generation_t;

// actually not prime but OK
#define OIO_LB_SHUFFLE_JUMP ((1UL << 31) - 1)


typedef guint16 oio_refcount_t;

struct oio_lb_pool_vtable_s
{
	void (*destroy) (struct oio_lb_pool_s *self);

	guint (*poll) (struct oio_lb_pool_s *self,
			const oio_location_t * avoids,
			oio_lb_on_id_f on_id);

	guint (*patch) (struct oio_lb_pool_s *self,
			const oio_location_t * avoids,
			const oio_location_t * known,
			oio_lb_on_id_f on_id);

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

guint
oio_lb_pool__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id)
{
	CFG_CALL(self,poll)(self, avoids, on_id);
}

// FIXME: return a GError*
guint
oio_lb_pool__patch(struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		const oio_location_t * known,
		oio_lb_on_id_f on_id)
{
	CFG_CALL(self, patch)(self, avoids, known, on_id);
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
	   need to complexify by a secondary sort by ID, especially if the number
	   of services at the same location is rather small.*/
	GArray *items;

	gchar *name;

	generation_t generation;

	/* Does the slot need to be re-handled to computed accumulated scores.
	   When set, the slot cannot be used for polling elements. */
	guint8 flag_dirty_weights : 1;

	/* Does the slot need to be re-sorted by location.
	   When set, the slot cannot be used to be searched by location */
	guint8 flag_dirty_order : 1;

	guint8 flag_rehash_on_update : 1;
};

/* All the load-balancing information:
 * - all the services in the 'world'
 * - all the slots that gather services with the same characteristics
 */
struct oio_lb_world_s
{
	GRWLock lock;
	GTree *slots;
	GTree *items;
	generation_t generation;
};

/* A pool describes a preset configuration for the polling of several services.
 * So, a pool is composed of several members:
 * - the set of targets that must bring a service in the result set
 * - a pointer to the world to map the targets into LB slots.
 * - the bitwise mask that tells how close the service are, when the mask is
 *   applied to their lcoations.
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

	oio_location_t location_mask;
	guint location_mask_max_shift : 16;
	gboolean nearby_mode : 16;
};

static void _local__destroy (struct oio_lb_pool_s *self);

static guint _local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id);

static guint _local__patch(struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		const oio_location_t * known,
		oio_lb_on_id_f on_id);

static struct oio_lb_item_s *_local__get_item(struct oio_lb_pool_s *self,
		const char *id);

static struct oio_lb_pool_vtable_s vtable_LOCAL =
{
	_local__destroy, _local__poll, _local__patch, _local__get_item
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

/* Take djb2 hash of each part of the '.'-separated string,
 * keep the 16 (or 8) LSB of each hash to build a 64 integer. */
oio_location_t
location_from_dotted_string(const char *dotted)
{
	// http://www.cse.yorku.ca/~oz/hash.html
	guint32 _djb2(const gchar *str) {
		guint32 hash = 5381;
		guint32 c = 0;
		while ((c = *str++))
			hash = ((hash << 5) + hash) + c;
		return hash;
	}
	gchar **toks = g_strsplit(dotted, ".", 8);
	unsigned int shift = (g_strv_length(toks) <= 4)? 16 : 8;
	oio_location_t mask = (1u << shift) - 1u;
	oio_location_t location = 0;
	for (gchar **tok = toks; tok && *tok; tok++) {
		location = (location << shift) | (_djb2(*tok) & mask);
	}
	g_strfreev(toks);
	return location;
}

static int
_compare_stored_items_by_location (const void *k0, const void *k)
{
	register const oio_location_t v0 = CITEM(k0)->location;
	register const oio_location_t v = CITEM(k)->location;
	return CMP(v0,v);
}

static gboolean
_item_is_too_close (const oio_location_t * avoids,
		const oio_location_t item, const oio_location_t mask)
{
	if (!avoids)
		return FALSE;
	const oio_location_t loc = mask & item;
	for (const oio_location_t *pp=avoids; *pp; ++pp) {
		if (loc == (mask & *pp))
			return TRUE;
	}
	return FALSE;
}

static gboolean
_item_is_too_far (const oio_location_t *known,
		const oio_location_t item, const oio_location_t mask)
{
	if (!known)
		return FALSE;
	const oio_location_t loc = mask & item;
	for (const oio_location_t *pp=known; *pp; ++pp) {
		if (loc != (mask & *pp))
			return TRUE;
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
_slot_rehash (struct oio_lb_slot_s *slot)
{
	if (slot->flag_dirty_order) {
		slot->flag_dirty_order = 0;
		slot->flag_dirty_weights = 1;
		g_array_sort (slot->items, _compare_stored_items_by_location);
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

struct polling_ctx_s
{
	void (*on_id) (oio_location_t location, const char *id);
	const oio_location_t * avoids;
	const oio_location_t * polled;
	oio_location_t *next_polled;
};

static gboolean
_accept_item (struct oio_lb_slot_s *slot, oio_location_t mask,
		gboolean reversed, struct polling_ctx_s *ctx, guint i)
{
	const struct _lb_item_s *item = _slot_get (slot, i);
	const oio_location_t loc = item->location;
	// Check the item is not in "avoids" list
	if (_item_is_too_close(ctx->avoids, loc, (oio_location_t)-1))
		return FALSE;
	if (reversed) {
		// Check the item is not too far from alread polled items
		if (_item_is_too_far(ctx->polled, loc, mask))
			return FALSE;
		// Check item has not been already polled
		if (_item_is_too_close(ctx->polled, loc, (oio_location_t)-1))
			return FALSE;
	} else {
		// Check the item is not too close to alread polled items
		if (_item_is_too_close(ctx->polled, loc, mask))
			return FALSE;
	}
	GRID_TRACE("Accepting item %s (0x%016lX) from slot %s",
			item->id, loc, slot->name);
	ctx->on_id((oio_location_t)loc, item->id);
	*(ctx->next_polled) = loc;
	return TRUE;
}

/* Perform a weighted-random polling in the slot.
 * Starting at the "closest" match, perform a shuffled lookup and for
 * each item check the polled item is not in the set to be avoided.
 * The purpose of the shuffled lookup is to jump to an item with
 * a distant location. */
static gboolean
_local_slot__poll (struct oio_lb_slot_s *slot, oio_location_t mask,
		gboolean reversed, struct polling_ctx_s *ctx)
{
	if (_slot_needs_rehash (slot))
		_slot_rehash (slot);

	GRID_TRACE2("%s slot=%s sum=%"G_GUINT32_FORMAT" items=%d mask=%016lX",
			__FUNCTION__, slot->name, slot->sum_weight, slot->items->len,
			mask);

	if (slot->items->len == 0) {
		GRID_TRACE2("%s slot empty", __FUNCTION__);
		return FALSE;
	}
	if (slot->sum_weight == 0) {
		GRID_TRACE2("%s no service available", __FUNCTION__);
		return FALSE;
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
		if (_accept_item(slot, mask, reversed, ctx, i))
			return TRUE;
		i = (i + OIO_LB_SHUFFLE_JUMP) % slot->items->len;
	}

	GRID_TRACE("%s avoided everything in slot=%s", __FUNCTION__, slot->name);
	return FALSE;
}

static gboolean
_local_target__poll (struct oio_lb_pool_LOCAL_s *lb,
		const char *target, guint mask_shift, struct polling_ctx_s *ctx)
{
	oio_location_t mask = lb->location_mask;
	if (lb->nearby_mode)
		mask <<= mask_shift;  // Decrease number of differentiating bits
	else
		mask >>= mask_shift;  // Increase number of differentiating bits

	GRID_TRACE2("%s pool=%s mask=%"OIO_LOC_FORMAT" target=%s",
			__FUNCTION__, lb->name, mask, target);
	gboolean res = FALSE;

	g_rw_lock_reader_lock(&lb->world->lock);
	/* each target is a sequence of '\0'-separated strings, terminated with
	 * an empty string. Each string is the name of a slot */
	for (const char *name = target; *name && !res; name += 1+strlen(name)) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot_unlocked(
				lb->world, name);
		if (!slot)
			GRID_DEBUG ("Slot [%s] not ready", name);
		else if (_local_slot__poll (slot, mask, lb->nearby_mode, ctx))
			res = TRUE;
	}
	g_rw_lock_reader_unlock(&lb->world->lock);
	return res;
}

static guint
_local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		void (*on_id) (oio_location_t location, const char *id))
{
	return _local__patch(self, avoids, NULL, on_id);
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

static guint
_local__patch(struct oio_lb_pool_s *self,
		const oio_location_t *avoids, const oio_location_t *known,
		void (*on_id) (oio_location_t location, const char *id))
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(lb->vtable == &vtable_LOCAL);
	EXTRA_ASSERT(lb->world != NULL);
	EXTRA_ASSERT(lb->targets != NULL);

	/* Count the expected targets to build a temp storage for
	 * polled locations */
	int count_targets = 0;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget)
		count_targets++;

	/* Copy the array of known locations because we don't know
	 * if its allocated length is big enough */
	oio_location_t polled[count_targets+1];
	int i = 0;
	for (; known && known[i]; i++)
		polled[i] = known[i];
	for (; i < count_targets; i++)
		polled[i] = 0;

	struct polling_ctx_s ctx = {
		.on_id = on_id,
		.avoids = avoids,
		.polled = (const oio_location_t *) polled,
		.next_polled = polled,
	};

	guint count = 0;
	for (gchar **ptarget = lb->targets; *ptarget; ++ptarget) {
		gboolean done = _local_target__is_satisfied(lb, *ptarget, &ctx);
		guint mask_shift = 0u;
		while (!done && mask_shift <= lb->location_mask_max_shift) {
			done = _local_target__poll(lb, *ptarget, mask_shift, &ctx);
			mask_shift += 8u;  // Degrade mask by 8 bits (two hex digit)
		}
		if (!done) {
			/* the strings is '\0' separated, printf won't display it */
			GRID_WARN("No service polled from target [%s]", *ptarget);
			return 0;
		}
		++ctx.next_polled;
		++count;
	}
	return count;
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
	if (!strcmp(key, OIO_LB_OPT_MASK)) {
		if (value[0] == '/') {
			guint64 mask_bits = g_ascii_strtoull(value+1, &endptr, 10u);
			if (endptr == value+1) {
				GRID_WARN("Invalid location mask [%s] for pool [%s], ",
						value, lb->name);
			} else {
				lb->location_mask = (~(oio_location_t)0) << (64 - mask_bits);
				GRID_TRACE("pool [%s] mask=%s decoded as 0x%"OIO_LOC_FORMAT,
						lb->name, value, lb->location_mask);
			}
		} else {
			guint64 new_mask = g_ascii_strtoull(value, &endptr, 16u);
			if (new_mask == 0 && endptr == value)
				GRID_WARN("Invalid location mask [%s] for pool [%s], "
						"must be 64bit hex", value, lb->name);
			else
				lb->location_mask = new_mask;
		}
	} else if (!strcmp(key, OIO_LB_OPT_MASK_MAX_SHIFT)) {
		guint64 shift = g_ascii_strtoull(value, &endptr, 10u);
		if (endptr == value)
			GRID_WARN("Invalid mask shift [%s] for pool [%s]",
					value, lb->name);
		else
			lb->location_mask_max_shift = shift;
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
	for (gchar **num_target = toks; num_target && *num_target; num_target++) {
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
	lb->location_mask = ~0xFFFFUL;
	lb->location_mask_max_shift = 16u;
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
_slot_debug (struct oio_lb_slot_s *slot, const char *name)
{
	GRID_DEBUG("slot=%s num=%u sum=%"G_GUINT32_FORMAT" flags=%d content:",
			name, slot->items->len, slot->sum_weight,
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
	gboolean _on_slot (gchar *name, struct oio_lb_slot_s *slot, void *i UNUSED) {
		_slot_debug (slot, name);
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

guint
oio_lb__poll_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t * avoids, oio_lb_on_id_f on_id)
{
	EXTRA_ASSERT(name != NULL);
	guint res = 0;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = oio_lb_pool__poll(pool, avoids, on_id);
	g_rw_lock_reader_unlock(&lb->lock);
	return res;
}

guint
oio_lb__patch_with_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t *avoids, const oio_location_t *known,
		oio_lb_on_id_f on_id)
{
	EXTRA_ASSERT(name != NULL);
	guint res = 0;
	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool = g_hash_table_lookup(lb->pools, name);
	if (pool)
		res = oio_lb_pool__patch(pool, avoids, known, on_id);
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

