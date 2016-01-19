#include <string.h>

#include <glib.h>

#include "oiolb.h"
#include "oiostr.h"
#include "oioext.h"
#include "oiolog.h"
#include "internals.h"

typedef guint16 oio_refcount_t;

struct oio_lb_pool_vtable_s
{
	void (*destroy) (struct oio_lb_pool_s *self);

	guint (*poll) (struct oio_lb_pool_s *self,
			const oio_location_t * avoids,
			oio_lb_on_id_f on_id);
};

struct oio_lb_pool_abstract_s
{
	struct oio_lb_pool_vtable_s *vtable;
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

/* -------------------------------------------------------------------------- */

struct _lb_item_s
{
	oio_location_t location;
	oio_refcount_t refcount;
	oio_weight_t weight;
	gchar id[];
};

struct _slot_item_s
{
	oio_weight_acc_t acc_weight;
	struct _lb_item_s *item;
};

/* Set of services matchig the same macro "everything-but-the-location"
   criteria. */
struct oio_lb_slot_s
{
	oio_location_t location_mask;

	/* the sum of all the individual weights. */
	oio_weight_acc_t sum_weight;

	/* Array of inline <struct _slot_item_s> sorted by location. No real
	   need to complexify by a secondary sort by ID, especially if the number
	   of services at the same location is rather small.*/
	GArray *items;

	gchar *name;

	/* Does the slot need to be re-handled to computed accumulated scores.
	   When set, the slot cannot be used for polling elements. */
	guint8 flag_dirty_weights : 1;

	/* Does the slit need to be re-sorted by location.
	   When set, the slot cannot be used to be searched by location */
	guint8 flag_dirty_order : 1;

	guint8 flag_rehash_on_update : 1;
};

/* All the load-balancing information */
struct oio_lb_world_s
{
	GTree *slots;
	GTree *items;
};

struct oio_lb_pool_LOCAL_s
{
	struct oio_lb_pool_vtable_s *vtable;

	gchar * name;
	struct oio_lb_world_s *world;
	gchar ** targets;
};

static void _local__destroy (struct oio_lb_pool_s *self);

static guint _local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		oio_lb_on_id_f on_id);

static struct oio_lb_pool_vtable_s vtable_LOCAL =
{
	_local__destroy, _local__poll
};

static struct _lb_item_s *
_item_make (guint location, const char *id)
{
	int len = strlen (id);
	struct _lb_item_s *out = g_malloc0 (sizeof(struct _lb_item_s) + len + 1);
	out->location = location;
	strcpy (out->id, id);
	return out;
}

static struct oio_lb_slot_s *
oio_lb_world__get_slot (struct oio_lb_world_s *world, const char *name)
{
	g_assert (world != NULL);
	g_assert (name != NULL && *name != 0);
	return g_tree_lookup (world->slots, name);
}

#define CSLOT(p) ((const struct _slot_item_s*)(p))
#define CITEM(p) CSLOT(p)->item
#define TAB_ITEM(t,i)  g_array_index ((t), struct _slot_item_s, i)
#define SLOT_ITEM(s,i) TAB_ITEM (s->items, i)

static int
_compare_stored_items_by_location (const void *k0, const void *k)
{
	register const oio_location_t v0 = CITEM(k0)->location;
	register const oio_location_t v = CITEM(k)->location;
	return CMP(v0,v);
}

static gboolean
_item_is_to_be_avoided (const oio_location_t * avoids,
		const oio_location_t item, const oio_location_t mask)
{
	if (!avoids)
		return FALSE;
	const oio_location_t loc = mask & item;
	for (const oio_location_t *pp=avoids; *pp ;++pp) {
		if (loc == (mask & *pp))
			return TRUE;
	}
	return FALSE;
}

static void
_slot_destroy (struct oio_lb_slot_s *slot)
{
	if (!slot)
		return;
	if (slot->items) {
		const guint max = slot->items->len;
		for (guint i=0; i<max ;++i) { /* unref all the elements */
			struct _slot_item_s *si = &SLOT_ITEM(slot,i);
			struct _lb_item_s *it = si->item;
			if (NULL != it) {
				g_assert (it->refcount > 0);
				-- it->refcount;
			}
			si->acc_weight = 0;
			si->item = NULL;
		}
		g_array_free (slot->items, TRUE);
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
			si->acc_weight = sum;
			sum += si->item->weight;
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
	g_assert (start < tab->len);
	g_assert (end < tab->len);
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
		struct polling_ctx_s *ctx, guint i)
{
	const struct _lb_item_s *item = _slot_get (slot, i);
	const oio_location_t loc = item->location;
	if (_item_is_to_be_avoided (ctx->avoids, loc, mask))
		return FALSE;
	if (_item_is_to_be_avoided (ctx->polled, loc, (oio_location_t)-1))
		return FALSE;
	ctx->on_id (loc, item->id);
	*(ctx->next_polled) = loc;
	return TRUE;
}

/* Perform a weighted-random polling in the slot.
 * Starting at the "closest" match, perform a ZigZag lookup and for
 * each item check the polled item is not in the set to be avoided.
 * The purpose of the ZigZag is to stay as close as possible to the
 * closest weight. */
static gboolean
_local_slot__poll (struct oio_lb_slot_s *slot, gboolean masked,
		struct polling_ctx_s *ctx)
{
	if (_slot_needs_rehash (slot))
		_slot_rehash (slot);

	GRID_TRACE2("%s slot=%s sum=%"G_GUINT32_FORMAT" items=%d mask=%u",
			__FUNCTION__, slot->name, slot->sum_weight, slot->items->len,
			masked);

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
	g_assert (i >= 0);
	g_assert ((guint)i < slot->items->len);

	/* do the ZigZag */
	oio_location_t mask = masked ? slot->location_mask : (oio_location_t)-1;
	guint minus = i, plus = i+1;
	while (minus > 0 || plus < slot->items->len) {
		if (minus > 0 && _accept_item (slot, mask, ctx, minus--))
			return TRUE;
		if (plus < slot->items->len && _accept_item(slot, mask, ctx, plus++))
			return TRUE;
	}

	GRID_TRACE2("%s avoided everything in slot=%s", __FUNCTION__, slot->name);
	return FALSE;
}

static gboolean
_local_target__poll (struct oio_lb_pool_LOCAL_s *lb,
		const char *target, gboolean masked, struct polling_ctx_s *ctx)
{
	GRID_TRACE2("%s pool=%s mask=%d", __FUNCTION__, lb->name, masked);

	/* each target is a sequence of '\0'-separated strings, terminated with
	 * an empty string. Each string is the name of a slot */
	for (const char *name = target; *name ;name+=1+strlen(name)) {
		struct oio_lb_slot_s *slot = oio_lb_world__get_slot (lb->world, name);
		if (!slot)
			GRID_DEBUG ("Slot [%s] not ready", name);
		else if (_local_slot__poll (slot, masked, ctx))
			return TRUE;
	}
	return FALSE;
}

static guint
_local__poll (struct oio_lb_pool_s *self,
		const oio_location_t * avoids,
		void (*on_id) (oio_location_t location, const char *id))
{
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	g_assert (lb != NULL);
	g_assert (lb->vtable == &vtable_LOCAL);
	g_assert (lb->world != NULL);
	g_assert (lb->targets != NULL);

	/* count the expected targets to build a temporary storage for
	 * polled locations */
	guint count_targets = 0;
	for (gchar **ptarget=lb->targets; *ptarget ;++ptarget)
		count_targets ++;
	oio_location_t polled[count_targets+1];
	memset (polled, 0, sizeof(oio_location_t) * (1+count_targets));

	struct polling_ctx_s ctx = {
		.on_id = on_id,
		.avoids = avoids,
		.polled = (const oio_location_t *) polled,
		.next_polled = polled,
	};

	/* each target must provide an item. For each target, try the slots with
	 * with their connstraints, and if no reply has been made, retry without
	 * the constraints. */
	guint count = 0;
	for (gchar **ptarget=lb->targets; *ptarget ;++ptarget) {
		gboolean done = _local_target__poll (lb, *ptarget, TRUE, &ctx);
		if (!done)
			done = _local_target__poll (lb, *ptarget, FALSE, &ctx);
		if (!done) {
			/* the strings is '\0' separated, printf won't display it */
			GRID_WARN ("No service polled from target [%s]", *ptarget);
			return 0;
		}
		++ ctx.next_polled;
		++ count;
	}
	return count;
}

static void
_local__destroy (struct oio_lb_pool_s *self)
{
	g_assert (self != NULL);
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	g_assert (lb->vtable == &vtable_LOCAL);
	g_strfreev (lb->targets);
	oio_str_clean (&lb->name);
	g_free (lb);
}

void
oio_lb_world__add_pool_target (struct oio_lb_pool_s *self, const char *to)
{
	g_assert (self != NULL);
	struct oio_lb_pool_LOCAL_s *lb = (struct oio_lb_pool_LOCAL_s *) self;
	g_assert (lb->vtable == &vtable_LOCAL);
	g_assert (lb->world != NULL);
	g_assert (lb->targets != NULL);

	/* prepare the string to be easy to parse. */
	gsize tolen = strlen (to);
	gchar *copy = g_malloc (tolen + 2);
	memcpy (copy, to, tolen + 1);
	copy [tolen+1] = '\0';
	for (gchar *p=copy; *p ;) {
		if (!(p = strchr (p, ','))) break; else *(p++) = '\0';
	}

	const gsize len = g_strv_length (lb->targets);
	lb->targets = g_realloc (lb->targets, (len+2) * sizeof(gchar*));
	lb->targets [len] = copy;
	lb->targets [len+1] = NULL;
}

/* -------------------------------------------------------------------------- */

struct oio_lb_world_s *
oio_lb_local__create_world (void)
{
	struct oio_lb_world_s *self = g_malloc0 (sizeof(*self));
	self->slots = g_tree_new_full (oio_str_cmp3, NULL,
			g_free, (GDestroyNotify) _slot_destroy);
	self->items = g_tree_new_full (oio_str_cmp3, NULL,
			g_free, g_free);
	return self;
}

void
oio_lb_world__destroy (struct oio_lb_world_s *self)
{
	if (!self)
		return;
	if (self->slots)
		g_tree_destroy (self->slots);
	if (self->items)
		g_tree_destroy (self->items);
	g_free (self);
}

struct oio_lb_pool_s *
oio_lb_world__create_pool (struct oio_lb_world_s *world, const char *name)
{
	g_assert (world != NULL);
	struct oio_lb_pool_LOCAL_s *lb = g_malloc0 (sizeof(struct oio_lb_pool_LOCAL_s));
	lb->vtable = &vtable_LOCAL;
	lb->name = g_strdup (name);
	lb->world = world;
	lb->targets = g_malloc0 (4 * sizeof(gchar*));
	return (struct oio_lb_pool_s*) lb;
}

static struct oio_lb_slot_s *
_world_create_slot (struct oio_lb_world_s *self, const char *name)
{
	struct oio_lb_slot_s *slot = oio_lb_world__get_slot (self, name);
	if (NULL != slot)
		return slot;
	slot = g_malloc0 (sizeof(*slot));
	slot->name = g_strdup (name);
	slot->location_mask = ((oio_location_t)-1) - 0xFF;
	slot->items = g_array_new (FALSE, TRUE, sizeof(struct _slot_item_s));
	g_tree_replace (self->slots, g_strdup (name), slot);
	return slot;
}

guint
oio_lb_world__count_slots (struct oio_lb_world_s *self)
{
	g_assert (self != NULL);
	return g_tree_nnodes (self->slots);
}

guint
oio_lb_world__count_items (struct oio_lb_world_s *self)
{
	g_assert (self != NULL);
	return g_tree_nnodes (self->items);
}

void
oio_lb_world__create_slot (struct oio_lb_world_s *self, const char *name)
{
	g_assert (self != NULL);
	g_assert (name != NULL && *name != '\0');
	(void) _world_create_slot (self, name);
}

static oio_location_t
_location_at_position (GArray *tab, const guint i)
{
	g_assert (i < tab->len);
	return TAB_ITEM(tab,i).item->location;
}

static int
_slide_to_first_at_location (GArray *tab, const oio_location_t needle,
		guint i)
{
	g_assert_cmpint (needle, ==, _location_at_position(tab,i));
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
	g_assert (start < tab->len);
	g_assert (end < tab->len);

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

void
oio_lb_world__feed_slot (struct oio_lb_world_s *self, const char *name,
		const struct oio_lb_item_s *item)
{
	g_assert (self != NULL);
	g_assert (name != NULL && *name != '\0');
	g_assert (item != NULL);
	GRID_TRACE2 ("> Feeding [%s,%"G_GUINT64_FORMAT"] in slot=%s",
			item->id, (guint64) item->location, name);

	gboolean found = FALSE;

	struct oio_lb_slot_s *slot = oio_lb_world__get_slot (self, name);
	if (!slot)
		return;

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
		if (slot->items->len)
			i0 = _search_first_at_location (slot->items, item0->location,
					0, slot->items->len-1);

		if (i0 != (guint)-1) {
			/* then iterate on the location to find it precisely. */
			for (guint i=i0; !found && i<slot->items->len ;++i) {
				if (item0 == _slot_get(slot,i)) {
					found = TRUE;
					/* we found the old item, now check the loca matches */
					if (item0->location != item->location) {
						item0->location = item->location;
						slot->flag_dirty_order = 1;
					}
				}
			}
		}
	}
	g_assert_nonnull (item0);

	if (!found) {
		++ item0->refcount;
		struct _slot_item_s fake = {0, item0};
		g_array_append_vals (slot->items, &fake, 1);
		item0 = NULL;
		found = TRUE;
		slot->flag_dirty_order = 1;
		slot->flag_dirty_weights = 1;
	}

	if (slot->flag_rehash_on_update && _slot_needs_rehash (slot))
		_slot_rehash (slot);
}

static void
_slot_debug (struct oio_lb_slot_s *slot, const char *name)
{
	GRID_DEBUG ("slot=%s num=%u sum=%"G_GUINT32_FORMAT" content:",
			name, slot->items->len, slot->sum_weight);
	for (guint i=0; i<slot->items->len ;++i) {
		const struct _slot_item_s *si = &SLOT_ITEM(slot,i);
		GRID_DEBUG ("- [%s,%"OIO_LOC_FORMAT"] w=%u/%"G_GUINT32_FORMAT,
				si->item->id, si->item->location, si->item->weight, si->acc_weight);
	}
}

void
oio_lb_world__debug (struct oio_lb_world_s *self)
{
	g_assert_nonnull (self);
	gboolean _on_slot (gchar *name, struct oio_lb_slot_s *slot, void *i) {
		(void) i;
		_slot_debug (slot, name);
		return FALSE;
	}
	g_tree_foreach (self->slots, (GTraverseFunc)_on_slot, NULL);
}
