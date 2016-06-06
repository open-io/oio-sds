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

#ifndef OIO_SDS__core__oiolb_h
# define OIO_SDS__core__oiolb_h 1
# include <stdbool.h>
# include <glib.h>

#define OIO_LOC_FORMAT G_GUINT64_FORMAT
typedef guint64 oio_location_t;
typedef guint8 oio_weight_t;

/* the sum of all the weights in a slot shall not overflow the capacity of
 * an oio_weight_acc_t. We internally need this to enweight pools */
typedef guint32 oio_weight_acc_t;

typedef void (*oio_lb_on_id_f) (oio_location_t, const char *);

struct oio_lb_item_s
{
	oio_location_t location;
	oio_weight_t weight;
	gchar id[];
};

struct oio_lb_pool_s;

/* Destroy the load-balancing pool pointed by <self>. */
void oio_lb_pool__destroy (struct oio_lb_pool_s *self);

/* Returns IDs from <self> that are not in <avoids> (supposed to be
 * small). <on_id> will be called once for each ID polled. One ID won't be
 * returned more than once. The number of IDs returned is the number of
 * targets of the pool. */
guint oio_lb_pool__poll (struct oio_lb_pool_s *self,
		const oio_location_t *avoids,
		oio_lb_on_id_f on_id);

/* Like oio_lb_pool__poll(), but provide an array of known locations. */
guint oio_lb_pool__patch(struct oio_lb_pool_s *self,
		const oio_location_t *avoids,
		const oio_location_t *known,
		oio_lb_on_id_f on_id);

/* Get an item from its ID. Returns NULL if the ID is isn't known.
 * The result must be freed with g_free(). */
struct oio_lb_item_s *oio_lb_pool__get_item(struct oio_lb_pool_s *self,
		const char *id);

/* -------------------------------------------------------------------------- */

/* A world is something you feed with services and that will arrange them for
 * you in slots. Services are tuples like <location,score,id>.
 * A slot is a partition of the world that is identified by a name. It holds
 * services. For the sake of simplicity, slots are not exposed but only
 * accessed through the world. */
struct oio_lb_world_s;

/* Constructor of worlds, a.k.a. a cosmogony */
struct oio_lb_world_s * oio_lb_local__create_world (void);

/* Vishnu, destroyer of worlds */
void oio_lb_world__destroy (struct oio_lb_world_s *self);

/* Use this carefully, it GRID_DEBUG() all the items in the given world */
void oio_lb_world__debug (struct oio_lb_world_s *self);

guint oio_lb_world__count_slots (struct oio_lb_world_s *self);
guint oio_lb_world__count_items (struct oio_lb_world_s *self);
guint oio_lb_world__count_slot_items(struct oio_lb_world_s *self, const char *name);

/** Get an item from the world. The result must be freed with g_free(). */
struct oio_lb_item_s *oio_lb_world__get_item(struct oio_lb_world_s *self,
		const char *id);

/* Ensure the slot exists in the  given world. */
void oio_lb_world__create_slot (struct oio_lb_world_s *self, const char *name);

/* Tell the world that the given service belong to the named slot. */
void oio_lb_world__feed_slot (struct oio_lb_world_s *self, const char *slot,
		const struct oio_lb_item_s *item);

/* Create a world-based implementation of a service pool. */
struct oio_lb_pool_s * oio_lb_world__create_pool (
		struct oio_lb_world_s *world, const char *name);

/* Tell the given world-based pool that it must target the given set of slots.
 * The slots sequence is coma-separated. It is an error to call this on a
 * not world-based pool. */
void oio_lb_world__add_pool_target (struct oio_lb_pool_s *self, const char *to);


/* -- LB pools management ------------------------------------------------- */

struct oio_lb_s {
	GRWLock lock;
	GHashTable *pools;
};

struct oio_lb_s *oio_lb__create(void);
void oio_lb__clear(struct oio_lb_s **lb);

/** Set or replace a pool. The key to access the pool is the name
 * of the pool as set at pool creation. Thread-safe. */
void oio_lb__force_pool(struct oio_lb_s *lb, struct oio_lb_pool_s*);

void oio_lb__delete_pool(struct oio_lb_s *lb, const char *name);

/** Calls oio_lb_pool__poll() on the pool `name`. Thread-safe. */
guint oio_lb__poll_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t * avoids, oio_lb_on_id_f on_id);

/** Calls oio_lb_pool__patch() on the pool `name`. Thread-safe. */
guint oio_lb__patch_with_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t *avoids, const oio_location_t *known,
		oio_lb_on_id_f on_id);

/** Get an item from a pool. Returns NULL if ID isn't known.
 *  The result must be freed with g_free(). */
struct oio_lb_item_s *oio_lb__get_item_from_pool(struct oio_lb_s *lb,
		const char *name, const char *id);

#endif /*OIO_SDS__core__oiolb_h*/
