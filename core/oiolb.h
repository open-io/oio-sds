/*
OpenIO SDS load-balancing
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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
# include <glib.h>
# include <core/oioloc.h>

typedef guint8 oio_weight_t;

/* the sum of all the weights in a slot shall not overflow the capacity of
 * an oio_weight_acc_t. We internally need this to enweight pools */
typedef guint32 oio_weight_acc_t;

// Defined in metautils/lib/metatypes.h
#ifndef LIMIT_LENGTH_SRVID
# define LIMIT_LENGTH_SRVID 64
#endif

#define STRLEN_ADDRINFO    sizeof("[XXXX:XXXX:XXXX:XXXX:XXXX:XXXX]:SSSSS")

struct oio_lb_item_s
{
	oio_location_t location;
	oio_weight_t weight;
	gchar addr[STRLEN_ADDRINFO];
	gchar id[LIMIT_LENGTH_SRVID];
	gchar tls[STRLEN_ADDRINFO];
};

struct oio_lb_selected_item_s
{
	struct oio_lb_item_s *item;
	gchar *expected_slot;
	gchar *final_slot;
	guint16 expected_dist;
	guint16 final_dist;
	guint16 warn_dist;
};


void oio_lb_selected_item_free(struct oio_lb_selected_item_s *item);

/* Signature for callbacks from `oio_lb_pool__poll` or `oio_lb_pool__patch`.
 *
 * First parameter represents a service which has been selected, plus the
 * quality of the selection. Do not free it, is is owned by the load-balancer.
 * Second parameter is a user-defined pointer passed to the polling function.
 */
typedef void (*oio_lb_on_id_f) (struct oio_lb_selected_item_s*, gpointer);

struct oio_lb_pool_s;

/* Destroy the load-balancing pool pointed by <self>. */
void oio_lb_pool__destroy (struct oio_lb_pool_s *self);

/* Returns IDs from <self> that are not in <avoids> (supposed to be
 * small). <on_id> will be called once for each ID polled. One ID won't be
 * returned more than once. The number of IDs returned is the number of
 * targets of the pool. <flawed> is a boolean that will be true if
 * some of the criteria of the pool could not be satisfied. */
GError *oio_lb_pool__poll(struct oio_lb_pool_s *self,
		const oio_location_t *avoids,
		oio_lb_on_id_f on_id, gboolean *flawed);

/* Like oio_lb_pool__poll(), but provide an array of known locations. */
GError *oio_lb_pool__patch(struct oio_lb_pool_s *self,
		const oio_location_t *avoids,
		const oio_location_t *known,
		oio_lb_on_id_f on_id, gboolean *flawed);

/* Get an item from its ID. Returns NULL if the ID is isn't known.
 * The result must be freed with g_free(). */
struct oio_lb_item_s *oio_lb_pool__get_item(struct oio_lb_pool_s *self,
		const char *id);

/* -------------------------------------------------------------------------- */

/* Resolve service_id to service address or TLS address.
 * The result must be freed if found or NULL. */
gchar* oio_lb_resolve_service_id(const gchar* service_id, gboolean upgrade_to_tls);

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

/* Flush all items of all slots */
void oio_lb_world__flush(struct oio_lb_world_s *self);

/* Call a function on all items of all slots. */
void oio_lb_world__foreach(struct oio_lb_world_s *self, void *udata,
		void (*on_item)(const char *id, const char *addr, void *udata));

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

/* Tell the world that the given service belongs to the named slot. */
void oio_lb_world__feed_slot (struct oio_lb_world_s *self, const char *slot,
		const struct oio_lb_item_s *item);

/* Tell the world that all services of the list belong to the named slot.
 * And rehash the slot. */
void oio_lb_world__feed_slot_with_list(struct oio_lb_world_s *self,
		const char *slot, GSList *items);

/* Create a world-based implementation of a service pool. */
struct oio_lb_pool_s * oio_lb_world__create_pool (
		struct oio_lb_world_s *world, const char *name);

void oio_lb_world__increment_generation(struct oio_lb_world_s *self);

void oio_lb_world__purge_old_generations(struct oio_lb_world_s *self);

/* When not possible to purge old generations (because of update errors),
 * we must still rehash the slots that have been updated. */
void oio_lb_world__rehash_all_slots(struct oio_lb_world_s *self);

/* Maximum distance between services */
#define OIO_LB_OPT_MAX_DIST       "max_dist"
/* Absolute minimum distance between services */
#define OIO_LB_OPT_MIN_DIST       "min_dist"
/* Distance between services at which the LB will emit a warning */
#define OIO_LB_OPT_WARN_DIST      "warn_dist"
/* Look for services close to each other (boolean string) */
#define OIO_LB_OPT_NEARBY         "nearby_mode"

/* Set a pool option. See option names above. */
void oio_lb_world__set_pool_option(struct oio_lb_pool_s *self, const char *key,
		const char *value);

/* Tell the given world-based pool that it must target the given set of slots.
 * The slots sequence is coma-separated. It is an error to call this on a
 * not world-based pool. */
void oio_lb_world__add_pool_target (struct oio_lb_pool_s *self, const char *to);

/* Tell the given world-based pool that it must target the given set of slots.
 * This function expects a string formatted like
 * "2,meta2-fast-europe,meta2-slow-europe;1,meta2-fast-usa,meta2-slow-usa" */
void oio_lb_world__add_pool_targets(struct oio_lb_pool_s *self,
		const gchar *targets);

/* Dump the pool targets and options. */
GString *oio_lb_world__dump_pool_options(struct oio_lb_pool_s *self);

/* Count the expected number of targets of this pool. */
guint oio_lb_world__count_pool_targets(struct oio_lb_pool_s *self);

/* -- LB pools management ------------------------------------------------- */

struct oio_lb_s {
	GRWLock lock;
	GHashTable *pools;
};

struct oio_lb_s *oio_lb__create(void);
void oio_lb__clear(struct oio_lb_s **lb);

gboolean oio_lb__has_pool(struct oio_lb_s *lb, const char *name);

/** Set or replace a pool. The key to access the pool is the name
 * of the pool as set at pool creation. Thread-safe. */
void oio_lb__force_pool(struct oio_lb_s *lb, struct oio_lb_pool_s*);

void oio_lb__delete_pool(struct oio_lb_s *lb, const char *name);

/** Calls oio_lb_pool__poll() on the pool `name`. Thread-safe. */
GError *oio_lb__poll_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t * avoids, oio_lb_on_id_f on_id, gboolean *flawed);

/** Calls oio_lb_pool__poll() on the pool `name`. Focus on the
 * provided location.
 * Thread-safe. */
GError *oio_lb__poll_pool_around(struct oio_lb_s *lb, const char *name,
		const oio_location_t pin, int mode,
		oio_lb_on_id_f on_id, gboolean *flawed);

/** Calls oio_lb_pool__patch() on the pool `name`. Thread-safe. */
GError *oio_lb__patch_with_pool(struct oio_lb_s *lb, const char *name,
		const oio_location_t *avoids, const oio_location_t *known,
		oio_lb_on_id_f on_id, gboolean *flawed);

/** Get an item from a pool. Returns NULL if ID isn't known.
 *  The result must be freed with g_free(). */
struct oio_lb_item_s *oio_lb__get_item_from_pool(struct oio_lb_s *lb,
		const char *name, const char *id);

GString* oio_selected_item_quality_to_json(GString *inout,
		struct oio_lb_selected_item_s *sel);

#endif /*OIO_SDS__core__oiolb_h*/
