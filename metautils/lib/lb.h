/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__lb_h
# define OIO_SDS__metautils__lib__lb_h 1

#include <metautils/lib/metatypes.h>

struct namespace_info_s;
struct service_info_s;
struct addr_info_s;
struct json_object;

/* Service pool features ---------------------------------------------------- */

/*! thread-safe structure managing several service pools, and holding the
 * load-balancing policies. */
struct grid_lbpool_s;

/*! A way to iterate on services from a mono-type pool. */
struct grid_lb_iterator_s;

/*! Used to iterate over service_info while reloading the pool. */
typedef gboolean (*service_provider_f) (struct service_info_s **p_si);


/* Iterators features ------------------------------------------------------ */

/*! Build an iterator based on another iterator. The concurrency is managed
 * internally. */
struct grid_lb_iterator_s* grid_lb_iterator_share(struct grid_lb_iterator_s *i);

/*! Clean the iterator and all its internals structures */
void grid_lb_iterator_clean(struct grid_lb_iterator_s *iter);

/*!  */
gboolean grid_lb_iterator_is_url_available(struct grid_lb_iterator_s *iter,
		const gchar *url);

/* Polling ----------------------------------------------------------------- */

typedef gboolean (*service_filter) (struct service_info_s *si, gpointer hook_data);

struct lb_next_opt_ext_s
{
	/** Number of services to get */
	guint max;

	/** Required distance between services */
	guint distance;

	/** Is it allowed to weaken the distance requirements? */
	gboolean weak_distance;

	/** Is it allowed to choose several times the same service */
	gboolean duplicates;

	 /** Wanted rawx storage class */
	const struct storage_class_s *stgclass;

	/** Prevent storage class fallbacks */
	gboolean strict_stgclass;

	/* Additional explicit constraint based on services already polled.
	 * This is typically used to check the distance between a new services
	 * with old ones. */
	GSList *srv_inplace;

	/* Additional explicit constraint */
	GSList *srv_forbidden;

	/* Yet another custom filter */
	struct lb_next_opt_filter_s {
		service_filter hook;
		gpointer data;
	} filter;
};

/*!
 * Returns 'max' different services.
 *
 * @param iter not NULL
 * @param si not NULL, set with a NULL-terminated array of (service_info_s*).
 * @param opt Options for the set of services
 * @return FALSE if not satisfiable
 */
gboolean grid_lb_iterator_next_set2(struct grid_lb_iterator_s *iter,
		struct service_info_s ***si, struct lb_next_opt_ext_s *opt,
		GError **err);

GString * grid_lb_iterator_to_string (struct grid_lb_iterator_s *it);

/* Multi-services pool features --------------------------------------------- */

/*! Create a lbpool ready to use (no service declared). */
struct grid_lbpool_s* grid_lbpool_create(const gchar *ns);

/*! Frees the memory used by the lbpool */
void grid_lbpool_destroy(struct grid_lbpool_s *glp);

/*! Ensure each type is managed according to the NS configuration. */
void grid_lbpool_reconfigure(struct grid_lbpool_s *glp,
		struct namespace_info_s *ni);

/*! Ensure the type is managed according to the given configuration */
void grid_lbpool_configure_string(struct grid_lbpool_s *glp,
		const gchar *srvtype, const gchar *cfg);

/*! Ensure the type is managed (pool+iterator) abd return the iterator. */
struct grid_lb_iterator_s * grid_lbpool_ensure_iterator (
		struct grid_lbpool_s *glp, const gchar *srvtype);

/*! Return the iterator for the given type, if managed (or NULL otherwise) */
struct grid_lb_iterator_s* grid_lbpool_get_iterator(
		struct grid_lbpool_s *glp, const gchar *srvtype);

/*! Internally calls a flush then feeds all the services coming
 * out of the provider hook. */
void grid_lbpool_reload(struct grid_lbpool_s *glp, const gchar *srvtype,
		service_provider_f provider);

/*! @see grid_lb_reload() */
GError* grid_lbpool_reload_json_object(struct grid_lbpool_s *glp, const gchar *srvtype,
		struct json_object *obj);

/*! @see grid_lb_reload() */
GError* grid_lbpool_reload_json(struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *encoded);

/*! Find a service inside service pools. If `srvtype` is NULL,
 * search in all the pools (slow, use with parsimony). */
struct service_info_s* grid_lbpool_get_service_from_url(
		struct grid_lbpool_s *glp, const gchar *srvtype,
		const gchar *url);

/*! flush all the sets registered in the given pool */
void grid_lbpool_flush(struct grid_lbpool_s *glp);


/* -- New style load balancing -------------------------------------------- */

/** Insert or update a list of services in a LB world */
void oio_lb_world__feed_service_info_list(struct oio_lb_world_s *lbw,
		GSList *services);

/** Create a service pool for each declared storage policy
 * @see oio_lb_pool__from_storage_policy */
void oio_lb_world__reload_storage_policies(struct oio_lb_world_s *lbw,
		struct oio_lb_s *lb, struct namespace_info_s *nsinfo);

/** Create a service pool returning sets of services satisfying
 * the specified service update policy */
struct oio_lb_pool_s *oio_lb_pool__from_service_policy(
		struct oio_lb_world_s *lbw,
		const gchar *srvtype,
		struct service_update_policies_s *pols);

/** Create a service pool returning sets of services satisfying
 * the specified storage policy */
struct oio_lb_pool_s *oio_lb_pool__from_storage_policy(
		struct oio_lb_world_s *lbw,
		const struct storage_policy_s *stgpol);

#endif /*OIO_SDS__metautils__lib__lb_h*/
