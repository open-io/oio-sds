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

/*!
 * @file lb.h
 */

#ifndef GRID__LB_H
# define GRID__LB_H 1

/**
 * @defgroup metautils_lb Load-Balancing 
 * @ingroup metautils_utils
 * @{
 */

/* Service pool features ---------------------------------------------------- */

/* forward declarations from metautils */
struct service_info_s;
struct addr_info_s;

/* A hidden structure to rule them all */
struct grid_lb_s;

/*! Used to iterate over service_info while reloading the pool.
 *
 * @param p_si
 * @return
 */
typedef gboolean (*service_provider_f) (struct service_info_s **p_si);

/*! Create a pool ready to work
 *
 * @param ns
 * @param srvtype
 * @return
 */
struct grid_lb_s* grid_lb_init(const gchar *ns, const gchar *srvtype);

/*! Sets a hook to be called each time a resource is got from the
 * load-balancer. This helps providing lazy/timeout (re)loading.
 *
 * @param lb
 * @param use_hook
 */
void grid_lb_set_use_hook(struct grid_lb_s *lb, void (*use_hook)(void));

/*! frees the structure and all ots components. lb is invalid after.
 *
 * @param lb
 */
void grid_lb_clean(struct grid_lb_s *lb);

/*! Internally calls a flush then feeds all the services coming
 * out of the provider hook.
 *
 * @param lb
 * @param provide
 */
void grid_lb_reload(struct grid_lb_s *lb, service_provider_f provide);

/*! Tests if a service is still available. Unavailable means either
 * absent, a score less or equal to zero. This function performs
 * a check on the service type.
 *
 * @param lb
 * @param si
 * @return
 */
gboolean grid_lb_is_srv_available(struct grid_lb_s *lb,
		const struct service_info_s *si);

/*! Idem for a given service
 *
 * @see grid_lb_is_srv_available()
 * @param lb
 * @param ai
 * @return
 */
gboolean grid_lb_is_addr_available(struct grid_lb_s *lb,
		const struct addr_info_s *ai);

/**
 * @param lb not NULL
 * @return the number of elements in the given pool.
 */
gsize grid_lb_count(struct grid_lb_s *lb);

/*! Hidden type to represent an iterator */
struct grid_lb_iterator_s;

/*!
 * @param lb
 */
struct grid_lb_iterator_s* grid_lb_iterator_single_run(struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_scored_round_robin(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_random(struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_weighted_random(
		struct grid_lb_s *lb);

/*!
 * @param lb
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_scored_random(
		struct grid_lb_s *lb);

typedef gboolean service_filter(struct service_info_s *si, gpointer hook_data);

/*! Build an iterator based on another iterator. The concurrency is managed
 * internally.
 *
 * @param main
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_share(struct grid_lb_iterator_s *main,
		service_filter custom_filter, gpointer u, GDestroyNotify cleanup);

/*!
 * If no type is provided, the default is choosen (RR).
 *
 * Types accepted:
 * - SINGLE : simple iterator, run the services once
 * - RR (default) : simple round-robin
 * - WRR : weighted round-robin (using the service's weight)
 * - SRR : weighted round-robin (using the service's score)
 * - RAND : simple random pick
 * - WRAND : weighted random-pick (using the service's weight)
 * - SRAND : weighted random-pick (using the service's score)
 *
 * @param lb
 * @param type
 * @return
 */
struct grid_lb_iterator_s* grid_lb_iterator_init(struct grid_lb_s *lb,
		const gchar *type);

/*! Get the next service from the iterator.
 * @see service_info_clean()
 * @param iter
 * @param si
 * @return
 */
gboolean grid_lb_iterator_next(struct grid_lb_iterator_s *iter,
		struct service_info_s **si, int ttl);

struct lb_next_opt_s
{
	guint max;
	guint reqdist;
	gboolean dupplicates;
};

/*!
 * Returns 'max' different services.
 *
 * @param iter not NULL
 * @param si not NULL, set with a NULL-terminated array of (service_info_s*).
 * @param max > 0, how many services are expected
 * @return FALSE if not satisfiable
 */
gboolean grid_lb_iterator_next_set(struct grid_lb_iterator_s *iter,
		struct service_info_s ***si, struct lb_next_opt_s *opt);

/*!
 * @param iter
 * @param si
 * @return
 */
gboolean grid_lb_iterator_is_srv_available(struct grid_lb_iterator_s *iter,
		const struct service_info_s *si);

/*!
 * @param iter
 * @param ai
 * @return
 */
gboolean grid_lb_iterator_is_addr_available(struct grid_lb_iterator_s *iter,
		const struct addr_info_s *ai);

/*!
 * @param iter
 * @param url
 * @return
 */
gboolean grid_lb_iterator_is_url_available(struct grid_lb_iterator_s *iter,
		const gchar *url);

/*! Clean the iterator and all its internals structures
 *
 * @param iter
 */
void grid_lb_iterator_clean(struct grid_lb_iterator_s *iter);

/*! @} */

#endif /* GRID__LB_H */
