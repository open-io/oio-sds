/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
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

#ifndef OIO_SDS__metautils__lib__lb_h
# define OIO_SDS__metautils__lib__lb_h 1

#include <metautils/lib/metatypes.h>

struct namespace_info_s;

/* -- New style load balancing -------------------------------------------- */

/** Insert or update a list of services in a LB world */
void oio_lb_world__feed_service_info_list(struct oio_lb_world_s *lbw,
		GSList *services);

/** Check there is a pool for each storage policy. If not, create a dummy one.
 * @see oio_lb_pool__from_storage_policy */
void oio_lb_world__reload_storage_policies(struct oio_lb_world_s *lbw,
		struct oio_lb_s *lb, struct namespace_info_s *nsinfo);

/** Create service pools from string definitions. */
void oio_lb_world__reload_pools(struct oio_lb_world_s *lbw,
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
