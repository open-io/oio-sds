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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <math.h>
#include <glib.h>
#include <json.h>

#include "metautils.h"

#define SLOT(P) ((struct score_slot_s*)P)

typedef guint32 srv_weight_t;
typedef guint32 srv_score_t;

struct score_slot_s
{
	guint index;
	srv_score_t score;
	guint32 sum;
};

void
oio_lb_world__feed_service_info_list(struct oio_lb_world_s *lbw,
		GSList *services)
{
	for (GSList *l = services; l; l = l->next) {
		char slot_name[128] = {0};
		struct service_info_s *srv = l->data;
		/* Allocate item on the stack, it will be copied later */
		struct oio_lb_item_s *item = g_alloca(sizeof(struct oio_lb_item_s)+128);
		service_info_to_lb_item(srv, item);

		/* Insert the service in a slot named after its storage class */
		g_snprintf(slot_name, sizeof(slot_name), "%s-%s",
				srv->type, service_info_get_stgclass(srv, STORAGE_CLASS_NONE));
		oio_lb_world__create_slot(lbw, slot_name);
		oio_lb_world__feed_slot(lbw, slot_name, item);

		// TODO: insert the service in slots named after its tags

		/* Insert the service in the main pool */
		g_snprintf(slot_name, sizeof(slot_name), "%s", srv->type);
		oio_lb_world__create_slot(lbw, slot_name);
		oio_lb_world__feed_slot(lbw, slot_name, item);
	}
}

void
oio_lb_world__reload_storage_policies(struct oio_lb_world_s *lbw,
		struct oio_lb_s *lb, struct namespace_info_s *nsinfo)
{
	/* For the special case of rawx services,
	** add a pool for each storage policy */
	void _make_pools(gpointer key, gpointer val, gpointer udata)
	{
		(void)udata;
		(void)val;
		const char *stgpol_name = key;
		struct storage_policy_s *stgpol = storage_policy_init(nsinfo,
				stgpol_name);
		struct oio_lb_pool_s *pool = \
				oio_lb_pool__from_storage_policy(lbw, stgpol);
		oio_lb__force_pool(lb, pool);
		storage_policy_clean(stgpol);
	}

	g_hash_table_foreach(nsinfo->storage_policy, _make_pools, NULL);
}

struct oio_lb_pool_s *
oio_lb_pool__from_service_policy(struct oio_lb_world_s *lbw,
		const gchar *srvtype, struct service_update_policies_s *pols)
{
	/* Create a pool with as many targets as required
	** by the service update policy */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lbw, srvtype);
	GString *targets = g_string_sized_new(64);
	// TODO: maybe add a target with a tag (service_update_tagfilter())
	g_string_append_printf(targets, "%s-%s", srvtype, STORAGE_CLASS_NONE);
	g_string_append_printf(targets, ",%s", srvtype);

	guint howmany = service_howmany_replicas(pols, srvtype);
	GRID_DEBUG("pool [%s] will target [%s] %u times",
			srvtype, targets->str, howmany);
	for (; howmany > 0; howmany--)
		oio_lb_world__add_pool_target(pool, targets->str);

	g_string_free(targets, TRUE);
	return pool;
}

struct oio_lb_pool_s *
oio_lb_pool__from_storage_policy(struct oio_lb_world_s *lbw,
		const struct storage_policy_s *stgpol)
{
	const struct storage_class_s *stgclass = \
			storage_policy_get_storage_class(stgpol);
	const char *stgpol_name = storage_policy_get_name(stgpol);

	/* Build the list of slots */
	GString *targets = g_string_sized_new(64);
	g_string_append_printf(targets, NAME_SRVTYPE_RAWX"-%s",
			storage_class_get_name(stgclass));
	const GSList *fallbacks = storage_class_get_fallbacks(stgclass);
	for (const GSList *l = fallbacks; l; l = l->next)
		g_string_append_printf(targets, ","NAME_SRVTYPE_RAWX"-%s",
				(const char*)l->data);

	/* Build a pool for the storage policy */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lbw,
			stgpol_name);

	/* Add the list of slots as target for the pool */
	gint64 howmany = storage_policy_get_nb_chunks(stgpol);
	GRID_DEBUG("pool [%s] will target [%s] %"G_GINT64_FORMAT" times",
			stgpol_name, targets->str, howmany);
	for (; howmany > 0; howmany--)
		oio_lb_world__add_pool_target(pool, targets->str);

	g_string_free(targets, TRUE);
	return pool;
}
