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

void
oio_lb_world__feed_service_info_list(struct oio_lb_world_s *lbw,
		GSList *services)
{
	struct oio_lb_item_s *item =
		g_alloca(sizeof(struct oio_lb_item_s) + LIMIT_LENGTH_SRVID);

	for (GSList *l = services; l; l = l->next) {
		char slot_name[128] = {0};
		struct service_info_s *srv = l->data;
		service_info_to_lb_item(srv, item);

		/* Insert the service in slots described in tag.slots */
		const gchar *slot_list_str = service_info_get_tag_value(srv,
				NAME_TAGNAME_SLOTS, NULL);
		if (slot_list_str) {
			gchar **tokens = g_strsplit(slot_list_str, OIO_CSV_SEP, -1);
			for (gchar **token = tokens; token && *token; token++) {
				/* Ensure the slot name is prefixed by the type of service */
				if (!g_str_has_prefix(*token, srv->type))
					g_snprintf(slot_name, sizeof(slot_name), "%s-%s",
							srv->type, *token);
				else
					g_strlcpy(slot_name, *token, sizeof(slot_name));
				oio_lb_world__create_slot(lbw, slot_name);
				oio_lb_world__feed_slot(lbw, slot_name, item);
			}
			g_strfreev(tokens);
		}

		/* Insert the service in the main slot */
		g_snprintf(slot_name, sizeof(slot_name), "%s", srv->type);
		oio_lb_world__create_slot(lbw, slot_name);
		oio_lb_world__feed_slot(lbw, slot_name, item);
		memset(item, 0, sizeof(struct oio_lb_item_s) + LIMIT_LENGTH_SRVID);
	}
}

void
oio_lb_world__reload_storage_policies(struct oio_lb_world_s *lbw,
		struct oio_lb_s *lb, struct namespace_info_s *nsinfo)
{
	EXTRA_ASSERT(lbw != NULL);
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(nsinfo != NULL);

	if (!nsinfo->storage_policy) {
		GRID_INFO("Not checking storage policies: configuration is NULL");
		return;
	}
	void _make_pools(gpointer key, gpointer val UNUSED, gpointer udata UNUSED)
	{
		const char *polname = key;
		struct storage_policy_s *stgpol = storage_policy_init(nsinfo, polname);
		if (!stgpol) {
			GRID_DEBUG("Storage policy [%s] not found or invalid", polname);
		} else {
			const char *pool_name = storage_policy_get_service_pool(stgpol);
			if (!pool_name) {
				GRID_DEBUG("No pool configured for policy [%s]", polname);
			} else if (!oio_lb__has_pool(lb, pool_name)) {
				struct oio_lb_pool_s *pool =
					oio_lb_pool__from_storage_policy(lbw, stgpol);
				GRID_INFO("No service pool [%s] for storage policy [%s], "
						"creating one", pool_name, polname);
				oio_lb__force_pool(lb, pool);
			}
			storage_policy_clean(stgpol);
		}
	}

	g_hash_table_foreach(nsinfo->storage_policy, _make_pools, NULL);
}

void
oio_lb_world__reload_pools(struct oio_lb_world_s *lbw,
		struct oio_lb_s *lb, struct namespace_info_s *nsinfo)
{
	EXTRA_ASSERT(lbw != NULL);
	EXTRA_ASSERT(lb != NULL);
	EXTRA_ASSERT(nsinfo != NULL);

	if (!nsinfo->service_pools) {
		GRID_INFO("Not loading service pools: configuration is NULL");
		return;
	}
	GRID_DEBUG("Loading pools from configuration");
	void _reload_pool(const gchar *name, GByteArray *def,
			gpointer unused UNUSED) {
		if (!def) {
			GRID_DEBUG("pool [%s] definition is NULL", name);
			return;
		}
		char *str_def = g_alloca(def->len + 1);
		strncpy(str_def, (const char*)def->data, def->len);
		str_def[def->len] = '\0';
		struct oio_lb_pool_s *pool = NULL;
		pool = oio_lb_world__create_pool(lbw, name);
		GRID_DEBUG("pool [%s] will target [%s]", name, str_def);
		oio_lb_world__add_pool_targets(pool, str_def);
		oio_lb__force_pool(lb, pool);
	}
	g_hash_table_foreach(nsinfo->service_pools, (GHFunc)_reload_pool, NULL);
}

struct oio_lb_pool_s *
oio_lb_pool__from_service_policy(struct oio_lb_world_s *lbw,
		const gchar *srvtype, struct service_update_policies_s *pols)
{
	/* Create a pool with as many targets as required
	** by the service update policy */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lbw, srvtype);
	GString *targets = g_string_sized_new(64);
	g_string_append_printf(targets, "%s", srvtype);

	gchar *user_is_service = service_update_get_tag_value(
			pols, srvtype, NAME_TAGNAME_USER_IS_SERVICE);
	guint howmany = service_howmany_replicas(pols, srvtype);
	if (user_is_service) {
		oio_lb_world__add_pool_target(pool, user_is_service);
		GRID_INFO("pool [%s] will target [%s] 1 time and [%s] %u times",
				srvtype, user_is_service, targets->str, howmany);
		g_free(user_is_service);
	} else {
		GRID_INFO("pool [%s] will target [%s] %u times",
				srvtype, targets->str, howmany);
	}
	for (; howmany > 0; howmany--)
		oio_lb_world__add_pool_target(pool, targets->str);

	g_string_free(targets, TRUE);
	return pool;
}

struct oio_lb_pool_s *
oio_lb_pool__from_storage_policy(struct oio_lb_world_s *lbw,
		const struct storage_policy_s *stgpol)
{
	const char *pool_name = storage_policy_get_service_pool(stgpol);

	/* Build a pool for the storage policy */
	struct oio_lb_pool_s *pool = oio_lb_world__create_pool(lbw, pool_name);

	/* Add the list of slots as target for the pool */
	gint64 howmany = storage_policy_get_nb_chunks(stgpol);
	GRID_DEBUG("pool [%s] will target [%s] %"G_GINT64_FORMAT" times",
			pool_name, NAME_SRVTYPE_RAWX, howmany);
	for (; howmany > 0; howmany--)
		oio_lb_world__add_pool_target(pool, NAME_SRVTYPE_RAWX);

	return pool;
}
