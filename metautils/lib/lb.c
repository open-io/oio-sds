/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
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
	GSList *items = NULL;
	GHashTable *slots = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, NULL);

	/* First pass: create items, parse slot names. */
	for (GSList *l = services; l; l = l->next) {
		struct service_info_s *srv = l->data;

		struct oio_lb_item_s *item =
			g_malloc0(sizeof(struct oio_lb_item_s) + LIMIT_LENGTH_SRVID);
		service_info_to_lb_item(srv, item);
		/* Keep a of all items, for easier garbage collection. */
		items = g_slist_prepend(items, item);

		/* Parse the service in slots described in tag.slots */
		const gchar *slot_list_str = service_info_get_tag_value(srv,
				NAME_TAGNAME_SLOTS, NULL);
		gchar *slot_name = NULL;
		if (slot_list_str) {
			gchar **tokens = g_strsplit(slot_list_str, OIO_CSV_SEP, -1);
			for (gchar **token = tokens; tokens && *token; token++) {
				/* Ensure the slot name is prefixed by the type of service */
				if (!g_str_has_prefix(*token, srv->type))
					slot_name = g_strdup_printf("%s-%s", srv->type, *token);
				else
					slot_name = g_strdup(*token);

				GSList *slot_items = g_hash_table_lookup(slots, slot_name);
				slot_items = g_slist_prepend(slot_items, item);
				g_hash_table_insert(slots, slot_name, slot_items);
			}
			g_strfreev(tokens);
		}

		/* Insert the service in the main slot
		 * (named after the type of service). */
		slot_name = g_strdup(srv->type);
		GSList *slot_items = g_hash_table_lookup(slots, slot_name);
		slot_items = g_slist_prepend(slot_items, item);
		g_hash_table_insert(slots, slot_name, slot_items);
	}

	/* Second pass: feed slots. */
	void _feed_slot(gpointer key, gpointer value, gpointer udata UNUSED) {
		gchar *slot_name = key;
		GSList *slot_items = value;

		oio_lb_world__create_slot(lbw, slot_name);
		oio_lb_world__feed_slot_with_list(lbw, slot_name, slot_items);
		/* Items may be in several lists. Just clean the list structure,
		 * and clear the items later. */
		g_slist_free(slot_items);
	}
	g_hash_table_foreach(slots, _feed_slot, NULL);

	g_slist_free_full(items, g_free);
	g_hash_table_destroy(slots);
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
				GString *opts = oio_lb_world__dump_pool_options(pool);
				GRID_INFO("No service pool [%s] for storage policy [%s], "
						"creating it with %s", pool_name, polname, opts->str);
				g_string_free(opts, TRUE);
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
		memcpy(str_def, (const char*)def->data, def->len);
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
	g_string_append(targets, srvtype);

	guint howmany = service_howmany_replicas(pols, srvtype);
	GRID_INFO("pool [%s] will target [%s] %u times", srvtype, targets->str, howmany);
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

	/* Set minimum distance requirement */
	gchar min_dist[16] = {0};
	g_snprintf(min_dist, sizeof(min_dist), "%"G_GINT64_FORMAT,
			storage_policy_get_distance(stgpol));
	oio_lb_world__set_pool_option(pool, OIO_LB_OPT_MIN_DIST, min_dist);

	/* Set warning distance parameter */
	gchar warn_dist[16] = {0};
	g_snprintf(warn_dist, sizeof(warn_dist), "%"G_GINT64_FORMAT,
			storage_policy_get_warn_dist(stgpol));
	oio_lb_world__set_pool_option(pool, OIO_LB_OPT_WARN_DIST, warn_dist);

	return pool;
}
