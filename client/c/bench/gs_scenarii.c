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

#include <glib.h>

#include "gs_bench.h"

static GSList *scenarii_needing_namespace = NULL;
static GSList *scenarii_needing_container_generator = NULL;
static GSList *scenarii_needing_content_generator = NULL;
static GSList *scenarii_multithreading_supported = NULL;

void
init_scenarii(GHashTable * scenarii)
{
	g_hash_table_insert(scenarii, "create_container", create_container_scenario);
	g_hash_table_insert(scenarii, "put_content", put_content_scenario);
	g_hash_table_insert(scenarii, "link_service", set_service_scenario);
	g_hash_table_insert(scenarii, "list_service", get_service_scenario);
	g_hash_table_insert(scenarii, "delete_all", delete_all_scenario);
	g_hash_table_insert(scenarii, "get_all", get_all_scenario);
	g_hash_table_insert(scenarii, "m2v2_db_convert", m2v2_db_convert);

	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "create_container");
	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "put_content");
	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "link_service");
	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "list_service");
	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "delete_all");
	scenarii_needing_namespace = g_slist_prepend(scenarii_needing_namespace, "get_all");

	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "create_container");
	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "list_service");
	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "link_service");
	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "get_all");
	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "delete_all");
	scenarii_needing_container_generator = g_slist_prepend(scenarii_needing_container_generator, "m2v2_db_convert");

	scenarii_needing_content_generator = g_slist_prepend(scenarii_needing_content_generator, "put_content");

	scenarii_multithreading_supported = g_slist_prepend(scenarii_multithreading_supported, "put_content");
	scenarii_multithreading_supported = g_slist_prepend(scenarii_multithreading_supported, "link_service");
	scenarii_multithreading_supported = g_slist_prepend(scenarii_multithreading_supported, "list_service");
	scenarii_multithreading_supported = g_slist_prepend(scenarii_multithreading_supported, "get_all");
}

void
clean_scenarii()
{
	if (scenarii_needing_namespace)
		g_slist_free(scenarii_needing_namespace);
	if (scenarii_needing_content_generator)
		g_slist_free(scenarii_needing_content_generator);
	if (scenarii_needing_container_generator)
		g_slist_free(scenarii_needing_container_generator);
	if (scenarii_multithreading_supported)
		g_slist_free(scenarii_multithreading_supported);
}

static gint
_slist_str_cmp(gconstpointer p1, gconstpointer p2)
{
	const gchar *str1 = p1;
	const gchar *str2 = p2;
	if (!(p1 && p2))
		return -1;
	return g_strcmp0(str1, str2);
}

gboolean
is_namespace_needed(const gchar *scenario)
{
	return NULL != g_slist_find_custom(scenarii_needing_namespace, scenario, _slist_str_cmp);
}

gboolean
is_container_generator_needed(const gchar *scenario)
{
	return NULL != g_slist_find_custom(scenarii_needing_container_generator, scenario, _slist_str_cmp);
}

gboolean
is_content_generator_needed(const gchar *scenario)
{
	return NULL != g_slist_find_custom(scenarii_needing_content_generator, scenario, _slist_str_cmp);
}

gboolean
is_multithreading_supported(const gchar *scenario)
{
	return NULL != g_slist_find_custom(scenarii_multithreading_supported, scenario, _slist_str_cmp);
}

