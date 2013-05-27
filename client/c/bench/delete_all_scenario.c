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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.client.bench.delete_all_scenario"
#endif

#include <stdlib.h>
#include <glib.h>
#include <glib/gprintf.h>

#include "gs_bench.h"
#include "grid_client.h"
#include "metautils.h"

static void _delete_content(gpointer _content_name, gpointer _cdata)
{
	const t_content_data *cdata = _cdata;
	const gchar *content_name = _content_name;

	gs_content_t *content = NULL;
	gs_error_t *err = NULL;

	GTimer * timer = g_timer_new();
	GTimeVal timeval;
	guint elapsed = 0;
	gchar result_str[256];

	if (!cdata || !cdata->container)
		return;

	DEBUG("removing %s", content_name);

	content = gs_get_content_from_path (cdata->container, content_name, &err);
	if (!content) {
		ERROR("content %s not found\n", content_name);
	} else {
		g_timer_start(timer);
		if (!gs_destroy_content(content, &err))
			ERROR("content %s not deleted: %s\n", content_name, gs_error_get_message(err));
		elapsed = 1000*g_timer_elapsed(timer, NULL);
		g_get_current_time(&timeval);
		g_snprintf(result_str, sizeof(result_str), "DELETE_CONTENT %s/%s", cdata->container_name, content_name);
		g_printf("%lli,%u,%s,,,,%s,0\n", (timeval.tv_sec*1000LL)+(timeval.tv_usec/1000), elapsed, result_str,
				err == NULL ? "true" : "false");
		gs_content_free (content);
		g_timer_destroy(timer);
	}

	if (err)
		gs_error_free(err);
} 

gboolean delete_all_scenario(struct scenario_data *sdata, gchar *result_str, gint result_str_len)
{
	g_assert(sdata);
	g_assert(result_str);

	GHashTable *content_ht = _init_content_ht(sdata->gs, sdata->callback_userdata);
	if (content_ht) {
		gboolean res = _apply_callback_to_ht(content_ht, _delete_content, sdata->gs, NULL);
		g_hash_table_destroy(content_ht);
		g_snprintf(result_str, result_str_len, "DELETE_ALL");
		return res;
	}

	return FALSE;
}

