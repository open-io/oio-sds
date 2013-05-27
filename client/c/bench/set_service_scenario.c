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
#define G_LOG_DOMAIN "grid.client.bench.set_service_scenario"
#endif

#include <glib.h>

#include "gs_bench.h"
#include "../lib/grid_client.h"
#include "../../metautils/lib/metautils.h"

#define SERVICE_NAME "redis"

gboolean set_service_scenario(struct scenario_data * sdata, gchar * result_str, gint result_str_len)
{
	gchar container_name[64];
	gs_container_t * container = NULL;
	gs_service_t ** services = NULL;
	gs_error_t * error = NULL;

	g_assert(sdata);
	g_assert(result_str);

	sdata->container_generator(container_name, sizeof(container_name), sdata->callback_userdata);
	g_snprintf(result_str, result_str_len, "LINK SERVICE [%s] to container %s", SERVICE_NAME, container_name);
	container = gs_get_container(sdata->gs, container_name, 1, &error);
	if (container == NULL) {
		GRID_ERROR("Get container [%s] failed with error : %s", container_name, gs_error_get_message(error));
		gs_error_free(error);
		return FALSE;
	}

	services = gs_container_service_get_available(container, SERVICE_NAME, &error);
	if (services == NULL) {
		GRID_ERROR("Link service [%s] to container %s failed with error : %s", SERVICE_NAME, container_name, gs_error_get_message(error));
		gs_error_free(error);
		gs_container_free(container);
		return FALSE;
	}

	gs_service_free_array(services);
	gs_container_free(container);

	return TRUE;
}
