/*
OpenIO SDS client
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

#include "./gs_internals.h"

static gs_container_t*
gs_container_init_from_location(gs_grid_storage_t *client,
	struct gs_container_location_s *location, gs_error_t **gserr)
{
	GError *gerr = NULL;
	gs_container_t *container = NULL;

	container = calloc(1, sizeof(struct gs_container_s));
	container->meta2_cnx = -1;
	container->opened = 0;

	l4_address_init_with_url(&(container->meta2_addr), location->m2_url[0], NULL);

	if (!oio_str_hex2bin(location->container_hexid, container->cID, sizeof(container_id_t))) {
		GSERRORCAUSE(gserr, gerr, "Invalid hexadecimal container ID");
		g_error_free(gerr);
		free(container);
		return NULL;
	}

	if (gerr)
		g_clear_error(&gerr);

	container->info.gs = client;

	if (location->container_name)
		g_strlcpy(container->info.name, location->container_name,
				sizeof(container->info.name)-1);

	if (location->container_hexid)
		g_strlcpy(container->str_cID, location->container_hexid,
				sizeof(container->str_cID)-1);

	return container;
}

gs_content_t*
gs_container_get_content_from_raw(gs_grid_storage_t *client,
		struct meta2_raw_content_s *raw, gs_error_t **gserr)
{
	gchar str_hex[STRLEN_CONTAINERID];
	struct gs_container_location_s *location;
	gs_content_t *result = NULL;

	if (!client || !raw) {
		GSERRORSET(gserr, "Invalid parameter (%p %p)", client, raw);
		return NULL;
	}

	/* Now locates the content's container */
	container_id_to_string(raw->container_id, str_hex, sizeof(str_hex));
	location = gs_locate_container_by_hexid(client, str_hex, gserr);
	if (!location) {
		GSERRORSET(gserr, "Container reference not found for CID[%s]", str_hex);
		return NULL;
	}

	/* Container found, alright ... */

	result = calloc(1, sizeof(gs_content_t));
	if (!result) {
		gs_container_location_free(location);
		GSERRORCODE(gserr, ENOMEM, "Memory allocation failure");
		return NULL;
	}

	/* Initiates the content part */
	g_strlcpy(result->info.path, raw->path, MIN(sizeof(result->info.path)-1,sizeof(raw->path)));
	result->info.size = raw->size;
	map_content_from_raw(result, raw);

	/* Initiates the container part */
	result->info.container = gs_container_init_from_location(client, location, gserr);
	if (!result->info.container) {
		gs_container_location_free(location);
		gs_content_free(result);
		GSERRORCODE(gserr, ENOMEM, "Memory allocation failure");
		return NULL;
	}

	DEBUG("Resolved container ID[%s]", location->container_hexid);
	gs_container_location_free(location);
	return result;
}

