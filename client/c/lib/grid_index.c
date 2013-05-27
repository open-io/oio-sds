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

#include "./gs_internals.h"

/* ------------------------------------------------------------------------- */

gs_service_t **
gs_index_get_services_for_paths(gs_container_t * container, char **paths, gs_error_t ** err)
{
	return gs_get_services_for_paths(container, NAME_SRVTYPE_INDEX, paths, err);
}

gs_service_t *
gs_index_choose_service_for_paths(gs_container_t * container, char **paths, gs_error_t ** err)
{
	return gs_choose_service_for_paths(container, NAME_SRVTYPE_INDEX, paths, err);
}

gs_status_t
gs_index_delete_services_for_paths(gs_container_t * container, char **paths,
	char ***really_removed, gs_service_t ***services_used, gs_error_t ** err)
{
	return gs_delete_services_for_paths(container, NAME_SRVTYPE_INDEX, paths, really_removed, services_used, err);
}

char**
gs_index_validate_changes_on_paths(gs_container_t *container, char **paths, gs_error_t ** err)
{
	return gs_validate_changes_on_paths(container, NAME_SRVTYPE_INDEX, paths, err);
}

char**
gs_index_invalidate_changes_on_paths(gs_container_t *container, char **paths, gs_error_t ** err)
{
	return gs_invalidate_changes_on_paths(container, NAME_SRVTYPE_INDEX, paths, err);
}


gs_service_t**
gs_index_get_all_services_used( gs_container_t *container, gs_error_t **err)
{
	return gs_get_all_services_used(container, NAME_SRVTYPE_INDEX, err);
}

gs_service_t**
gs_index_flush(gs_container_t *container, gs_error_t **err)
{
	return gs_service_flush(container, NAME_SRVTYPE_INDEX, err);
}

