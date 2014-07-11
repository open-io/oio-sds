#include "./gs_internals.h"

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

