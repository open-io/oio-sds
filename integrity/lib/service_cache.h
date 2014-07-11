/**
 * @file service_cache.h
 * Handle a cache of local service list
 */

#ifndef SERVICE_CACHE_H
#define SERVICE_CACHE_H

/**
 * @defgroup integrity_loop_lib_service_cache Service cache handling
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>

/**
 * Store a pooled service
 */
struct pooled_service_s {
	gboolean in_pool;		/*!< Set to TRUE if the service is curently processed (or waiting to be) */
	service_info_t* service_info;	/*!< The service info */
};

/**
 * Store a service cache
 */
struct service_cache_s {
	gchar* service_type;	/*!< The type of service to cache. If set to NULL, all types are cached */
	GSList* service_list;	/*!< The list of cached services */
};

/**
 * Update a service_cache
 *
 * @param service_cache a struct service_cache_s
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 *
 * - Use list_local_services() to get all local services
 * - Extract from this list services with the type defined in service_cache
 * - Create a new list, holding services which are still available and removing services which have disapeared
 *
 * @test
 * - Create a fake service_cache object containing 2 services
 * - Override list_local_services() so that it returns 2 services with at least one in common with the fake service_cache
 * - Call func and check the service in service_cache which was not in the list returned by list_local_services() has been replaced
 */
gboolean update_service_cache(struct service_cache_s* service_cache, GError** error);

/** @} */

#endif	/* SERVICE_CACHE_H */
