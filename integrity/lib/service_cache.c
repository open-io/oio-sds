#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.service_cache"
#endif

#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "check.h"
#include "service_cache.h"

/**
 * Compare a pooled service and a service_info
 *
 * @param a a pooled service (struct pooled_service_s)
 * @param b a service_info_t
 *
 * @return 0 if both service are equal, -1 otherwise
 */
static gint
compare_pooled_service(gconstpointer a, gconstpointer b)
{
	struct pooled_service_s* pooled_service = (struct pooled_service_s*)a;
	service_info_t* new_service = (service_info_t*)b;

	return service_info_equal(pooled_service->service_info, new_service) ? 0 : -1;
}

static void
pooled_service_gclean(gpointer ps, gpointer unused)
{
	(void) unused;

	if (ps == NULL)
		return;

	service_info_clean(((struct pooled_service_s*)ps)->service_info);
}

gboolean
update_service_cache(struct service_cache_s* service_cache, GError** error)
{
	GSList* list = NULL, *list_services = NULL, *list_pooled_services = NULL;

	DEBUG("Reloading service list from agent");

	CHECK_ARG_POINTER(service_cache, error);

	list_services = list_local_services(error);
	if (list_services == NULL) {
		GSETERROR(error, "Failed to list local services");
		return FALSE;
	}


	for (list = list_services; list && list->data; list = list->next) {
		service_info_t *service = (service_info_t*)list->data;

		if (service_cache->service_type == NULL || 0 == strcmp(service->type, service_cache->service_type)) {
			struct pooled_service_s* pooled_service = NULL;
			GSList* result = NULL;

			/* Check if we have already that service in list */
			result = g_slist_find_custom(service_cache->service_list, service, compare_pooled_service);
			if (result == NULL) {
				pooled_service = g_try_new0(struct pooled_service_s, 1);
				pooled_service->service_info = service;
			}
			else {
				pooled_service = (struct pooled_service_s*)result->data;
				service_cache->service_list = g_slist_remove(service_cache->service_list, pooled_service);
				service_info_clean(service);
			}

			/* Add pooled service in the new list */
			list_pooled_services = g_slist_prepend(list_pooled_services, pooled_service);
		}
		else
			service_info_clean(service);
	}

	/* Clean old lists */
	g_slist_free(list_services);
	g_slist_foreach(service_cache->service_list, pooled_service_gclean, NULL);
	g_slist_free(service_cache->service_list);

	/* Set new list */
	service_cache->service_list = list_pooled_services;

	return TRUE;
}
