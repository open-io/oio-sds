#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.scanner_thread"
#endif

#include <metautils/lib/metautils.h>

#include "check.h"
#include "scanner_thread.h"
#include "../lib/service_cache.h"

static GHashTable *callback_registry = NULL;
static gboolean init = FALSE;

/**
 * struct to store temp data
 */
struct worker_data_s
{
	struct pooled_service_s *service;
	struct volume_scanning_info_s *scanning_info;
};

/**
 * Allocate a volume_scanning_info_s and its volume_path field
 */
static struct volume_scanning_info_s *
_alloc_scanning_info()
{
	struct volume_scanning_info_s *scanning_info = NULL;

	scanning_info = g_new0(struct volume_scanning_info_s, 1);	/* Freed in _thread_worker() */

	scanning_info->volume_path = g_malloc0(LIMIT_LENGTH_VOLUMENAME);	/* Freed in _thread_worker() */

	return scanning_info;
}

/**
 * Push new services and not in_pool services in thread pool
 *
 * @param pool the scanner thread pool
 * @param config the integrity_loop config
 * @param list_service the updated list of local services
 */
static void
_push_services_in_pool(GThreadPool * pool, struct integrity_loop_config_s *config, GSList * list_service)
{
	GError *error;
	GSList *l1 = NULL, *l2 = NULL;
	struct pooled_service_s *service = NULL;

	for (l1 = list_service; l1 && l1->data; l1 = l1->next) {
		service = (struct pooled_service_s *) l1->data;

		if (!service->in_pool) {

			struct scanner_s *scanner = NULL;

			scanner = g_hash_table_lookup(callback_registry, service->service_info->type);
			if (scanner == NULL) {
				WARN("No scanner found for service type [%s]", service->service_info->type);
				continue;
			}

			for (l2 = scanner->workers; l2 && l2->data; l2 = l2->next) {
				struct scan_worker_s *worker = (struct scan_worker_s *) l2->data;
				struct volume_scanning_info_s *scanning_info = NULL;
				struct worker_data_s *worker_data = NULL;

				scanning_info = _alloc_scanning_info();

				if (!worker->scanning_info_filler(scanning_info, service->service_info, config, &error)) {
					ERROR("Failed to fill scanning_info : %s", error->message);
					continue;
				}

				DEBUG("Pushing new scanning of volume [%s] to thread pool", scanning_info->volume_path);

				service->in_pool = TRUE;

				worker_data = g_new0(struct worker_data_s, 1);	/* Freed in _thread_worker() */

				worker_data->scanning_info = scanning_info;
				worker_data->service = service;
				g_thread_pool_push(pool, worker_data, NULL);
			}
		}
	}
}

/**
 * The thread pool executor
 *
 * @param data a worker_data_s pointer
 * @param user_data unused
 *
 */
static void
_thread_worker(gpointer data, gpointer user_data)
{
	(void) user_data;
	struct worker_data_s *worker_data = NULL;

	if (data == NULL)
		return;
	else
		worker_data = data;

	/* Execute scanning */
	scan_volume(worker_data->scanning_info);

	/* Tag service as out of pool (should be pooled again) */
	worker_data->service->in_pool = FALSE;

	/* Free scanning_info */
	g_free(worker_data->scanning_info->volume_path);
	g_free(worker_data->scanning_info);

	/* Free worker data */
	g_free(worker_data);
}

/**
 * The scanner thread function
 *
 * @param data the integrity_loop config
 */
static gpointer
_scanner_thread_func(gpointer data)
{
	GError *error = NULL;
	GThreadPool *pool = NULL;
	struct integrity_loop_config_s *config = NULL;
	struct service_cache_s service_cache;

	TRACE("Starting chunk_crawler thread");

	if (data == NULL) {
		GSETERROR(&error, "Argument data is NULL");
		return error;
	}

	config = data;

	pool = g_thread_pool_new(_thread_worker, config, config->nb_volume_scanner_thread, FALSE, NULL);

	memset(&service_cache, 0, sizeof(struct service_cache_s));
	service_cache.service_type = NULL;

	while (1) {
		if (config->nb_volume_scanner_thread > g_thread_pool_get_num_threads(pool)) {

			if (!update_service_cache(&service_cache, &error)) {
				ERROR("Failed to update service list from agent : %s", error->message);
				g_clear_error(&error);
				error = NULL;
				continue;
			}

			/* TODO */
			/* foreach broken_events get by event puller, add into broken_events_queue */
			
			_push_services_in_pool(pool, config, service_cache.service_list);
		}

		sleep(10);
	}
}

void
init_scanning_thread()
{
	struct scanner_s scanner;

	if (init)
		return;

	/* Alloc registry */
	callback_registry = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	/* Add RAWX service type */
	memset(&scanner, 0, sizeof(struct scanner_s));
	scanner.matching_glob =
	    g_strdup_printf("%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s\
%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s\
%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s",
	    "[0-9a-zA-Z]");
	g_hash_table_insert(callback_registry, g_strdup(NAME_SRVTYPE_RAWX), g_memdup(&scanner,
		sizeof(struct scanner_s)));

	init = TRUE;
}


gboolean
register_scanning_callback(const gchar * service_type, struct scan_worker_s *worker, GError ** error)
{
	struct scanner_s *scanner = NULL;

	CHECK_ARG_POINTER(service_type, error);
	CHECK_ARG_POINTER(worker, error);

	if (!init) {
		GSETERROR(error, "Scanner thread needs to be initialized before registering new callbacks");
		return FALSE;
	}

	scanner = g_hash_table_lookup(callback_registry, service_type);
	if (scanner == NULL) {
		GSETERROR(error, "No scanner found for service of type [%s]", service_type);
		return FALSE;
	}

	scanner->workers = g_slist_prepend(scanner->workers, worker);

	return TRUE;
}

gboolean
start_scanner_thread(struct integrity_loop_config_s * config, GError ** error)
{
	if (!init) {
		GSETERROR(error, "Scanner thread has not been initialized. Please call init_scanning_thread() before");
		return FALSE;
	}

	g_thread_create(_scanner_thread_func, config, TRUE, NULL);

	return TRUE;
}
