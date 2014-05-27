/**
 * - Read service list from local agent (GridCluster Api:list_local_services)
 * - Launch a RAWX checker thread for each RAWX service
 * - Launch a RAWX crawler thread for each RAWX service
 * - Launch a META2 checker thread for each META2 service 
 */

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "./event_puller.h"

#include "config.h"
#include "scanner_thread.h"
#include "chunk_crawler.h"
#include "chunk_checker.h"
#include "event_filter.h"
#include "log_event_filter.h"
#include "chunk_repair_event_filter.h"
#include "meta2_repair_event_filter.h"

/** GLOBALS */
GAsyncQueue *broken_events_queue;

int
main(int argc, char **argv)
{
	GError* error = NULL;
	struct integrity_loop_config_s* config = NULL;
	struct scan_worker_s worker;

	(void) argc;
	(void) argv;

	/* init log4c */
	log4c_init();

	/* Init thread system */
	if (!g_thread_supported())
		g_thread_init(NULL);
	else {
		ERROR("Threads unavailable in glib");
		return -1;
	}

	/* Init config */
	if (!load_config(&config, &error)) {
		ERROR("Failed to load config : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Init log_event filter */
	if (!init_log_event_filter("integrity.events", &error)) {
		ERROR("Failed to init log_event filter : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Init chunk_repair_event filter */
	if (!init_chunk_repair_event_filter(&error)) {
		ERROR("Failed to init chunk_repair_even filter : %s", error->message);
		g_clear_error(&error);
		return -1;
	}
	
	/* Init meta2_repair_event filter */
	if (!init_meta2_repair_event_filter(&error)) {
		ERROR("Failed to init meta2_repair_event filter : %s", error->message);	
		g_clear_error(&error);
		return -1;
	}

	/* Init broken events filter */
	broken_events_queue = g_async_queue_new();
	if (!start_event_filter(config, &error)) {
		ERROR("Failed to start event filter : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Init scanner thread pool */
	init_scanning_thread();
	
	/* Register chunk_crawler in scanner thread pool */
	worker.scanning_info_filler = fill_scanning_info_for_chunk_crawler;
	if (!register_scanning_callback(NAME_SRVTYPE_RAWX, g_memdup(&worker, sizeof(struct scan_worker_s)), &error)) {
		ERROR("Failed to register chunk_crawler in scanner : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Register chunk_checker in scanner thread pool */
	worker.scanning_info_filler = fill_scanning_info_for_chunk_checker;
	if (!register_scanning_callback(NAME_SRVTYPE_RAWX, g_memdup(&worker, sizeof(struct scan_worker_s)), &error)) {
		ERROR("Failed to register chunk_checker in scanner : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Start chunk crawler thread */
	if (!start_scanner_thread(config, &error)) {
		ERROR("Failed to start scanner thread : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* Start event puller thread */
	if (!start_event_puller_thread(&error)) {
		ERROR("Failed to start event puller thread : %s", error->message);
		g_clear_error(&error);
		return -1;
	}

	/* loop */
	while(1) {
		sleep(1);
	}

	/* close log4c */
	log4c_fini();

	return 0;
}
