#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.event_filter"
#endif

#include <metautils/lib/metautils.h>

#include "event_filter.h"
#include "../lib/broken_event.h"
#include "config.h"
#include "scanner_thread.h"
#include "log_event_filter.h"


struct filter_exec_s {
	broken_event_filter_f func;
	void *data;
};



static GHashTable * filter_mappings = NULL;


void
_exec_filters(gpointer data, gpointer user_data)
{
	NOTICE("event_filter _exec_filter running \n");
	GError * error = NULL;
	GHashTableIter iterator;
	gpointer key, value;
	struct broken_element_s * broken_element;
	struct broken_event_filter_s * filter = NULL;
	struct filter_exec_s * filter_exec = NULL;
	struct broken_event_s * broken_event = NULL;

	broken_element = data;
	broken_event = user_data;

	g_hash_table_iter_init(&iterator, filter_mappings);
	while (g_hash_table_iter_next(&iterator, &key, &value)) {
		filter = (struct broken_event_filter_s*)key;
		filter_exec = value;
		NOTICE("Element: %s",broken_element->container_id);	
		NOTICE("broken_element->location: %d, filter->location = %d",broken_element->location , filter->location);
		NOTICE("broken_element->property: %d, filter->property = %d",broken_element->property , filter->property);
		NOTICE("broken_element->reason: %d, filter->reason = %d",broken_element->reason , filter->reason);
	
		/* really up???  */
	
		if (broken_element->location & filter->location && broken_element->property & filter->property && broken_element->reason & filter->reason) {
			NOTICE("All properties setted");
			NOTICE("filter_exec->data = %s",filter_exec->data);
				
			if (!filter_exec->func(broken_event, filter_exec->data, &error)) {
				NOTICE("miss sur le exec_func dans exec_filters");
				ERROR("Failed to execute filter action : %s", error->message);
				g_clear_error(&error);
				error = NULL;
			}
		}
		/* debug trace */
		else{
			NOTICE("Event filtered but some property missing for filter execution...");
		}
	}
}

static gpointer
_thread_func(gpointer data)
{
	struct broken_event_s* broken_event = NULL;

	(void) data;
	if (filter_mappings == NULL)
		return NULL;

	while((broken_event = g_async_queue_pop(broken_events_queue))) {
		ERROR("Received a broken_event, executing filtered actions");

		if (broken_event->broken_elements == NULL) {
			ERROR("broken_event to filter has no broken_elements");
			continue;
		}

		g_slist_foreach(broken_event->broken_elements, _exec_filters, broken_event);
	}

	return NULL;
}

gboolean start_event_filter(const struct integrity_loop_config_s * config, GError ** error)
{
	(void) error;
	(void) config;
	g_thread_create(_thread_func, NULL, TRUE, NULL);

	return TRUE;
}

gboolean record_broken_event(struct broken_event_s * broken_event, GError ** error)
{
	(void) error;
	g_async_queue_push(broken_events_queue, broken_event);

	return TRUE;
}

gboolean register_event_filter(const struct broken_event_filter_s * filter, broken_event_filter_f filter_func, void * data, GError ** error)
{
	struct filter_exec_s * filter_exec = NULL;
	(void) error;

	if (filter_mappings == NULL)
		filter_mappings = g_hash_table_new_full(g_direct_hash, g_direct_equal, g_free, NULL);

	filter_exec = g_new0(struct filter_exec_s, 1);
	filter_exec->func = filter_func;
	filter_exec->data = data;

	g_hash_table_insert(filter_mappings, g_memdup(filter, sizeof(struct broken_event_filter_s)), filter_exec);

	return TRUE;
}
