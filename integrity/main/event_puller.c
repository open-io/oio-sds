#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.event_puller"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include "config.h"
#include "scanner_thread.h"
#include "event_filter.h"
#include "log_event_filter.h"



/* TODO: hash map to store broken events already in run */
GHashTable* knowable_broken_events;




/**
 @file event_puller.c
 This component is responsible for pulling broken events from the local agent and passing them in the queue
 */

void
display_hash_table_content(gpointer k, gpointer v, gpointer user_data)
{
	(void) k;
	(void) user_data;
	NOTICE("item contenu dans la table->ns_name= %s",
		((const struct broken_event_s *)v)->service_info.ns_name);
}

void
free_key(gpointer key)
{
	if (!key)
		return;
	g_slist_foreach(((const struct broken_event_s *)key)->broken_elements,broken_element_gfree, NULL);
        g_free(key);
}

void
free_value(gpointer value)
{
	if (!value)
		return;
	g_free(value);
}

gboolean
notify_broken_events_processing(const struct broken_event_s* event, GError** error) {
	(void) event;
	(void) error;
	/* g_hash_table_replace(knowable_broken_events, (gpointer)event, TRUE); */
	return TRUE;
}

/**
 * Generate a broken_event with the entity sending by local agent and push it in the queue
 * @param container_id
 * @param srv_info
 * @return TRUE or FALSE if an error occured
 */
gboolean generate_and_push_broken_event(container_id_t container_id, service_info_t* srv_info){
	GError*  error;
	gchar* test_char="test";
	struct broken_event_s * broken_event = NULL;
	broken_event = g_new0(struct broken_event_s, 1);
	memcpy(&(broken_event->service_info),srv_info, sizeof(service_info_t));
	NOTICE("container id: %s",container_id);
	
	/* fill the broken_element structure */
	struct broken_element_s * broken_element;
	broken_element = broken_element_alloc(container_id, test_char, test_char, L_META2, P_CONTAINER_ID, R_MISMATCH, NULL);
	NOTICE("alloc broken element ok");
	broken_event->broken_elements = g_slist_prepend(broken_event->broken_elements, broken_element); 
	NOTICE("hash_table content: ");
	g_hash_table_foreach(knowable_broken_events, display_hash_table_content, NULL);
	NOTICE("\n");
	if (!g_hash_table_lookup(knowable_broken_events,broken_event)) {
		if (!record_broken_event(broken_event, error)) {
			GSETERROR(error, "Failed to record a broken event");
			g_free(broken_event);
			return FALSE;
		}
		else{
			NOTICE("knowable_broken_events size =%d",g_hash_table_size(knowable_broken_events));
			g_hash_table_insert(knowable_broken_events, g_memdup(broken_event,sizeof(struct broken_event_s)), FALSE);	
			NOTICE("event saved in the hash map, knowable_broken_events size = %d",g_hash_table_size(knowable_broken_events));
		}
	}
	else {
		NOTICE("broken_event already know, don't notify again");
	}	
	return TRUE;
}

void
puller_main_func(gpointer data , gpointer user_data)
{
	GError* err = NULL;
	gchar *ns_name = "local", **split, *addr;
	container_id_t *container_hash;
	service_info_t *service_info;

	(void) user_data;
	NOTICE("Starting event_puller main func");
	ERROR("erroneous element: %s\n", data );
	split = g_strsplit(data,":",10);
	addr = g_strconcat(g_strdup(split[0]),":",g_strdup(split[1]),NULL);
	container_hash = g_strdup(split[2]);

	/* fill service info */
	service_info=g_malloc0(sizeof(service_info_t));
	service_info_set_address(service_info, g_strdup(split[0]), g_strdup(split[1]),err);
	g_strlcpy(service_info->ns_name, ns_name, sizeof(service_info->ns_name)-1);
	g_strlcpy(service_info->type, NAME_SRVTYPE_META2, sizeof(service_info->type)-1);
	
	if(!generate_and_push_broken_event(container_hash, service_info)){
		ERROR("Failed to push broken event");
	}
}

/**
 Pull available items from local agent

 @param events a list of events
 @param error

 @return TRUE or FALSE if an error occured
 */
gboolean
pull_events_from_agent(GSList** events, GError** error)
{
	gchar* ns="local";
	GSList** erroneous_containers;

	knowable_broken_events=g_hash_table_new_full(g_str_hash, g_str_equal,free_key, free_value);	
	while (1) {
		erroneous_containers=fetch_erroneous_containers(ns,error);
		g_slist_foreach(erroneous_containers,puller_main_func, ns);	
		sleep(3);
	}
	return TRUE;
}


gboolean start_event_puller_thread(GError** error){
	if(!g_thread_create(pull_events_from_agent, NULL, FALSE, error)){
		NOTICE("An error occured when starting event puller thread");
		return FALSE;
	}
	return TRUE; 

}
