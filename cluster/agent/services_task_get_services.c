#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "agent.services.task_types"
#endif

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metacomm.h>
#include <cluster/conscience/conscience.h>
#include <cluster/conscience/conscience_srvtype.h>
#include <cluster/module/module.h>

#include "./asn1_request_worker.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

#define TASK_ID "services_task_get_services"

struct session_data_s {
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_SRVTYPE+1+LIMIT_LENGTH_NSNAME+1];
	GSList *services;
};

static int
parse_srv_list( worker_t *worker, GError **error )
{
	asn1_session_t *asn1_session = NULL;
	struct session_data_s *sdata;

        TRACE_POSITION();

	asn1_session = asn1_worker_get_session(worker);
        sdata = asn1_worker_get_session_data(worker);

	if (asn1_session->resp_body != NULL) {
		GSList *services = NULL;
		if (service_info_unmarshall(&services, asn1_session->resp_body, &(asn1_session->resp_body_size), error) <= 0) {
			GSETERROR(error, "[task_id=%s] Failed to unmarshall service_info list", sdata->task_id);
			return 0;
		} else {
			DEBUG("[task_id=%s] Received %d services", sdata->task_id, g_slist_length( services ));
			sdata->services = sdata->services
				? g_slist_concat( sdata->services, services )
				: services;
		}
	}

        return(1);
}


static int
asn1_final_handler( worker_t *worker, GError **error)
{
	gint counter;
	GSList *l;
	struct session_data_s *sdata;
	GHashTableIter iterator;
	gpointer k, v;
	namespace_data_t *ns_data;

	TRACE_POSITION();

	sdata = asn1_worker_get_session_data( worker );
	if (!sdata) {
		GSETERROR(error,"Invalid worker");
		return 0;
	}
	
	task_done(sdata->task_id);

	if (sdata->services)
		DEBUG("[task_id=%s] Saving the %d services received from the conscience", sdata->task_id, g_slist_length(sdata->services));
	else
		INFO("[task_id=%s] No service received, forgetting all currently saved", sdata->task_id );

	ns_data = get_namespace( sdata->ns, error);
	if (!ns_data) {
		GSETERROR(error,"Namespace %s disappeared", sdata->ns);
		return 0;
	}
	
	/*cleans the old lists*/
	g_hash_table_iter_init(&iterator,ns_data->conscience->srvtypes);
	while (g_hash_table_iter_next(&iterator,&k,&v))
		conscience_srvtype_flush(v);

	/*sets the new list*/
	counter = 0;
	for (l=sdata->services; l ;l=g_slist_next(l)) {
		gchar str_addr[128];
		GError *error_local=NULL;
		struct service_info_s *si;
		struct conscience_srvtype_s *srvtype;

		if (!l->data)
			continue;
		si = l->data;
		addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
		
		srvtype = conscience_get_srvtype( ns_data->conscience, &error_local, si->type, MODE_STRICT );
		if (!srvtype) {
			ERROR("[task_id=%s] Orphan service : service type [%s] not found : %s", sdata->task_id,
				si->type, gerror_get_message(error_local));
			if (error_local)
				g_clear_error(&error_local);
			continue;
		}
		
		if (conscience_srvtype_refresh( srvtype, &error_local, si, TRUE )) {
			DEBUG("[task_id=%s] service refreshed [%s/%s/%s]", sdata->task_id, sdata->ns, si->type, str_addr);
			counter++;
		}
		else
			WARN("[task_id=%s] Failed to refresh service [%s/%s/%s]", sdata->task_id, sdata->ns, si->type, str_addr);
	}

	DEBUG("[task_id=%s] Task terminated, %d services refreshed/registered", sdata->task_id, counter);
	return 1;
}

static int
asn1_error_handler( worker_t *worker, GError **error )
{
	struct session_data_s *sdata;
	TRACE_POSITION();
	sdata = asn1_worker_get_session_data( worker );
	if (sdata) {
		GSETERROR(error, "[task_id=%s] services request failed", sdata->task_id);
		task_done(sdata->task_id);
	}
	else
		GSETERROR(error,"[task_id=%s.?] services request failed", TASK_ID);
        return(0);
}

static void
sdata_cleaner( struct session_data_s *sdata )
{
	TRACE_POSITION();
	if (!sdata)
		return;
	task_done(sdata->task_id);
	if (sdata->services) {
		g_slist_foreach( sdata->services, service_info_gclean, NULL);
		g_slist_free(sdata->services);
		sdata->services = NULL;
	}
	memset(sdata,0x00,sizeof(struct session_data_s));
	g_free(sdata);
}

static int
task_worker(gpointer p, GError **error)
{
	GByteArray *gba_types;
	GSList *list_types, *l;
	struct session_data_s *sdata;
        worker_t *asn1_worker;
	struct namespace_data_s *ns_data;
	
	TRACE_POSITION();
	sdata=NULL;
	asn1_worker=NULL;

	ns_data = get_namespace((gchar*)p, error);
	if (!ns_data) {
		GSETERROR(error,"Namespace [%s] not (yet) managed", (gchar*)p);
		return 0;
	}

	list_types = conscience_get_srvtype_names(ns_data->conscience, error);
	if (!list_types) {
		GSETERROR(error,"No service type found in namespace [%s]", conscience_get_namespace(ns_data->conscience));
		return 0;
	}
	else {
		gchar *s;

		s = list_types->data;
		gba_types = g_byte_array_append(g_byte_array_new(), (guint8*)s, strlen(s));
		for (l=list_types->next; l ;l=l->next) {
			s = l->data;
			if (s) {
				g_byte_array_append(gba_types, (guint8*)",", 1);
				g_byte_array_append(gba_types, (guint8*)s, strlen(s));
			}
		}
		g_slist_foreach(list_types, g_free1, NULL);
		g_slist_free(list_types);
	}
		
	/*prepare the worker*/
	sdata = g_try_malloc0(sizeof(struct session_data_s));
	g_strlcpy(sdata->ns, ns_data->name, sizeof(sdata->ns)-1);
	g_snprintf(sdata->task_id,sizeof(sdata->task_id),"%s.%s", TASK_ID, ns_data->name);

	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_GET_SRV);
	asn1_worker_set_handlers(asn1_worker,parse_srv_list,asn1_error_handler,asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker, sdata, (GDestroyNotify)sdata_cleaner);
	g_hash_table_insert(asn1_worker_get_session(asn1_worker)->req_headers, g_strdup("TYPENAME"), gba_types);

	/*create the worker*/
	if (!asn1_request_worker(asn1_worker, error)) {
		GSETERROR(error, "[task_id=%s] Failed to send asn1 request", sdata->task_id);
		g_free(sdata);
		free_asn1_worker(asn1_worker,TRUE);
		return 0;
	}

	DEBUG("[task_id=%s] worker started", sdata->task_id);
        return 1;
}

/* ------------------------------------------------------------------------- */

NAMESPACE_TASK_CREATOR(task_starter, TASK_ID, task_worker, period_get_srvlist);

int
services_task_get_services(GError **error)
{
	TRACE_POSITION();

	task_t *task = create_task(2, TASK_ID);
	task->task_handler = task_starter;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add srv_list_get task to scheduler");
		g_free(task);
		return 0;
	}

	INFO("Task started: %s", __FUNCTION__);
	return 1;
}

