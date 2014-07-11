#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./broken_workers.h"
#include "./io_scheduler.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"


#define TASK_ID "broken_task_push"

struct session_data_s {
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME];
};

static int
asn1_error_handler(worker_t *worker, GError **error)
{
	struct session_data_s *sdata;
	TRACE_POSITION();
	sdata = asn1_worker_get_session_data( worker );
	if (sdata) {
		GSETERROR(error, "[task_id=%s] Request failed", sdata->task_id);
		task_done(sdata->task_id);
	}
        return 0;
}

static int
asn1_final_handler(worker_t *worker, GError **error)
{
	struct session_data_s *sdata;
	(void)error;
	TRACE_POSITION();
	sdata = asn1_worker_get_session_data( worker );
	if (sdata) {
		DEBUG("[task_id=%s] Request successful", sdata->task_id);
		task_done(sdata->task_id);
	}
        return 1;
}

static gboolean
send_list( struct namespace_data_s *ns_data, GSList *list, GError **error )
{
	struct session_data_s *sdata;
	worker_t *asn1_worker;
	GByteArray *gba;

	TRACE_POSITION();

	gba=NULL;
	sdata=NULL;
	asn1_worker=NULL;
	
	/*prepare the payload*/
	gba = meta2_maintenance_names_marshall( list, error );
	if (!gba) {
		GSETERROR(error, "Failed to marshall volume_stat list");
		return FALSE;
	}
	DEBUG("broken elements serialized (%d bytes)", gba->len);

	/* prepare the ASN.1 session data */
	sdata = g_try_malloc0(sizeof(struct session_data_s));
	g_strlcpy(sdata->ns,ns_data->name,LIMIT_LENGTH_NSNAME-1);
	g_snprintf(sdata->task_id,sizeof(sdata->task_id), TASK_ID".%s",ns_data->name);
	
	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_PUSH_BROKEN_CONT);
	asn1_worker_set_handlers(asn1_worker, agent_asn1_default_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker, sdata, g_free);
	asn1_worker_set_request_body(asn1_worker,gba);
	g_byte_array_free(gba,FALSE);

	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		return FALSE;
	}

	return TRUE;
}

static gboolean
task_action(gpointer task_param, GError **error)
{
	gchar task_id[sizeof(TASK_ID)+LIMIT_LENGTH_NSNAME+1];
	struct namespace_data_s *ns_data;
	int counter;
	GSList *l, *list_tmp;

	TRACE_POSITION();
	
	if (!task_param) {
		GSETERROR(error,"Invalid task parameter");
		return FALSE;
	}

	g_snprintf(task_id, sizeof(task_id), TASK_ID".%s", (gchar*)task_param);
	task_done(task_id);
	ns_data = get_namespace((gchar*)task_param, error);
	if (!ns_data) {
		GSETERROR(error,"Namespace [%s] not (yet) managed", (gchar*)task_param);
		return FALSE;
	}
	
	if (!ns_data->configured) {
		if (ns_data->list_broken) {
			g_slist_foreach( ns_data->list_broken, g_free1, NULL);
			g_slist_free( ns_data->list_broken );
			ns_data->list_broken = NULL;
		}
		GSETERROR(error,"Namespace not configured");
		return 0;
	}
	
	list_tmp = NULL;
	for (counter=0,l=ns_data->list_broken; l ;l=l->next) {
		if (!l->data)
			continue;
		/*transfer in the temporary list*/
		list_tmp = g_slist_prepend( list_tmp, l->data );
		l->data = NULL;
		counter++;
		if (counter>128) {
			send_list(ns_data,list_tmp,error);
			g_slist_foreach( list_tmp, g_free1, NULL );
			g_slist_free( list_tmp );
			list_tmp = NULL;
			counter = 0;
		}
	}
	
	if (list_tmp) {
		send_list(ns_data,list_tmp,error);
		g_slist_foreach( list_tmp, g_free1, NULL );
		g_slist_free( list_tmp );
	}

	g_slist_free( ns_data->list_broken );
	ns_data->list_broken = NULL;
	return TRUE;
}

NAMESPACE_TASK_CREATOR(task_worker,TASK_ID,task_action,period_push_broken);

int
agent_start_broken_task_push(GError **error)
{
	task_t *task = g_malloc0(sizeof(task_t));
	task->id = g_strdup(TASK_ID);
	task->period = 5;
	task->task_handler = task_worker;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add broken_send_task task to scheduler");
		g_free(task);
		return 0;
	}

	return(1);
}

