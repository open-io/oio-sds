#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/conscience/conscience.h>

#include "module/module.h"

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./broken_workers.h"
#include "./io_scheduler.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

#define TASK_ID "broken_task_get"

struct session_data_s {
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME];
	GSList *broken_elements;
};

static int
parse_names_response_handler( worker_t *worker, GError **error )
{
	asn1_session_t *asn1_session = NULL;
	struct session_data_s *sdata;
	struct namespace_data_s *ns_data;

	TRACE_POSITION();

	asn1_session = (asn1_session_t*)worker->data.session;
	sdata = asn1_session->session_data;

	/*quickly check the namespace still exists*/
	ns_data = get_namespace(sdata->ns, NULL);
	if (!ns_data) {
		GSETERROR(error,"[task_id=%s] Namespace %s disappeared", sdata->task_id, sdata->ns);
		return 0;
	}
	if (!ns_data->configured) {
		GSETERROR(error,"[task_id=%s] Namespace %s not configured (corruption?)", sdata->task_id, sdata->ns);
		return 0;
	}

	/*now manage the body*/
	if (asn1_session->resp_body != NULL) {
		gsize body_size;
		GSList *names = NULL;

		names = NULL;
		body_size = asn1_session->resp_body_size;
		if (!strings_unmarshall(&names, asn1_session->resp_body, &body_size, error)) {
			GSETERROR(error, "[task_id=%s] Failed to unmarshall broken elements list",
				 sdata->task_id);
			return 0;
		} else {
			DEBUG("Received %d names", g_slist_length( names ));
			sdata->broken_elements = !sdata->broken_elements ? names : g_slist_concat( names, sdata->broken_elements);
		}
	}
	else {
		DEBUG("[task_id=%s] Empty reply received from the conscience", sdata->task_id);
	}

	return(1);
}

static int
asn1_error_handler(worker_t *worker, GError **error)
{
	struct session_data_s *sdata;

	TRACE_POSITION();
	sdata = asn1_worker_get_session_data( worker );
	if (sdata) {
		GSETERROR(error, "[task_id=%s] Request failed ", sdata->task_id);
		task_done(sdata->task_id);
	}
        return 0;
}

static int
asn1_final_handler(worker_t *worker, GError **error)
{
	GSList *nl;
	struct conscience_s *conscience;
	struct namespace_data_s *ns_data;
	struct session_data_s *sdata;
	
	TRACE_POSITION();
	
	sdata = asn1_worker_get_session_data( worker );
	if (!sdata) {
		GSETERROR(error,"Invalid worker");
		return 0;
	}
	task_done(sdata->task_id);
	
	/*quickly check the namespace still exists*/
	ns_data = get_namespace(sdata->ns, NULL);
	if (!ns_data) {
		GSETERROR(error,"[task_id=%s] Namespace %s disappeared", sdata->task_id, sdata->ns);
		goto error_label;
	}
	if (!ns_data->configured || !ns_data->conscience) {
		GSETERROR(error,"[task_id=%s] Namespace %s not configured (corruption?)", sdata->task_id, sdata->ns);
		goto error_label;
	}
	
	conscience = ns_data->conscience;
	broken_holder_flush( conscience->broken_elements );
	
	for (nl=sdata->broken_elements; nl ;nl=nl->next) {
		if (nl->data) {
			broken_holder_add_element(conscience->broken_elements,nl->data);
			g_free(nl->data);
			nl->data = NULL;
		}
	}
	g_slist_free(sdata->broken_elements);
	sdata->broken_elements = NULL;
	
	DEBUG("[task_id=%s] Request successful", sdata->task_id);
	return 1;
error_label:
	return 0;
}

static void
sdata_cleaner(struct session_data_s *sdata)
{
	TRACE_POSITION();
	
	if (!sdata)
		return;
	if (sdata->broken_elements) {
		g_slist_foreach(sdata->broken_elements, g_free1, NULL);
		g_slist_free(sdata->broken_elements);
	}
	task_done(sdata->task_id);
	memset(sdata,0x00,sizeof(struct session_data_s));
	g_free(sdata);
}

static gboolean
task_worker(gpointer task_param, GError **error)
{
	struct namespace_data_s *ns_data;
	struct session_data_s *sdata;
	worker_t *asn1_worker;

	TRACE_POSITION();

	if (!task_param) {
		GSETERROR(error,"Invalid task parameter");
		return FALSE;
	}
	ns_data = get_namespace((gchar*)task_param, error);
	if (!ns_data) {
		GSETERROR(error,"Namespace [%s] not (yet) managed", (gchar*)task_param);
		return FALSE;
	}
	
	sdata=NULL;
	asn1_worker=NULL;

	/* prepare the ASN.1 session data */
	sdata = g_try_malloc0(sizeof(struct session_data_s));
	g_strlcpy(sdata->ns,ns_data->name,LIMIT_LENGTH_NSNAME-1);
	g_snprintf(sdata->task_id,sizeof(sdata->task_id), TASK_ID".%s",ns_data->name);

	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_GET_BROKEN_CONT);
	asn1_worker_set_handlers(asn1_worker, parse_names_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker,sdata, (GDestroyNotify)sdata_cleaner);

	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		return FALSE;
	}

	return TRUE;
}

NAMESPACE_TASK_CREATOR(task_starter,TASK_ID,task_worker,period_get_broken);

int
agent_start_broken_task_get(GError **error)
{
	task_t *task = g_malloc0(sizeof(task_t));
	task->id = g_strdup(TASK_ID);
	task->period = 5;
	task->task_handler = task_starter;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add broken_get_task task to scheduler");
		g_free(task);
		return 0;
	}

	return(1);
}

