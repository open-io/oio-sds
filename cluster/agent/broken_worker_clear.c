#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <string.h>
#include <stdlib.h>

#include <metautils/lib/metacomm.h>

#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./broken_workers.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task_scheduler.h"

static int
asn1_final_handler( worker_t *worker, GError **error )
{
	worker_t *original_worker;
	
	TRACE_POSITION();
	original_worker = asn1_worker_get_session_data(worker);
	if (!original_worker) {
		GSETERROR(error,"Request successful but reply failed due to invalid worker");
		return 0;
	}
	__respond_message( original_worker, 1, "OK", NULL );
	return 1;
}

static int
asn1_error_handler( worker_t *worker, GError **error )
{
	worker_t *original_worker;

	TRACE_POSITION();
	GSETERROR(error, "Failed to send the 'erroneous containers flush' order");
	original_worker = asn1_worker_get_session_data(worker);
	if (!original_worker) {
		GSETERROR(error,"Failed due to invalid worker");
		return 0;
	}
	__respond_error( original_worker, error?*error:NULL, NULL );
	return 1;
}

static gboolean
create_sub_worker( struct namespace_data_s *ns_data, worker_t *orig_worker, GError **error )
{
	worker_t *asn1_worker;

	TRACE_POSITION();

	/*Prepare the ASN.1 session for the future worker*/
	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_RM_BROKEN_CONT);
	asn1_worker_set_handlers(asn1_worker, agent_asn1_default_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker,orig_worker,NULL);

	/*Then create the ASN.1 worker*/
	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		return FALSE;
	}

	return TRUE;
}

/* ------------------------------------------------------------------------- */

int
agent_flush_erroneous_container(worker_t *worker, GError **error)
{
	GError *error_local = NULL;
	request_t *req = NULL;
	struct namespace_data_s *ns_data = NULL;
	char ns_name[LIMIT_LENGTH_NSNAME+1];
	gsize req_param_length;

	TRACE_POSITION();
	memset(ns_name, 0x00, sizeof(ns_name));

	/*parse the request args, find the namespace*/
	req = (request_t*) worker->data.session;
	req_param_length = req->arg ? strlen(req->arg) : 0;
	if (req_param_length<=0 || req_param_length>=LIMIT_LENGTH_NSNAME)
		return __respond_message(worker, 0, "Invalid REQUEST format", error);
	g_memmove( ns_name, req->arg, req_param_length);

	ns_data = get_namespace(ns_name, &error_local);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	DEBUG("Flushing the broken elements on [%s]", ns_name);

	/*free outgoing data*/
	if (ns_data->list_broken) {
		g_slist_foreach( ns_data->list_broken, g_free1, NULL);
		g_slist_free( ns_data->list_broken);
		ns_data->list_broken = NULL;
	}

	/* Ask a distant flush, on the conscience */
	if (!create_sub_worker(ns_data, worker, &error_local)) {
		GSETERROR(&error_local, "Failed to connect to the conscience");
		return __respond_error(worker, error_local, error);
	}

	/*free incomed data*/
	if (ns_data->conscience && ns_data->conscience->broken_elements)
		broken_holder_flush( ns_data->conscience->broken_elements );

	if (error_local)
		g_clear_error(&error_local);

	worker->func = agent_worker_default_func;
	return 1;
}

