#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.services_task_push"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>
#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./fs.h"
#include "./io_scheduler.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

#define TASK_ID "services_task_push"


struct session_data_s
{
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar task_id[sizeof(TASK_ID) + 1 + LIMIT_LENGTH_NSNAME];
};

static void
asn1_cleaner(gpointer p)
{
	TRACE_POSITION();
	if (!p)
		return;
	task_done(((struct session_data_s*)p)->task_id);
	memset(p, 0x00, sizeof(struct session_data_s));
	g_free(p);
}

static int
asn1_final_handler(worker_t * worker, GError ** error)
{
	struct session_data_s *sdata;

	(void)error;
	TRACE_POSITION();
	sdata = asn1_worker_get_session_data(worker);
	if (sdata) {
		DEBUG("[task_id=%s] Request successful", sdata->task_id);
		task_done(sdata->task_id);
	}
	return 1;
}

static int
asn1_error_handler(worker_t * worker, GError ** error)
{
	struct session_data_s *sdata;

	TRACE_POSITION();
	sdata = asn1_worker_get_session_data(worker);
	if (sdata) {
		GSETERROR(error, "[task_id=%s] Request failed ", sdata->task_id);
		task_done(sdata->task_id);
	}
	else
		GSETERROR(error, "[task_id="TASK_ID".?] task improperly initiated");
	return 0;
}

static int
task_worker(gpointer p, GError ** error)
{
	GSList *services, *list;
	GByteArray *gba_body;
	struct session_data_s sdata;
	struct namespace_data_s *ns_data;
	worker_t *asn1_worker;

	TRACE_POSITION();

	/*prepare a session and a worker for the ASN.1 request */
	bzero(sdata.ns, sizeof(sdata.ns));
	g_strlcpy(sdata.ns, (gchar*)p, sizeof(sdata.ns)-1);

	bzero(sdata.task_id, sizeof(sdata.task_id));
	g_snprintf(sdata.task_id, sizeof(sdata.task_id), TASK_ID".%s", (gchar*)p);

	ns_data = get_namespace((gchar*)p, error);
	if (!ns_data) {
		GSETERROR(error,"Namespace '%s' not managed", (gchar*)p);
		return 0;
	}

	/*build the request body */
	services = namespace_get_services(ns_data);
	if (!services) {
		DEBUG("No service to forward");
		task_done(sdata.task_id);
		return 1;
	}

	gba_body = service_info_marshall_gba(services, error);
	if (!gba_body) {
		GSETERROR(error, "[ns=%s] services serialization failure", ns_data->name);
		g_slist_free(services);
		return 0;
	}

	asn1_worker = NULL;

	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_PUSH_SRV);
	asn1_worker_set_handlers(asn1_worker, agent_asn1_default_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker, g_memdup(&sdata,sizeof(sdata)), asn1_cleaner);
	asn1_worker_set_request_body(asn1_worker, gba_body);
	g_byte_array_free(gba_body, FALSE);

	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker, TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		g_slist_free(services);
		return 0;
	}

	/* Remove first lauched flag from all services */
	for (list = services; list; list = list->next) {
		struct service_info_s *si = (struct service_info_s*)list->data;
		service_info_remove_tag(si->tags, NAME_TAGNAME_RAWX_FIRST);
	}

	DEBUG("%d services sent to conscience", g_slist_length(services));

	g_slist_free(services);
 
	return 1;
}

NAMESPACE_TASK_CREATOR(task_starter,TASK_ID, task_worker, period_push_srvlist);

int
services_task_push(GError ** error)
{
	TRACE_POSITION();

	task_t *task = create_task(1, TASK_ID);
	task->task_handler = task_starter;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add vol_stat_send task to scheduler");
		g_free(task);
		return 0;
	}

	INFO("Task started: %s", TASK_ID);
	return 1;
}

