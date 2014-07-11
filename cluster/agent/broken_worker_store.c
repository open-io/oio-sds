#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <string.h>
#include <stdlib.h>

#include <metautils/lib/metacomm.h>

#include <cluster/module/module.h>
#include <cluster/conscience/conscience.h>

#include "./agent.h"
#include "./broken_workers.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

int
agent_store_erroneous_container(worker_t *worker, GError **error)
{
	GError *error_local = NULL;
	gchar ns_name[LIMIT_LENGTH_NSNAME], broken_element[2048], **tokens;
	request_t *req = NULL;
	namespace_data_t *ns_data = NULL;

	TRACE_POSITION();
	memset(ns_name, 0x00, sizeof(ns_name));
	memset(broken_element, 0x00, sizeof(broken_element));

	if (!flag_manage_broken)
		return __respond_message(worker, 0, "Broken elements not managed", error);

	/*extract the fields packed in the request's parameter*/
	req = (request_t*)worker->data.session;

	tokens = buffer_split( req->arg, req->arg_size, ":", 2);
	if (!tokens) {
		GSETERROR(&error_local, "Invalid format (0)");
		return 0;
	}
	else if (!tokens[0] || !tokens[1]) {
		g_strfreev(tokens);
		return __respond_message(worker, 0, "Invalid REQUEST format", error);
	}
	g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
	g_strlcpy(broken_element, tokens[1], sizeof(broken_element)-1);
	g_strfreev(tokens);
	tokens = NULL;

	DEBUG("[NS=%s] broken element received [%s]", ns_name, broken_element);

	/* Get an initiated namespace data */
	ns_data = get_namespace(ns_name, NULL);
	if (!ns_data || !ns_data->configured) 
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	if (!broken_holder_check_element_format( ns_data->conscience->broken_elements, broken_element))
		return __respond_message(worker, 0, "Invalid ELEMENT format", error);

	/*Element seems OK, keep it*/	
	ns_data->list_broken = g_slist_prepend(ns_data->list_broken, g_strdup(broken_element));
	return __respond_message(worker, 1, "OK", error);
}

