#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.namespace_get_task_worker"
#endif

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

#define TASK_ID "namespace_get_task"

static void
session_data_cleaner(gpointer p)
{
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME+1];
	if (!p)
		return;
	g_snprintf(task_id, sizeof(task_id), TASK_ID".%s", (gchar*)p);
	task_done(task_id);
	g_free(p);
}

static int
final_handler(worker_t *worker, GError **error)
{
	gchar *ns_name;
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME+1];
	
	(void)error;
	TRACE_POSITION();
	ns_name = asn1_worker_get_session_data(worker);
	g_snprintf(task_id, sizeof(task_id), TASK_ID".%s", ns_name);
	task_done(task_id);
	return 1;
}

static int
error_handler(worker_t *worker, GError **error)
{
	gchar *ns_name;
	gchar task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME+1];

	TRACE_POSITION();

	ns_name = asn1_worker_get_session_data(worker);
	if (ns_name)
		GSETERROR(error, "[task_id=%s.%s] Failed to request namespace info", TASK_ID, ns_name);
	else
		GSETERROR(error, "[task_id=%s.?] Failed to request namespace info", TASK_ID);
	
	g_snprintf(task_id, sizeof(task_id), TASK_ID".%s", ns_name);
	task_done(task_id);
        return(1);
}


static int
parse_namespace_info(worker_t *worker, GError **error)
{
	gchar *ns_name;
	asn1_session_t *asn1_session;
	namespace_data_t *ns_data;
	namespace_info_t *ns_info = NULL;

	TRACE_POSITION();

	asn1_session = asn1_worker_get_session(worker);
	ns_name = asn1_worker_get_session_data(worker);
	if (!ns_name || !asn1_session) {
		GSETERROR(error,"Invalid worker : no session data");
		return 0;
	}
	ns_data = g_hash_table_lookup(namespaces,ns_name);
	if (!ns_data) {
		GSETERROR(error,"Namespace '%s' does not exist", ns_name);
		return 0;
	}

	if (asn1_session->resp_body != NULL) {
		ns_info = namespace_info_unmarshall(asn1_session->resp_body, asn1_session->resp_body_size, error);
		if (ns_info == NULL) {
			GSETERROR(error, "Failed to unmarshall namespace_info from ASN1 data");
			return 0;
		}

		memcpy(&(ns_info->addr), &(ns_data->ns_info.addr), sizeof(addr_info_t));
		
		/* Check that we have the same name */
		if (strcmp(ns_info->name, ns_data->name)) {
			ERROR("Namespace name [%s] in /etc/gridstorage does not match name [%s] in conscience !",
				ns_data->name, ns_info->name);
			namespace_info_free(ns_info);
			return(0);
		}

		DEBUG("Infos of namespace [%s] updated with value name [%s] / chunk_size[%"G_GINT64_FORMAT"]",
			ns_data->ns_info.name, ns_info->name, ns_info->chunk_size);

		namespace_info_clear(&(ns_data->ns_info));

		if (!namespace_info_copy(ns_info, &(ns_data->ns_info), error)) {
			GSETERROR(error, "Failed to copy namespace_info");
			namespace_info_free(ns_info);
			return 0;
		}

		namespace_info_free(ns_info);

		/* Flag namespace if it's the first config */
		ns_data->configured = TRUE;
        }

	return(1);
}

static gboolean
task_worker(gpointer p, GError **error)
{
        worker_t *asn1_worker;
	struct namespace_data_s *ns_data;

	ns_data = g_hash_table_lookup(namespaces, (gchar*)p);
	if (!ns_data) {
		GSETERROR(error,"Namespace '%s' not found", (gchar*)p);
		return FALSE;
	}

	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_GET_NSINFO);
	asn1_worker_set_session_data(asn1_worker, g_strdup(ns_data->name), session_data_cleaner);
	asn1_worker_set_request_header(asn1_worker, "VERSION", SHORT_API_VERSION);
	asn1_worker_set_handlers(asn1_worker,parse_namespace_info,error_handler,final_handler);

	error = NULL;
        if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
               	GSETERROR(error,"Failed to send asn1 request");
		return FALSE;
        }

        return TRUE;
}

static gboolean
task_starter(gpointer udata, GError **error)
{
	gpointer ns_k, ns_v;
	GHashTableIter ns_iterator;

	task_t *task;
	gchar ns_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME+1];
	namespace_data_t *ns_data;

	TRACE_POSITION();
	(void)udata;
	g_hash_table_iter_init(&ns_iterator, namespaces);
	while (g_hash_table_iter_next(&ns_iterator,&ns_k,&ns_v)) {
		ns_data = ns_v;
		g_snprintf(ns_id,sizeof(ns_id),TASK_ID".%s",ns_data->name);
		if (!namespace_is_available(ns_data)) {
			if (!is_task_scheduled(ns_id)) {
				task = create_task(period_get_ns, ns_id);
				task = set_task_callbacks(task, task_worker, g_free, g_strdup(ns_data->name));
				if (!add_task_to_schedule(task, error)) {
					ERROR("[task_id="TASK_ID"] Failed to start a sub worker for namespace '%s'", (gchar*)ns_k);
					g_free(task);
				}
				else
					INFO("[task_id="TASK_ID"] subtask started [%s]", ns_id);
			}
		}
	}
	task_done(TASK_ID);
	return 1;
}

int
start_namespace_get_task(GError **error)
{
	task_t *task = create_task(2, TASK_ID);
	task->task_handler = task_starter;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add vol_list_get task to scheduler");
		g_free(task);
		return 0;
	}

	return 1;
}

/* ------------------------------------------------------------------------- */

namespace_data_t*
get_namespace(const char *ns_name, GError **error)
{
	namespace_data_t *ns_data = NULL;
	const char *vns = strchr(ns_name, '.');
	if (vns != NULL)
		ns_name = g_strndup(ns_name, vns - ns_name);

	/* Get namespace data */
	ns_data = g_hash_table_lookup(namespaces, ns_name);
	if (ns_data == NULL) {
		GSETERROR(error, "Namespace [%s] unknown in config", ns_name);
		goto end_label;
	}

	if (!ns_data->configured) {
		GSETERROR(error, "Namespace [%s] unavailable", ns_name);
		ns_data = NULL;
		goto end_label;
	}

	if (!ns_data->local_services
		|| !ns_data->down_services
		|| !ns_data->conscience)
	{
		GSETERROR(error,"Namespace [%s] misconfigured", ns_name);
		ns_data = NULL;
	}

end_label:
	if (vns != NULL)
		g_free((gpointer)ns_name);
	return ns_data;
}

GSList*
namespace_get_services(struct namespace_data_s *ns_data)
{
	GSList *result;
	GHashTableIter iter;
	gpointer k, v;
	
	if (!ns_data)
		return NULL;
	
	result = NULL;

	g_hash_table_iter_init(&iter,ns_data->local_services);
	while (g_hash_table_iter_next(&iter,&k,&v))
		result = g_slist_prepend( result, v );

	g_hash_table_iter_init(&iter,ns_data->down_services);
	while (g_hash_table_iter_next(&iter,&k,&v))
		result = g_slist_prepend( result, v );

	return result;
}


gboolean
namespace_is_available(const struct namespace_data_s *ns_data)
{
	return ns_data && ns_data->configured;
}

/* ------------------------------------------------------------------------- */

#define TASK_PREFIX "nsinfo.indirect"

static gboolean
worker_ns_indirect_config(gpointer udata, GError **error)
{
	gchar task_id[sizeof(TASK_PREFIX)+1+LIMIT_LENGTH_NSNAME+1];
	gboolean rc = FALSE;
	namespace_data_t *ns_data;
	namespace_info_t *ns_info;
	const gchar *ns_name = udata;

	TRACE_POSITION();
	g_snprintf(task_id, sizeof(task_id), "%s.%s", TASK_PREFIX, ns_name);

	if (!IS_FORKED_AGENT) {
		GSETERROR(error, "CODE ERROR: a secondary task cannot be started within the main agent");
		goto label_end;
	}

	if (!(ns_data = g_hash_table_lookup(namespaces, ns_name))) {
		GSETERROR(error, "NS[%s] unknown", ns_name);
		goto label_end;
	}

	if (!(ns_info = get_namespace_info(ns_name, error))) {
		GSETERROR(error, "Cannot the NsInfo from the gridagent");
		goto label_end;
	}

	namespace_info_clear(&(ns_data->ns_info));
	if (!namespace_info_copy(ns_info, &(ns_data->ns_info), error)) {
		GSETERROR(error, "Cannot copy the NsInfo from the gridagent (1)");
		goto label_free;
	}

	namespace_info_clear(&(ns_data->conscience->ns_info));
	if (!namespace_info_copy(ns_info, &(ns_data->conscience->ns_info), error)) {
		GSETERROR(error, "Cannot copy the NsInfo from the gridagent (2)");
		goto label_free;
	}

	ns_data->configured = TRUE;
	rc = TRUE;
	DEBUG("NS[%s] reconfigured from the gridagent", ns_name);
label_free:
	namespace_info_clear(ns_info);
	namespace_info_free(ns_info);
label_end:
	task_done(task_id);
	return rc;
}

int
agent_start_indirect_ns_config(const gchar *ns_name, GError **error)
{
	gchar *task_id;
	task_t *task;

	TRACE_POSITION();

	if (!IS_FORKED_AGENT) {
		GSETERROR(error, "CODE ERROR: a secondary task cannot be started within the main agent");
		return FALSE;
	}

	task_id = g_strconcat(TASK_PREFIX, ".", ns_name, NULL);
	task = set_task_callbacks(create_task(period_get_ns, task_id),
			worker_ns_indirect_config, g_free, g_strdup(ns_name));
	g_free(task_id);

	if (!task) {
		GSETERROR(error, "Memory allocation failure");
		return 0;
	}
	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Task startup error");
		g_free(task);
		return 0;
	}

	return 1;
}

