#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.event.configure"
#endif

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/events/gridcluster_events.h>
#include <cluster/events/gridcluster_eventsremote.h>
#include <cluster/events/gridcluster_eventhandler.h>
#include <cluster/events/eventhandler_internals.h>
#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./asn1_request_worker.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./task_scheduler.h"

#define TASK_ID "event_task_configure"

static void
_prepend_implicit_rule_to_conscience(struct conscience_s *conscience, const gchar *pattern)
{
	guint i, old_length;
	struct gridcluster_eventrule_s *rule, **new_rules;
	struct gridcluster_eventaction_s action;
	
	memset(&action, 0x00, sizeof(action));
	action.type = GCEAT_ADDRESS;
	memcpy(&(action.parameter.address), &(conscience->ns_info.addr), sizeof(addr_info_t));

	rule = g_malloc0(sizeof(struct gridcluster_eventrule_s));
	rule->pattern = g_strdup(pattern);
	rule->actions = g_malloc0(2 * sizeof(struct gridcluster_eventaction_s*));
	rule->actions[0] = g_memdup(&action, sizeof(action));

	if (conscience->event_handler->ruleset) {
		guint new_size;
		old_length = g_strv_length((gchar**)conscience->event_handler->ruleset);
		new_size = (old_length+2) * sizeof(struct gridcluster_eventrule_s*);
		new_rules = g_realloc(conscience->event_handler->ruleset, new_size);
		for (i=old_length+1; i>0 ;i--)
			new_rules[i] = new_rules[i-1];
	}
	else {
		old_length = 0;
		new_rules = g_malloc0(2 * sizeof(struct gridcluster_eventrule_s*));
	}

	new_rules[0] = rule;
	conscience->event_handler->ruleset = new_rules;
}

static gboolean
agent_configure_events2(struct conscience_s *conscience, gchar *data,
		gsize data_size, GError **error)
{
	gboolean rc;
	const gchar *ns_name;

	ns_name = conscience->ns_info.name;

	if (!conscience->event_handler) {
		conscience->event_handler = gridcluster_eventhandler_create(ns_name, error, NULL, NULL);
		if (!conscience->event_handler) {
			GSETERROR(error, "Memory allocation failure");
			return FALSE;
		}
	}

	if (!data) {
		GSETERROR(error, "NULL configuration");
		return FALSE;
	}

	rc = gridcluster_eventhandler_configure(conscience->event_handler, data, data_size, error);
	if (rc) {
		_prepend_implicit_rule_to_conscience(conscience, "broken.*");
		return TRUE;
	}

	GSETERROR(error,"Configuration parsing error");
	return FALSE;
}

static gboolean
agent_configure_events(struct conscience_s *conscience, GError **error)
{
	gboolean rc;
	const gchar *ns_name;
	GByteArray *gba;

	ns_name = conscience->ns_info.name;

	if (!(gba = event_get_configuration(ns_name, error))) {
		GSETERROR(error, "Gridagent error");
		return FALSE;
	}

	while (gba->len) {
		guint8 c = gba->data[gba->len-1];
		if (!c || c == '\n' || c == '\r' || g_ascii_isspace(c))
			g_byte_array_set_size(gba, gba->len-1);
		else
			break;
	}
	g_byte_array_append(gba, (guint8*)"", 1);

	rc = agent_configure_events2(conscience, (gchar*)gba->data, gba->len-1, error);
	g_byte_array_free(gba, TRUE);
	if (!rc)
		GSETERROR(error, "Configuration error");
	return rc;
}

/* ------------------------------------------------------------------------- */

struct session_data_s {
	gchar  ns[LIMIT_LENGTH_NSNAME];
	gchar  task_id[sizeof(TASK_ID)+1+LIMIT_LENGTH_NSNAME+1+LIMIT_LENGTH_SRVTYPE];
	gchar *configuration_text;
	gsize  configuration_text_size;
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
		GSETERROR(error,"Namespace %s disappeared", sdata->ns);
		return 0;
	}
	if (!ns_data->configured) {
		GSETERROR(error,"Namespace %s not configured (corruption?)", sdata->ns);
		return 0;
	}

	if (sdata->configuration_text) {
		g_free(sdata->configuration_text);
		sdata->configuration_text = NULL;
		sdata->configuration_text_size = 0;
	}

	/*now manage the body*/
	if (asn1_session->resp_body != NULL) {
		sdata->configuration_text = g_strndup(asn1_session->resp_body, asn1_session->resp_body_size);
		if (sdata->configuration_text)
			sdata->configuration_text_size = strlen(sdata->configuration_text);
	}
	else {
		DEBUG("Empty reply received from the conscience of NS=%s", sdata->ns);
		sdata->configuration_text = g_strdup("");
		sdata->configuration_text_size = 0;
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
		GSETERROR(error, "Request failed NS=%s", sdata->ns);
		task_done(sdata->task_id);
	}
        return 0;
}

static int
asn1_final_handler(worker_t *worker, GError **error)
{
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
		GSETERROR(error,"Namespace %s disappeared", sdata->ns);
		return 0;
	}
	if (!ns_data->configured || !ns_data->conscience) {
		GSETERROR(error,"Namespace %s configuration disappeared (corruption?)", sdata->ns);
		return 0;
	}
	
	if (!agent_configure_events2(ns_data->conscience, sdata->configuration_text, sdata->configuration_text_size, error)) {
		GSETERROR(error,"Configuration parsing error for NS=%s", sdata->ns);
		return 0;
	}

	DEBUG("[task_id=%s] Request successful", sdata->task_id);
	return 1;
}

static void
sdata_cleaner(struct session_data_s *sdata)
{
	TRACE_POSITION();
	
	if (!sdata)
		return;
	task_done(sdata->task_id);
	if (sdata->configuration_text)
		g_free(sdata->configuration_text);
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
	sdata = g_malloc0(sizeof(struct session_data_s));
	g_strlcpy(sdata->ns, ns_data->name, sizeof(sdata->ns)-1);
	g_snprintf(sdata->task_id, sizeof(sdata->task_id), TASK_ID".%s", ns_data->name);

	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_GET_EVENT_CONFIG);
	asn1_worker_set_handlers(asn1_worker, parse_names_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker,sdata, (GDestroyNotify)sdata_cleaner);

	if (!asn1_request_worker(asn1_worker, error)) {
		GSETERROR(error, "Failed to send asn1 request for task [%s]", sdata->task_id);
		free_asn1_worker(asn1_worker,TRUE);
		return FALSE;
	}

	DEBUG("Worker successfuly started for task [%s]", sdata->task_id);
	return TRUE;
}

NAMESPACE_TASK_CREATOR(task_starter,TASK_ID,task_worker,period_get_evtconfig);

int
agent_start_event_task_config(GError **error)
{
	task_t *task = create_task(2, TASK_ID);
	task->task_handler = task_starter;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add broken_send_task task to scheduler");
		g_free(task);
		return 0;
	}

	return(1);
}

/* ------------------------------------------------------------------------- */

int
agent_reply_event_configuration_worker(worker_t *worker, GError **error)
{
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	struct namespace_data_s *ns_data;
	request_t *req;
	GByteArray *gba_config;

	/*Find the namespace*/
	req = (request_t*) worker->data.session;
	memset(ns_name, 0x00, sizeof(ns_name));
	if (req->arg && req->arg_size>0)
		memcpy(ns_name, req->arg, MIN(req->arg_size,sizeof(ns_name)));

	ns_data = get_namespace(ns_name,error);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	/*extract the eventhandler configuration*/
	if (!ns_data->conscience->event_handler)
		return __respond(worker, 1, g_byte_array_new(), error);

	GError *e = NULL;
	gba_config = gridcluster_eventhandler_get_configuration(ns_data->conscience->event_handler, &e);
	if (!gba_config) {
		GSETERROR(&e, "Failed to extract the configuration");
		return __respond_error(worker, e, error);
	}
	
	/*reply the serialized configuration*/
	return __respond(worker, 1, gba_config, error);
}

int
agent_reply_event_managed_patterns_worker(worker_t *worker, GError **error)
{
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	struct namespace_data_s *ns_data;
	request_t *req;
	GSList *list_of_patterns;
	GByteArray *gba_config;

	/*Find the namespace*/
	req = (request_t*) worker->data.session;
	memset(ns_name, 0x00, sizeof(ns_name));
	if (req->arg && req->arg_size>0)
		memcpy(ns_name, req->arg, MIN(req->arg_size,sizeof(ns_name)));
	ns_data = get_namespace(ns_name,error);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	/*extract the eventhandler configuration*/
	if (!ns_data->conscience->event_handler)
		return __respond(worker, 1, g_byte_array_new(), error);

	list_of_patterns = gridcluster_eventhandler_get_patterns(ns_data->conscience->event_handler, NULL);
	gba_config = strings_marshall_gba(list_of_patterns, error);
	g_slist_foreach(list_of_patterns, g_free2, NULL);
	g_slist_free(list_of_patterns);

	if (!gba_config) {
		GSETERROR(error,"Failed to serialize the eventhandler patterns for ns='%s'", ns_name);
		return 0;
	}

	return __respond(worker, 1, gba_config, error);
}

/* Indirect configuration -------------------------------------------------- */

#define TASK_PREFIX "event.indirect"

static gboolean
worker_event_indirect_config(gpointer udata, GError **error)
{
	gchar task_id[sizeof(TASK_PREFIX)+1+LIMIT_LENGTH_NSNAME+1];
	gboolean rc = FALSE;
	namespace_data_t *ns_data;
	const gchar *ns_name = udata;

	TRACE_POSITION();
	g_snprintf(task_id, sizeof(task_id), "%s.%s", TASK_PREFIX, ns_name);

	if (!IS_FORKED_AGENT) {
		GSETERROR(error, "CODE ERROR: a secondary task cannot be started within the main agent");
		goto label_end;
	}

	if (!(ns_data = get_namespace(ns_name, error))) {
		GSETERROR(error, "NS[%s] unknown", ns_name);
		goto label_end;
	}

	if (!agent_configure_events(ns_data->conscience, error)) {
		GSETERROR(error, "NS[%s] Cannot the configure the events from the gridagent", ns_name);
		goto label_end;
	}

	rc = TRUE;
	DEBUG("NS[%s] events reconfigured from the gridagent", ns_name);
label_end:
	task_done(task_id);
	return rc;
}

int
agent_start_indirect_event_config(const gchar *ns_name, GError **error)
{
	gchar *task_id;
	task_t *task;

	TRACE_POSITION();

	if (!IS_FORKED_AGENT) {
		GSETERROR(error, "CODE ERROR: a secondary task cannot be started within the main agent");
		return FALSE;
	}

	task_id = g_strconcat(TASK_PREFIX, ".", ns_name, NULL);
	task = set_task_callbacks(create_task(period_get_evtconfig, task_id),
			worker_event_indirect_config, g_free, g_strdup(ns_name));
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

