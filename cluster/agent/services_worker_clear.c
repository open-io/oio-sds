#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif
#include <string.h>

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
		GSETERROR(error,"Request successful, failed to reply due to invalid worker");
		return 0;
	}
	return __respond_message( original_worker, 1, "OK", NULL );
}

static int
asn1_error_handler( worker_t *worker, GError **error )
{
	worker_t *original_worker;
	TRACE_POSITION();
	GSETERROR(error, "Failed to send the 'erroneous containers flush' order");
	original_worker = asn1_worker_get_session_data(worker);
	if (!original_worker) {
		GSETERROR(error,"Failed to reply due to invalid worker");
		return 0;
	}
	return __respond_error( original_worker, error?*error:NULL, NULL );
}

static gboolean
create_sub_worker( struct namespace_data_s *ns_data, const gchar *type_name, worker_t *orig_worker, GError **error )
{
	worker_t *asn1_worker;
	
	TRACE_POSITION();

	asn1_worker=NULL;	

	/*Prepare the ASN.1 session for the future worker*/
	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr), NAME_MSGNAME_CS_RM_SRV);
	asn1_worker_set_handlers(asn1_worker, agent_asn1_default_response_handler, asn1_error_handler, asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker, orig_worker, NULL);
	
	g_hash_table_insert(asn1_worker_get_session(asn1_worker)->req_headers,
		g_strdup("TYPENAME"), g_byte_array_append(g_byte_array_new(), (guint8*)type_name,
			strlen_len((guint8*)type_name, LIMIT_LENGTH_SRVTYPE)));

	/*Then create the ASN.1 worker*/
	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		return FALSE;
	}

	return TRUE;
}

/* ------------------------------------------------------------------------- */

static void
remove_local_services(struct namespace_data_s *ns_data, const gchar *type_name)
{
	(void)type_name;
	TRACE_POSITION();
	g_hash_table_remove_all(ns_data->local_services);
	g_hash_table_remove_all(ns_data->down_services);
}

int
services_worker_clear(worker_t *worker, GError **error)
{
	request_t *req = NULL;
	struct namespace_data_s *ns_data = NULL;
	char **tokens, ns_name[LIMIT_LENGTH_NSNAME+1], type_name[LIMIT_LENGTH_SRVTYPE+1];

	TRACE_POSITION();

	/*parse the request args, find the namespace*/
	req = (request_t*) worker->data.session;
	tokens = buffer_split(req->arg, req->arg_size,":",0);

	if (!tokens) {
		GSETERROR(error,"Split error");
		return 0;
	}
	if (g_strv_length(tokens) != 2) {
		g_strfreev(tokens);
		return __respond_message(worker, 0, "Invalid request's argument format (not NS:TYPE)", error);
	}
	else {
		memset(ns_name, 0, sizeof(ns_name));
		memset(type_name, 0, sizeof(type_name));
		g_strlcpy(ns_name,tokens[0],sizeof(ns_name)-1);
		g_strlcpy(type_name,tokens[1],sizeof(type_name)-1);
		g_strfreev(tokens);
	}
	
	ns_data = get_namespace(ns_name, NULL);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "Namespace invalid or not ready", NULL);

	DEBUG("Flushing the services with type %s", ns_name);

	/*free locally registered services with this type*/
	remove_local_services(ns_data,type_name);

	/* Ask a distant flush, on the conscience */
	GError *e = NULL;
	if (!create_sub_worker(ns_data, type_name, worker, &e)) {
		GSETERROR(&e,"Failed to ask a flush on the conscience");
		return __respond_error(worker, e, error);
	}

	/*free services received from the conscience with this type*/
	if (ns_data->conscience) {
		struct conscience_srvtype_s *srvtype;
		srvtype = conscience_get_srvtype( ns_data->conscience, NULL, type_name, MODE_STRICT);
		if (srvtype)
			conscience_srvtype_flush( srvtype );
	}

	request_cleanup(worker);
	worker->func = agent_worker_default_func;
	return 1;
}

