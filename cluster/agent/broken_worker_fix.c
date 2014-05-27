#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.broken"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metacomm.h>

#include <cluster/module/module.h>
#include <cluster/conscience/conscience.h>

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
		GSETERROR(error,"Failed to reply, invalid worker");
		return 0;
	}
	if (!__respond_message( original_worker, 1, "OK", error)) {
		GSETERROR(error,"Reply failure");
		return 0;
	}
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
		GSETERROR(error,"Failed to reply, invalid worker");
		return 0;
	}
	if (!__respond_error( original_worker, error?*error:NULL, NULL )) {
		GSETERROR(error,"Reply failure");
		return 0;
	}
	return 1;
}

static gboolean
create_sub_worker( struct namespace_data_s *ns_data, worker_t *orig_worker,
	gchar *broken_element, GError **error )
{
	GByteArray *gba;
	worker_t *asn1_worker;

	TRACE_POSITION();

	gba=NULL;
	asn1_worker=NULL;

	/*Prepare the ASN.1 request payload*/
	if (broken_element) {
		GSList *l = g_slist_prepend(NULL,broken_element);
		gba = meta2_maintenance_names_marshall(l, error);
		g_slist_free( l );
	}
	if (!gba) {
		GSETERROR(error,"Failed to serialize the broken element");
		return FALSE;
	}

	/*Prepare the ASN.1 session for the future worker*/
	asn1_worker = create_asn1_worker(&(ns_data->ns_info.addr),NAME_MSGNAME_CS_FIX_BROKEN_CONT);
	asn1_worker_set_handlers(asn1_worker,agent_asn1_default_response_handler,asn1_error_handler,asn1_final_handler);
	asn1_worker_set_session_data(asn1_worker,orig_worker,NULL);
	asn1_worker_set_request_body(asn1_worker,gba);
	g_byte_array_free(gba,FALSE);

	if (!asn1_request_worker(asn1_worker, error)) {
		free_asn1_worker(asn1_worker,TRUE);
		GSETERROR(error, "Failed to send asn1 request");
		return FALSE;
	}

	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gboolean
check_format(struct conscience_s *conscience, const gchar *element,
		GError **error)
{
	gboolean rc;

	TRACE_POSITION();

	errno = 0;
	rc = broken_holder_check_element_format(conscience->broken_elements, element);
	if (rc)
		return TRUE;
	switch (errno) {
		case EINVAL:
			GSETERROR(error, "Invalid argument (%p %p)", conscience->broken_elements, element);
			return FALSE;
		case EBADMSG:
			GSETERROR(error, "Element not ':'-separated");
			return FALSE;
		case EPROTO:
			GSETERROR(error, "Element has too few tokens");
			return FALSE;
		default:
			GSETERROR(error, "Unknown format error");
			return FALSE;
	}
}

int
agent_fixed_erroneous_container(worker_t *worker, GError **error)
{
	GError *error_local = NULL;
	request_t *req = NULL;
	namespace_data_t *ns_data = NULL;
	gchar **tokens=NULL, broken_element[2048], ns_name[LIMIT_LENGTH_NSNAME];

	TRACE_POSITION();
	memset(broken_element, 0x00, sizeof(broken_element));
	memset(ns_name, 0x00, sizeof(ns_name));

	if (!flag_manage_broken)
		return __respond_message(worker, 0, "Broken elements not managed", error);

	/*extract the fields packed in the request's parameter*/
	req = (request_t*)worker->data.session;
	tokens = buffer_split( req->arg, req->arg?strlen(req->arg):0, ":", 2);

	/*sanity checks*/
	if (!tokens) {
		GSETERROR(&error_local, "Invalid format (no namespace prefix)");
		return 0;
	}
	if (g_strv_length(tokens)!=2) {
		g_strfreev(tokens);
		return __respond_message(worker, 0, "Invalid REQUEST format", error);
	}

	g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
	g_snprintf(broken_element, sizeof(broken_element), "%s", req->arg + 1 + strlen(ns_name));
	g_strfreev(tokens);

	ns_data = get_namespace(ns_name, NULL);
	if (!ns_data || !ns_data->configured)
		return __respond_message(worker, 0, "NAMESPACE not found/ready", error);

	if (!check_format(ns_data->conscience, broken_element, &error_local))
		return __respond_message(worker, 0, "Invalid ELEMENT format", error);

        if (!create_sub_worker(ns_data, worker, broken_element, &error_local)) {
		GSETERROR(&error_local, "Failed to connect to the conscience");
		return __respond_error(worker, error_local, error);
	}

	request_cleanup(worker);
	worker->func = agent_worker_default_func;
	return 1;
}

