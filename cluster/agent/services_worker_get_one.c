#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.srv_list_get_task_worker"
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
#include "./message.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task_scheduler.h"

struct request_data_s {
	const gchar *ns_name;
	const gchar *type_name;
	GSList *result;
};

static gboolean
poll_conscience_service(struct conscience_srvtype_s *srvtype, struct service_info_s *si, GError **err)
{
	gint last_score;
	struct conscience_srv_s *last, *srv, *stop;

	(void) err;

	stop = &(srvtype->services_ring);
	last_score = 0;
	last = NULL;

	for (srv=stop->next; srv && srv!=stop ;srv=srv->next) {
		if (srv->score.value > last_score) {
			last = srv;
			last_score = srv->score.value;
		}
	}

	if (last && last_score>0) {
		conscience_srv_fill_srvinfo(si, last);
		return TRUE;
	}
	return FALSE;
}

gboolean
agent_choose_best_service2(struct namespace_data_s *ns_data, const gchar *srvname, struct service_info_s *si, GError **err)
{
	struct conscience_srvtype_s *srvtype;

	srvtype = conscience_get_srvtype(ns_data->conscience, err, srvname, MODE_STRICT);
	if (!srvtype) {
		GSETERROR(err,"Service type [%s] not found", srvname);
		return FALSE;
	}
	return poll_conscience_service(srvtype, si, err);
}

gboolean
agent_choose_best_service(const gchar *ns_name, const gchar *srvname, struct service_info_s *si, GError **err)
{
	struct namespace_data_s *ns_data;
	
	ns_data = get_namespace(ns_name,err);
	if (!ns_data) {
		GSETERROR(err,"Namespace [%s] not (yet) managed", ns_name);
		return FALSE;
	}
	return agent_choose_best_service2(ns_data, srvname, si, err);
}

static GByteArray*
_serialize_one_service_info(struct service_info_s *si, GError **error)
{
	GSList *list_of_si;
	GByteArray *gba;

	list_of_si = g_slist_prepend(NULL, si);
	gba = service_info_marshall_gba(list_of_si,error);
	g_slist_free(list_of_si);
	return gba;
}

int
services_worker_get_one(worker_t *worker, GError **error)
{
	GError *error_local = NULL;
	gchar **tokens, ns_name[LIMIT_LENGTH_NSNAME], type_name[LIMIT_LENGTH_SRVTYPE];
	GByteArray *gba;
	request_t *req;
	struct service_info_s *si = NULL;

	TRACE_POSITION();

	/*unpack the parameters and find the namespace*/	
	req = (request_t*) worker->data.session;
	tokens = buffer_split(req->arg, req->arg_size, ":", 3);
	if (!tokens) {
		GSETERROR(error, "Split error");
		return 0;
	}
	if (g_strv_length(tokens)!=2) {
		g_strfreev(tokens);
		return __respond_message(worker,0,"Invalid format (not NS:TYPE)", error);
	}
	else {
		bzero(ns_name, sizeof(ns_name));
		bzero(type_name, sizeof(type_name));
		g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
		g_strlcpy(type_name, tokens[1], sizeof(type_name)-1);
		g_strfreev(tokens);
	}
	si = g_malloc0(sizeof(struct service_info_s));

	/*find a service*/
	if (!agent_choose_best_service(ns_name, type_name, si, &error_local)) {
		service_info_clean(si);
		return __respond_error(worker, error_local, error);
	}
	
	/*Serialize the service*/
	if (!(gba = _serialize_one_service_info(si, &error_local))) {
		service_info_clean(si);
		GSETERROR(&error_local,"service_info list serialization error");
		return 0;
	}
	
	/*prepare the response*/
	return __respond(worker, 1, gba, error);
}

