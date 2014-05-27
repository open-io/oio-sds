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

static void
free_services_list( GSList *list )
{
	TRACE_POSITION();
	if (list) {
		g_slist_foreach( list, service_info_gclean, NULL);
		g_slist_free( list );
	}
}

static gboolean
services_runner(struct conscience_srv_s * srv, gpointer u)
{
	struct request_data_s *req_data;
	struct service_info_s *si;
	
	TRACE_POSITION();
	
	if (!srv || !u)
		return FALSE;
	
	req_data = u;

	si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);
	
	req_data->result = g_slist_prepend( req_data->result, si);
	return TRUE;
}

static guint
count_known_services_list( struct namespace_data_s *ns_data, const gchar *type_name, GError **error)
{
	struct conscience_srvtype_s *srvtype;

	TRACE_POSITION();
	
	srvtype = conscience_get_srvtype( ns_data->conscience, error, type_name, MODE_STRICT);
	if (!srvtype) {
		GSETERROR(error,"Service type not found");
		return 0;
	}

	return conscience_srvtype_count_srv(srvtype,TRUE);
}

static GSList*
build_known_services_list( struct namespace_data_s *ns_data, const gchar *type_name, GError **error)
{
	gchar **array_types;
	struct request_data_s req_data;

	TRACE_POSITION();

	req_data.result = NULL;
	array_types = g_strsplit(type_name,",",0);

	if (!conscience_run_srvtypes(
			ns_data->conscience, error, SRVTYPE_FLAG_INCLUDE_EXPIRED,
			array_types, services_runner, &req_data)) {
		g_strfreev(array_types);
		free_services_list(req_data.result);
		if (!*error)
			GSETERROR(error, "Failed to collect the services %s/%s",
					ns_data->name, type_name);
		return NULL;
	}

	g_strfreev(array_types);
	return req_data.result;
}

int
services_worker_list( worker_t *worker, GError **error )
{
	GError *error_local = NULL;
	struct namespace_data_s *ns_data;
	gchar **tokens, ns_name[LIMIT_LENGTH_NSNAME], type_name[LIMIT_LENGTH_SRVTYPE];
	GByteArray *gba = NULL;
	request_t *req;

	TRACE_POSITION();

	/*unpack the parameters and find the namespace*/	
	req = (request_t*) worker->data.session;
	tokens = buffer_split(req->arg, req->arg_size, ":", 3);
	if (!tokens) {
		GSETERROR(&error_local,"internal error");
		return 0;
	}
	if (g_strv_length(tokens)!=2) {
		g_strfreev(tokens);
		return __respond_message(worker, 0, "Invalid format (not NS:TYPE)", error);
	}
	else {
		bzero(ns_name, sizeof(ns_name));
		bzero(type_name, sizeof(type_name));
		g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);
		g_strlcpy(type_name, tokens[1], sizeof(type_name)-1);
		g_strfreev(tokens);
		tokens = NULL;
		if (strchr(ns_name, '.'))
			*(strchr(ns_name, '.')) = '\0';
	}

	if (!(ns_data = get_namespace(ns_name, &error_local)))
		return __respond_error(worker, error_local, error);

	do {
		GSList *services = build_known_services_list(ns_data, type_name, &error_local);
		gba = service_info_marshall_gba(services,&error_local);
		free_services_list(services);
		services = NULL;
	} while (0);

	if (!gba) {
		GSETERROR(&error_local,"service_info list serialization error");
		return 0;
	}

	return __respond(worker, 1, gba, error);
}

int
services_worker_count( worker_t *worker, GError **error )
{
	struct namespace_data_s *ns_data;
	gchar **tokens, ns_name[LIMIT_LENGTH_NSNAME], type_name[LIMIT_LENGTH_SRVTYPE], str_count[12];
	guint services_count;
	GByteArray *gba;
	request_t *req;

	TRACE_POSITION();

	/*unpack the parameters and find the namespace*/	
	req = (request_t*) worker->data.session;
	tokens = buffer_split(req->arg, req->arg_size, ":", 3);

	if (!tokens || g_strv_length(tokens)!=2) {
		if (tokens)
			g_strfreev(tokens);
		return __respond_message(worker, 0, "Invalid format (not NS:TYPE)", error);
	} else {
		bzero(ns_name, sizeof(ns_name));
		g_strlcpy(ns_name, tokens[0], sizeof(ns_name)-1);

		bzero(type_name, sizeof(type_name));
		g_strlcpy(type_name, tokens[1], sizeof(type_name)-1);

		g_strfreev(tokens);
	}

	GError *e = NULL;
	if (!(ns_data = get_namespace(ns_name, &e)))
		return __respond_error(worker, e, error);

	/*now compute and reply the service count*/
	services_count = count_known_services_list(ns_data, type_name, error);
	g_snprintf( str_count, sizeof(str_count), "%d", services_count);
	gba = g_byte_array_append(g_byte_array_new(), (guint8*)str_count, strlen(str_count));

	if (!gba) {
		GSETERROR(error, "Memory allocation failure");
		return 0;
	}

	return __respond(worker, 1, gba, error);
}

int
services_types_worker_list( worker_t *worker, GError **error )
{
	struct namespace_data_s *ns_data;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	GByteArray *gba;
	request_t *req;

	TRACE_POSITION();

	/*unpack the parameters and find the namespace*/	
	bzero(ns_name, sizeof(ns_name));
	req = (request_t*) worker->data.session;
	g_memmove(ns_name, req->arg, MIN(req->arg_size, sizeof(ns_name)-1));

	GError *e = NULL;
	if (!(ns_data = get_namespace(ns_name,&e)))
		return __respond_error(worker, e, error);

	/*reply the service types names*/
	do {
		GSList *names = conscience_get_srvtype_names(ns_data->conscience, error);
		gba = meta2_maintenance_names_marshall(names,error);
		g_slist_foreach(names,g_free1,NULL);
		g_slist_free(names);
		names = NULL;
	} while (0);

	if (!gba) {
		GSETERROR(error,"String list serialization error");
		return 0;
	}
	
	return __respond(worker,1,gba,error);
}

