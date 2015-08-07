/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
	
	
	if (!srv || !u)
		return FALSE;
	
	req_data = u;

	si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);
	
	req_data->result = g_slist_prepend( req_data->result, si);
	return TRUE;
}

static GSList*
build_known_services_list( struct namespace_data_s *ns_data, const gchar *type_name, GError **error)
{
	gchar **array_types;
	struct request_data_s req_data;


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
services_types_worker_list( worker_t *worker, GError **error )
{
	struct namespace_data_s *ns_data;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	GByteArray *gba;
	request_t *req;


	/*unpack the parameters and find the namespace*/	
	req = (request_t*) worker->data.session;
	memset(ns_name, 0, sizeof(ns_name));
	memcpy(ns_name, req->arg, MIN(req->arg_size, sizeof(ns_name)-1));

	GError *e = NULL;
	if (!(ns_data = get_namespace(ns_name,&e)))
		return __respond_error(worker, e, error);

	/*reply the service types names*/
	do {
		GSList *names = conscience_get_srvtype_names(ns_data->conscience, error);
		gba = strings_marshall_gba(names,error);
		g_slist_free_full(names, g_free);
	} while (0);

	if (!gba) {
		GSETERROR(error,"String list serialization error");
		return 0;
	}
	
	return __respond(worker,1,gba,error);
}

