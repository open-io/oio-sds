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

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

#include "conscience/conscience.h"

#include "agent.h"
#include "gridagent.h"
#include "message.h"
#include "namespace_get_task_worker.h"
#include "task.h"
#include "task_scheduler.h"
#include "services_workers.h"

gsize
agent_get_service_key(struct service_info_s *si, gchar * dst, gsize dst_size)
{
	gsize writen;


	writen = 0;
	writen += g_snprintf(dst + writen, dst_size - writen, "%s:", si->type);
	writen += grid_addrinfo_to_string(&(si->addr), dst + writen, dst_size - writen);
	return writen;
}

static gboolean
manage_service(struct service_info_s *si)
{
	GError *error_local;
	struct service_info_s *old_si = NULL;
	struct service_tag_s *tag_first = NULL;
	struct namespace_data_s *ns_data;
	gsize key_size;
	gchar key[LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO], str_addr[STRLEN_ADDRINFO];


	if (!si) {
		ERROR("Invalid parameter");
		return FALSE;
	}

	key_size = agent_get_service_key(si, key, sizeof(key));
	grid_addrinfo_to_string(&(si->addr), str_addr, sizeof(str_addr));

	/*this service must refer to known namespace and service type*/
	error_local = NULL;
	if (!(ns_data = get_namespace(si->ns_name, &error_local))) {
		ERROR("Namespace unavailable for service [ns=%s type=%s addr=%s] : %s",
			si->ns_name, si->type, str_addr, gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
		return FALSE;
	}

	/*Info trace when a service of a new type is used */
	if (error_local)
		g_error_free(error_local);
	if (!conscience_get_srvtype(ns_data->conscience, &error_local, si->type, MODE_STRICT)) {
		/*to avoid traces flooding, if the service already exists, no trace is sent */
		if (!g_hash_table_lookup(ns_data->local_services, key)
				&& !g_hash_table_lookup(ns_data->down_services, key)) {
			INFO("New service type discovered [ns=%s type=%s addr=%s]", ns_data->name, si->type, str_addr);
		}
	}

	/*replace MACRO tags by their true values */
	if (error_local)
		g_clear_error(&error_local);

	metautils_srvinfo_ensure_tags (si);

	si->score.value = SCORE_UNSET;
	si->score.timestamp = oio_ext_real_time() / G_TIME_SPAN_SECOND;

	/*then keep the score */
	g_hash_table_remove(ns_data->down_services, key);

	/* save first lauched tag if still in old si */
	old_si = g_hash_table_lookup(ns_data->local_services, key);
	if (old_si != NULL) {
		tag_first = service_info_get_tag(old_si->tags, NAME_TAGNAME_RAWX_FIRST);
		if (tag_first != NULL)
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_FIRST), tag_first->value.b);
	}

	service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_UP), TRUE);
	g_hash_table_insert(ns_data->local_services, g_strndup(key, key_size), si);

	DEBUG("Service registration [ns=%s type=%s addr=%s]", ns_data->name, si->type, str_addr);

	if (error_local)
		g_error_free(error_local);
	return TRUE;
}

int
services_worker_push(worker_t * worker, GError ** error)
{
	gboolean rc;
	GSList *list_service_info = NULL, *l;


	/*extract the fields packed in the request's parameter */
	request_t *req = (request_t *) worker->data.session;
	rc = service_info_unmarshall(&list_service_info, req->arg, req->arg_size, error);
	
	if (!rc) {
		GSETERROR(error, "Invalid payload (service_info sequence expected)");
		return 0;
	}

	/*push all the services */
	for (l = list_service_info; l; l = l->next) {
		if (!l->data)
			continue;
		if (!manage_service(l->data))
			service_info_clean(l->data);
		l->data = NULL;
	}
	g_slist_free(list_service_info);
	list_service_info = NULL;

	return __respond_message(worker, 1, "OK", error);
}

/* ------------------------------------------------------------------------- */

static void
fill_service_info_score(struct conscience_s *conscience, struct service_info_s *si)
{
	struct conscience_srv_s *srv;
	struct conscience_srvtype_s *srvtype;

	si->score.value = SCORE_UNSET;
	srvtype = conscience_get_srvtype(conscience, NULL, si->type, MODE_STRICT);
	if (srvtype) {
		srv = conscience_srvtype_get_srv(srvtype, (struct conscience_srvid_s*)&(si->addr));
		if (srv)
			si->score.value = srv->score.value;
	}
}

static GSList *
build_local_service_info_list(void)
{
	GHashTableIter srv_iterator, ns_iterator;
	gpointer srv_k, srv_v, ns_k, ns_v;
	GSList *services;


	/* iterate over the locally registered services of all the namespaces
	 * For all these services, we force their score to the only two values
	 * they may have : unset or zero */
	services = NULL;
	g_hash_table_iter_init(&ns_iterator, namespaces);
	while (g_hash_table_iter_next(&ns_iterator, &ns_k, &ns_v)) {
		struct namespace_data_s *ns_data;

		ns_data = ns_v;
		if (!namespace_is_available(ns_data))
			continue;

		/*UP services */
		g_hash_table_iter_init(&srv_iterator, ns_data->local_services);
		while (g_hash_table_iter_next(&srv_iterator, &srv_k, &srv_v)) {
			struct service_info_s *si;

			si = srv_v;
			fill_service_info_score(ns_data->conscience, si);
			services = g_slist_prepend(services, si);
		}

		/*DOWN services */
		g_hash_table_iter_init(&srv_iterator, ns_data->down_services);
		while (g_hash_table_iter_next(&srv_iterator, &srv_k, &srv_v)) {
			struct service_info_s *si;

			si = srv_v;
			si->score.value = SCORE_DOWN;
			services = g_slist_prepend(services, si);
		}
	}

	return services;
}

int
services_worker_list_local(worker_t * worker, GError ** error)
{
	GSList *services;
	GByteArray *gba;
	response_t response;


	memset(&response, 0, sizeof(response_t));

	services = build_local_service_info_list();
	gba = service_info_marshall_gba(services, error);
	g_slist_free(services);

	if (!gba) {
		GSETERROR(error, "service_info list serialization error");
		return __respond_error(worker, error ? *error : NULL, NULL);
	}

	return __respond(worker, 1, gba, error);
}

