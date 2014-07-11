#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.service_register_worker"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "conscience/conscience.h"

#include "agent.h"
#include "cpu_stat_task_worker.h"
#include "fs.h"
#include "gridagent.h"
#include "io_stat_task_worker.h"
#include "message.h"
#include "namespace_get_task_worker.h"
#include "task.h"
#include "task_scheduler.h"
#include "services_workers.h"

gsize
agent_get_service_key(struct service_info_s *si, gchar * dst, gsize dst_size)
{
	gsize writen;

	TRACE_POSITION();

	writen = 0;
	writen += g_snprintf(dst + writen, dst_size - writen, "%s:", si->type);
	writen += addr_info_to_string(&(si->addr), dst + writen, dst_size - writen);
	return writen;
}

static gboolean
expand_service_tags(struct namespace_data_s *ns_data, struct service_info_s *si, GError ** error)
{
	int i, max;
	struct service_tag_s *tag;
	gchar str_addr[STRLEN_ADDRINFO], str_tag[1024];

	if (!si->tags)
		return TRUE;

	addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
	for (i = 0, max = si->tags->len; i < max; i++) {

		tag = g_ptr_array_index(si->tags, i);
		if (!tag)
			continue;
		if (tag->type == STVT_MACRO) {
			int idle;

			if (!tag->value.macro.type) {
				GSETERROR(error, "Invalid MACRO type for service_tag");
				return FALSE;
			}

			if (!g_ascii_strcasecmp(tag->value.macro.type, NAME_MACRO_IOIDLE_TYPE)) {
				if (get_io_idle_for_path(tag->value.macro.param, &idle, error))
					service_tag_set_value_i64(tag, MACRO_MAX(idle,1));
				else {
					service_tag_to_string(tag, str_tag, sizeof(str_tag));
					if (gridagent_blank_undefined_srvtags) {
						DEBUG("Service [NS=%s][SRVTYPE=%s][@=%s] : %s nulled",
							si->ns_name, si->type, str_addr, tag->name);
						service_tag_set_value_i64(tag, 0);
					}
					else {
						GSETERROR(error, "Service [NS=%s][SRVTYPE=%s][@=%s] : "
								"macro expansion failure name=[%s] value=[%s]",
								si->ns_name, si->type, str_addr, tag->name, str_tag);
						return FALSE;
					}
				}
			}
			else if (!g_ascii_strcasecmp(tag->value.macro.type, NAME_MACRO_CPU_TYPE)) {
				if (get_cpu_idle(&idle, error))
					service_tag_set_value_i64(tag, idle?idle:1);
				else {
					service_tag_to_string(tag, str_tag, sizeof(str_tag));
					if (gridagent_blank_undefined_srvtags) {
						DEBUG("Service [NS=%s][SRVTYPE=%s][@=%s] : nulled %s",
								si->ns_name, si->type, str_addr, tag->name);
						service_tag_set_value_i64(tag, 0);
					}
					else {
						GSETERROR(error, "Service [NS=%s][SRVTYPE=%s][@=%s] : "
								"macro expansion failure name=[%s] value=[%s]",
								si->ns_name, si->type, str_addr, tag->name, str_tag);
						return FALSE;
					}
				}
			}
			else if (!g_ascii_strcasecmp(tag->value.macro.type, NAME_MACRO_SPACE_TYPE)) {
				long free_space;
				gint64 free_space_i64;
				free_space = get_free_space(tag->value.macro.param,ns_data->ns_info.chunk_size);
				free_space_i64 = free_space;
				service_tag_set_value_i64(tag,free_space_i64);
			}
			else {
				WARN("Service [NS=%s][SRVTYPE=%s][@=%s] : macro type not managed name=[%s] type=[%s]",
					si->ns_name, si->type, str_addr, tag->name, tag->value.macro.type);
			}
		}
	}
	return TRUE;
}

static gboolean
manage_service(struct service_info_s *si)
{
	GError *error_local;
	struct service_info_s *old_si = NULL;
	struct service_tag_s *tag_first = NULL;
	struct namespace_data_s *ns_data;
	gsize key_size;
	gchar key[LIMIT_LENGTH_SRVTYPE + 1 + STRLEN_ADDRINFO + 1], str_addr[STRLEN_ADDRINFO];

	TRACE_POSITION();

	if (!si) {
		ERROR("Invalid parameter");
		return FALSE;
	}

	key_size = agent_get_service_key(si, key, sizeof(key));
	addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));

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
	if (!expand_service_tags(ns_data, si, &error_local)) {
		WARN("Service tags expansion failure: [ns=%s type=%s addr=%s] : %s",
				ns_data->name, si->type, str_addr, gerror_get_message(error_local));
		if (error_local)
			g_error_free(error_local);
		return FALSE;
	}

	/*Set the score to the "unset" value*/
	si->score.value = -2;
	si->score.timestamp = time(0);

	/*then keep the score */
	g_hash_table_remove(ns_data->down_services, key);

	/* save first lauched tag if still in old si */
	old_si = g_hash_table_lookup(ns_data->local_services, key);
	if (old_si != NULL) {
		tag_first = service_info_get_tag(old_si->tags, NAME_TAGNAME_RAWX_FIRST);
		if (tag_first != NULL)
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_FIRST), tag_first->value.b);
	}

	service_tag_set_value_boolean(service_info_ensure_tag(si->tags, "tag.up"), TRUE);
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
	gsize arg_size;
	GSList *list_service_info = NULL, *l;

	TRACE_POSITION();

	/*extract the fields packed in the request's parameter */
	request_t *req = (request_t *) worker->data.session;
	arg_size = req->arg_size;
	rc = service_info_unmarshall(&list_service_info, req->arg, &arg_size, error);
	
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

	si->score.value = -1;
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

	TRACE_POSITION();

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
			si->score.value = 0;
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

	TRACE_POSITION();

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

