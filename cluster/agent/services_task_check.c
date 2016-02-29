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
#include <string.h>

#include <metautils/lib/metacomm.h>
#include <cluster/conscience/conscience.h>
#include <cluster/conscience/conscience_srvtype.h>
#include <cluster/module/module.h>

#include "./asn1_request_worker.h"
#include "./io_scheduler.h"
#include "./namespace_get_task_worker.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

#define TASK_ID "services_check"

#define TASKNAME_LENGTH_MAX (sizeof(TASK_ID) + STRLEN_ADDRINFO)
#define SRVKEY_LEN (LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO)

struct taskdata_checksrv_s {
	gchar task_name[TASKNAME_LENGTH_MAX];
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar srv_key[SRVKEY_LEN];
};

struct workerdata_checksrv_s {
	gchar task_name[TASKNAME_LENGTH_MAX];
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar srv_key[SRVKEY_LEN];

	gboolean flag_connected;
};

/**
 *
 */
static void
zero_service_stats(GPtrArray *pa)
{
	int i, max;
	if (!pa)
		return;
	for (i=0,max=pa->len; i<max ;i++) {
		struct service_tag_s *tag;
		tag = g_ptr_array_index(pa,i);
		if (tag->type==STVT_I64 && g_str_has_prefix(tag->name,"stat."))
			service_tag_set_value_i64(tag,0LL);
	}
}

/**
 * Find the service in the conscience and set its score to 0, and call
 * zero_service_stats() on the conscience service.
 */
static void
invalidate_conscience_service(struct namespace_data_s *ns_data, struct service_info_s *si)
{
	GError *error;
	struct conscience_srvtype_s *srvtype;
	struct conscience_srv_s *srv;
	struct conscience_srvid_s srvid;

	error = NULL;

	srvtype = conscience_get_srvtype(ns_data->conscience, &error, si->type, MODE_STRICT);
	if (srvtype) {
		memcpy(&(srvid.addr), &(si->addr), sizeof(addr_info_t));
		srv = conscience_srvtype_get_srv(srvtype, &srvid);
		if (srv) {
			srv->score.value = 0;
			zero_service_stats(srv->tags);
		}
	}
	if (error)
		g_error_free(error);
}

static void
_mark_service_state(const gchar *ns_name, const gchar *srv_key, gboolean is_up)
{
	struct namespace_data_s *ns_data;
	struct service_info_s *si;

	ns_data = g_hash_table_lookup(namespaces, ns_name);
	if (!ns_data)
		return;

	if (is_up) {
		si = g_hash_table_lookup(ns_data->local_services, srv_key);
		if (!si) {
			/*service was DOWN*/
			si = g_hash_table_lookup(ns_data->down_services, srv_key);
			if (si && (si = service_info_dup(si))) {
				g_hash_table_remove(ns_data->down_services, srv_key);
				g_hash_table_insert(ns_data->local_services, g_strdup(srv_key), si);
				INFO("Service [%s/%s] now UP", ns_name, srv_key);
			}
		}
		else {
			si->score.timestamp = oio_ext_real_time() / G_TIME_SPAN_SECOND;
			DEBUG("Service [%s/%s] still UP", ns_name, srv_key);
		}

		/*ensure the UP tag on TRUE*/
		if (si) {
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_UP), TRUE);
			si->score.timestamp = oio_ext_real_time() / G_TIME_SPAN_SECOND;
		}
	}
	else {
		si = g_hash_table_lookup(ns_data->down_services, srv_key);
		if (!si) {
			/*service was maybe UP*/
			si = g_hash_table_lookup(ns_data->local_services, srv_key);
			if (si && (si = service_info_dup(si))) {
				g_hash_table_remove(ns_data->local_services, srv_key);
				g_hash_table_insert(ns_data->down_services, g_strdup(srv_key), si);
				si->score.value = -2;
			}
			INFO("Service [%s/%s] now DOWN", ns_name, srv_key);
		}
		else {
			DEBUG("Service [%s/%s] still DOWN", ns_name, srv_key);
			si->score.value = -2;
		}

		/*was it UP or not, we ensure it has ZERO stats and the right flags*/
		if (si) {
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_UP), FALSE);
			zero_service_stats(si->tags);
			invalidate_conscience_service(ns_data, si);
			DEBUG("Service [%s/%s] zeroed, invalidated, marked down", ns_name, srv_key);
		}
	}
}

/**
 *
 */
static void
_detect_obsolete_services(struct namespace_data_s *ns_data)
{
	guint counter;
	time_t time_now, time_down, time_broken;
	GHashTableIter s_iterator;
	gpointer s_k, s_v;
	gchar *str_key;
	struct service_info_s *si;


	time_now = oio_ext_real_time() / G_TIME_SPAN_SECOND;
	time_down = time_now - 5;
	time_broken = time_now - 30;
	counter = 0;

	if (!ns_data->configured) {
		return;
	}

	/*move services from UP to DOWN */
	g_hash_table_iter_init(&s_iterator, ns_data->local_services);
	while (g_hash_table_iter_next(&s_iterator, &s_k, &s_v)) {
		str_key = s_k;
		si = s_v;
		si->score.value = -2;/*score not set*/
		if (si->score.timestamp < time_down) {
			gchar str_addr[STRLEN_ADDRINFO];

			grid_addrinfo_to_string(&(si->addr),str_addr,sizeof(str_addr));
			DEBUG("Timeout on service [%s/%s/%s] (%"G_GINT32_FORMAT" < %ld) --> DOWN",
				si->ns_name, si->type, str_addr, si->score.timestamp, time_down);

			g_hash_table_iter_steal(&s_iterator);
			g_hash_table_insert(ns_data->down_services, str_key, si);

			invalidate_conscience_service(ns_data,si);
			zero_service_stats(si->tags);
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_UP), FALSE);

			counter++;
		}
	}

	/*remove services DOWN from a long time ago */
	g_hash_table_iter_init(&s_iterator, ns_data->down_services);
	while (g_hash_table_iter_next(&s_iterator, &s_k, &s_v)) {
		str_key = s_k;
		si = s_v;
		si->score.value = -2;/*score not set*/
		if (si->score.timestamp < time_broken) {
			gchar str_addr[STRLEN_ADDRINFO];

			grid_addrinfo_to_string(&(si->addr),str_addr,sizeof(str_addr));
			DEBUG("Service obsolete [%s/%s/%s] --> DELETED", si->ns_name, si->type, str_addr);

			g_hash_table_iter_remove(&s_iterator);
			counter++;
		}
		else
			zero_service_stats(si->tags);
	}

	if (counter)
		DEBUG("[task_id=%s] %u services states have changed", TASK_ID, counter);
}

static void
_check_tcp_service_worker_cleaner(worker_t *worker)
{
	struct workerdata_checksrv_s *wdata;


	wdata = worker->data.session;
	task_done(wdata->task_name);

	if (wdata->flag_connected) {
		_mark_service_state(wdata->ns_name, wdata->srv_key, TRUE);
		DEBUG("Connection attempt successful to [%s/%s]", wdata->ns_name, wdata->srv_key);
	}
	else {
		_mark_service_state(wdata->ns_name, wdata->srv_key, FALSE);
		WARN("Connection attempt failed to [%s/%s]", wdata->ns_name, wdata->srv_key);
	}

	g_free(wdata);
}

/**
 * This function is passed as the worker callback but does nothing
 * else that closing the connection. At this point, the objective
 * has been reached.
 */
static int
_check_tcp_service_worker_func(worker_t *worker, GError **error)
{
	struct workerdata_checksrv_s *wdata;

	(void) error;
	wdata = worker->data.session;
	wdata->flag_connected = TRUE;

	remove_fd_from_io_scheduler(worker, NULL);
	worker->func = agent_worker_default_func;

	_check_tcp_service_worker_cleaner(worker);
	g_free(worker);
	return 1;
}

/**
 * Check the service still exists and start a worker that will
 * just perform a TCP-connect test.
 */
static int
_check_tcp_service_task(gpointer udata, GError **error)
{
	struct service_info_s *si;
	struct namespace_data_s *ns_data;
	struct taskdata_checksrv_s *task_data;

	task_data = udata;

	ns_data = g_hash_table_lookup(namespaces, task_data->ns_name);
	if (!ns_data) {
		task_done(task_data->task_name);
		GSETERROR(error, "Namespace unavailable");
		return 0;
	}

	/* if the service does not exists, the task itself is de-scheduled */
	if (!(si=g_hash_table_lookup(ns_data->local_services, task_data->srv_key))
	    && !(si=g_hash_table_lookup(ns_data->down_services, task_data->srv_key))) {
		task_done(task_data->task_name);
		task_stop(task_data->task_name);
		INFO("Service [%s] does not exist, stopping task [%s]", task_data->srv_key, task_data->task_name);
		return 1;
	}

	/* Now start a worker for this service. The worker has its own session_data,
	 * without hard reference to the task_t or the namespace_data_t */
	do {
		int fd = addrinfo_connect_nopoll(&(si->addr), error);
		if (0 > fd) {
			GSETERROR(error, "Connection to gridd server failed : (%d) %s",
					errno, strerror(errno));
			return 0;
		}

		sock_set_linger(fd, 1, 0);

		struct workerdata_checksrv_s *wdata = g_malloc0(sizeof(*wdata));
		g_strlcpy(wdata->task_name, task_data->task_name, sizeof(wdata->task_name)-1);
		g_strlcpy(wdata->ns_name, task_data->ns_name, sizeof(wdata->ns_name)-1);
		g_strlcpy(wdata->srv_key, task_data->srv_key, sizeof(wdata->srv_key)-1);

		worker_t *worker = g_malloc0(sizeof(worker_t));
		worker->func = _check_tcp_service_worker_func;
		worker->clean = _check_tcp_service_worker_cleaner;
		worker->timeout.startup = 1000;
		worker->timeout.activity = 1000;
		worker->data.sock_timeout = 1000;
		worker->data.fd = fd;
		worker->data.session = wdata;

		if (!add_fd_to_io_scheduler(worker, EPOLLOUT, error)) {
			_mark_service_state(task_data->ns_name, wdata->srv_key, FALSE);
			task_done(task_data->task_name);
			g_free(worker);
			g_free(wdata);
			GSETERROR(error, "Failed to add socket fd=%d to io_scheduler : %s", fd, strerror(errno));
			return 0;
		}

		TRACE("TCP-connect tried to [%s] for [%s] (fd=%d)", task_data->srv_key, task_data->task_name, fd);
	} while (0);

        return 1;
}

/**
 *
 */
static void
allservice_check_start_HT(struct namespace_data_s *ns_data, GHashTable *ht)
{
	gsize offset;
	struct taskdata_checksrv_s td_scheme;
	GHashTableIter iter_serv;
	gpointer k, v;


	g_hash_table_iter_init(&iter_serv, ht);
	while (g_hash_table_iter_next(&iter_serv, &k, &v)) {
		struct service_info_s *si = v;
		gboolean srv_check_enabled = TRUE;

		/* Services can disable TCP checks (enabled by default) */
		service_tag_t *tag = service_info_get_tag(si->tags,
				NAME_TAGNAME_AGENT_CHECK);
		if (tag) {
			GError *err = NULL;
			if (tag->type == STVT_BOOL) {
				service_tag_get_value_boolean(tag, &srv_check_enabled, &err);
			} else {
				gchar buf[64] = {0};
				service_tag_get_value_string(tag, buf, sizeof(buf), &err);
				srv_check_enabled = metautils_cfg_get_bool(buf, TRUE);
			}
			g_clear_error(&err);
		}

		memset(&td_scheme, 0x00, sizeof(td_scheme));
		offset = g_snprintf(td_scheme.task_name, sizeof(td_scheme.task_name), "%s.", TASK_ID);
		grid_addrinfo_to_string(&(si->addr), td_scheme.task_name+offset, sizeof(td_scheme.task_name)-offset);
		g_strlcpy(td_scheme.ns_name, ns_data->name, sizeof(td_scheme.ns_name)-1);

		if (!srv_check_enabled) {
			GRID_DEBUG("Task [%s] disabled by "
					NAME_TAGNAME_AGENT_CHECK, td_scheme.task_name);
		} else if (!is_task_scheduled(td_scheme.task_name)) {
			GError *error_local = NULL;
			task_t *task = NULL;
			struct taskdata_checksrv_s *task_data;


			agent_get_service_key(si, td_scheme.srv_key, sizeof(td_scheme.srv_key));
			g_strlcpy(td_scheme.srv_key, (gchar*)k, sizeof(td_scheme.srv_key)-1);

			/* prepare the task structure */
			task_data = g_memdup(&td_scheme, sizeof(td_scheme));
			if (!task_data) {
				ERROR("Memory allocation failure");
				continue;
			}

			task = create_task(period_check_services, td_scheme.task_name);
			task = set_task_callbacks(task, _check_tcp_service_task,
					g_free, task_data);
			if (!task) {
				ERROR("Memory allocation failure");
				continue;
			}

			/* now start the task! */
			if (add_task_to_schedule(task, &error_local))
				INFO("Task started: %s", td_scheme.task_name);
			else {
				ERROR("Failed to add task to scheduler [%s] : %s", td_scheme.task_name, gerror_get_message(error_local));
				g_free(task);
			}
			if (error_local)
				g_clear_error(&error_local);
		}
	}
}

static int
allservices_check_starter(gpointer udata, GError **error)
{
	GHashTableIter iter_ns;
	gpointer k, v;

	(void) udata;
	(void) error;

	/*ensure there is a task started for each services locally registered*/
	g_hash_table_iter_init(&iter_ns, namespaces);
	while (g_hash_table_iter_next(&iter_ns, &k, &v)) {
		struct namespace_data_s *ns_data = v;
		TRACE("Checking NS=[%s]", (gchar*)k);
		allservice_check_start_HT(ns_data, ns_data->local_services);
		allservice_check_start_HT(ns_data, ns_data->down_services);
		_detect_obsolete_services(ns_data);
	}

	task_done(TASK_ID);
	return 1;
}

int
services_task_check(GError ** error)
{
	task_t *task = NULL;


	task = set_task_callbacks(create_task(2, TASK_ID),
			allservices_check_starter, NULL, NULL);
	if (!task) {
		GSETERROR(error, "Memory allocation failure");
		return 0;
	}

	if (!add_task_to_schedule(task, error)) {
		g_free(task);
		GSETERROR(error, "Failed to add vol_stat_send task to scheduler");
		return 0;
	}

	INFO("Task started: "TASK_ID);
	return 1;
}

