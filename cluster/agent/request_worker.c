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

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>

#include "./get_ns_worker.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./message.h"
#include "./request_worker.h"
#include "./services_workers.h"
#include "./task_scheduler.h"

static int register_request_handler(const char *request_name, worker_func_f handler, GError **error);

static GHashTable *requests = NULL;

int
init_request_worker(GError **error)
{
	requests = g_hash_table_new(g_str_hash, g_str_equal);

	if (!register_request_handler(MSG_GETNS, get_ns_worker, error)) {
		GSETERROR(error, "Failed to register get_ns worker in request_worker");
		return(0);
	}

	if (!register_request_handler(MSG_SRVTYPE_LST, services_types_worker_list, error)) {
		GSETERROR(error, "Failed to register services_types_worker_list worker in request_worker");
		return(0);
	}

	if (!register_request_handler(MSG_SRV_LST, services_worker_list, error)) {
		GSETERROR(error, "Failed to register services_worker_list worker in request_worker");
		return(0);
	}
	if (!register_request_handler(MSG_SRV_CLR, services_worker_clear, error)) {
		GSETERROR(error, "Failed to register services_worker_clear worker in request_worker");
		return(0);
	}
	if (!register_request_handler(MSG_SRV_PSH, services_worker_push, error)) {
		GSETERROR(error, "Failed to register services_worker_push worker in request_worker");
		return(0);
	}
	if (!register_request_handler(MSG_SRV_GET1, services_worker_get_one, error)) {
		GSETERROR(error, "Failed to register services_worker_get_one worker in request_worker");
		return(0);
	}

	if (!register_request_handler(MSG_LSTSVC, services_worker_list_local, error)) {
		GSETERROR(error, "Failed to register services_worker_list_local worker in request_worker");
		return(0);
	}

	if (!register_request_handler(MSG_LSTTASK, list_tasks_worker, error)) {
		GSETERROR(error, "Failed to register list_tasks_worker worker in request_worker");
		return(0);
	}

	return(1);
}

int register_request_handler(const char *request_name, worker_func_f handler, GError **error) {

	if (!requests) {
		GSETERROR(error, "request_worker has not been initialized. Please, call init_request_worker before.");
		return(0);
	}

	if (g_hash_table_lookup(requests, request_name) != NULL) {
		GSETERROR(error, "Handler for this request has already been registered.");
		return(0);
	}

	g_hash_table_insert(requests, g_strdup(request_name), handler);

	return(1);
}

int request_worker(worker_t *worker, GError **error) {
	request_t *request = NULL;


	EXTRA_ASSERT(worker != NULL);
	EXTRA_ASSERT(worker->data.session != NULL);

	request = g_malloc0(sizeof(request_t));

	if (!read_request_from_message((message_t*)worker->data.session, request, error)) {
		GSETERROR(error, "Failed to parse message to build request");
		request_clean(request);
		return 0;
	}

	/* Free the message and put the request in session */
	message_cleanup(worker);
	worker->data.session = request;
	worker->clean = request_cleanup;
	worker->func = g_hash_table_lookup(requests, request->cmd);

	if (!worker->func) {
		GSETERROR(error, "No handler found for request [%s]", request->cmd);
		return 0;
	}

	if (!change_fd_events_in_io_scheduler(worker, EPOLLOUT, error)) {
		GSETERROR(error, "Failed to change polling event on fd %d", worker->data.fd);
		return 0;
	}

	return 1;
}

