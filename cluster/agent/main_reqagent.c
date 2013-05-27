/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.agent.reqagent"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <glib.h>

#include <metautils.h>

#include "./agent.h"
#include "./broken_workers.h"
#include "./cpu_stat_task_worker.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./io_stat_task_worker.h"
#include "./namespace_get_task_worker.h"
#include "./request_worker.h"
#include "./server.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

static void
sighandler_agent(int s)
{
	/*INFO("Signal %d (%s)", s, get_signame(s));*/
	switch (s) {
	case SIGPIPE:
		break;
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		stop_task_scheduler();
		stop_io_scheduler();
		stop_server();
		break;
	}
	signal(s,sighandler_agent);
}


int
main_reqagent(void)
{
	int rc = -1;
	GError *error = NULL;

	signal(SIGQUIT, sighandler_agent);
	signal(SIGTERM, sighandler_agent);
	signal(SIGINT,  sighandler_agent);
	signal(SIGPIPE, sighandler_agent);

	if (is_agent_running()) {
		ERROR("An agent is already running");
		goto error_label;
	}

	if (!init_io_scheduler(&error)) {
		ERROR("Failed to init io scheduler : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!start_server(SOCK_TIMEOUT, &error)) {
		ERROR("Failed to start server : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!init_request_worker(&error)) {
		ERROR("Failed to init message worker : %s", gerror_get_message(error));
		goto error_label;
	}


	/* Local monitoring tasks */
	if (!start_io_stat_task(&error)) {
		ERROR("Failed to start io stat task : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!start_cpu_stat_task(&error)) {
		ERROR("Failed to start cpu stat task : %s", gerror_get_message(error));
		goto error_label;
	}

	
	/* Conscience services tasks */
	if (!start_namespace_get_task(&error)) {
		ERROR("Failed to start namespace info retriever task : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!services_task_get_types(&error)) {
		ERROR("Services GETTYPES task error : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!services_task_get_services(&error)) {
		ERROR("Services GET task error : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!services_task_push(&error)) {
		ERROR("Services PUSH task error : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!services_task_check(&error)) {
		ERROR("Services crawler (detect_obsoletes) task error : %s", gerror_get_message(error));
		goto error_label;
	}
	INFO("Services tasks successfully started");


	/* Conscience broken elements tasks */
	if (!agent_start_broken_task_get(&error)) {
		ERROR("Failed to start broken containers GET task: %s", gerror_get_message(error));
		goto error_label;
	}
#ifdef HAVE_LEGACY
	if (!agent_start_broken_task_push(&error)) {
		ERROR("Failed to start broken containers SEND task : %s", gerror_get_message(error));
		goto error_label;
	}
#endif
	INFO("Broken tasks successfully started");


	/* Event tasks : config + incoming */
	if (!agent_start_event_task_config(&error)) {
		ERROR("Event handlers configuration task error : %s", gerror_get_message(error));
		goto error_label;
	}
	INFO("Events tasks successfully started");


	INFO("Starting the main IO scheduler...");
	if (!launch_io_scheduler(&error)) {
		ERROR("Failed to launch network io scheduler : %s", gerror_get_message(error));
		goto error_label;
	}

	rc = 0;

error_label:
	if (error)
		g_clear_error(&error);
	return rc;
}


