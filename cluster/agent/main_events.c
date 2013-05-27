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
# define LOG_DOMAIN "gridcluster.agent.events"
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
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils.h>

#include "./namespace_get_task_worker.h"
#include "./agent.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./server.h"
#include "./task.h"
#include "./task_scheduler.h"

static void
sighandler_event_manager(int s)
{
	/*INFO("Signal %d (%s)", s, get_signame(s));*/
	switch (s) {
	case SIGPIPE:
	case SIGALRM:
	case SIGUSR1:
	case SIGUSR2:
		break;
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		stop_task_scheduler();
		stop_io_scheduler();
		break;
	}
	signal(s,sighandler_event_manager);
}

static inline void
set_sighandlers(void)
{
	signal(SIGPIPE, sighandler_event_manager);
	signal(SIGALRM, sighandler_event_manager);
	signal(SIGUSR1, sighandler_event_manager);
	signal(SIGUSR2, sighandler_event_manager);

	signal(SIGINT, sighandler_event_manager);
	signal(SIGQUIT, sighandler_event_manager);
	signal(SIGTERM, sighandler_event_manager);
}

int
main_event(const gchar *ns_name)
{
	GError *error = NULL;
	
	set_sighandlers();	
	
	if (!init_io_scheduler(&error)) {
		ERROR("Failed to init io scheduler :\n\t%s", gerror_get_message(error));
		goto error_label;
	}
	if (!agent_start_indirect_ns_config(ns_name, &error)) {
		ERROR("Failed to launch the indirect namespace configuration  task :\n\t%s", gerror_get_message(error));
		goto error_label;
	}
	if (!agent_start_indirect_event_config(ns_name, &error)) {
		ERROR("Failed to launch the indirect events configuration task :\n\t%s", gerror_get_message(error));
		goto error_label;
	}
	if (!agent_start_event_all_tasks(ns_name, &error)) {
		ERROR("Failed to launch the events PUSH task :\n\t%s", gerror_get_message(error));
		goto error_label;
	}
	if (!launch_io_scheduler(&error)) {
		ERROR("Failed to launch network io scheduler :\n\t%s", gerror_get_message(error));
		goto error_label;
	}

	return 0;
error_label:
	g_clear_error(&error);
	return -1;
}

