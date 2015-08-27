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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/lib/message.h>

#include "./agent.h"
#include "./cpu_stat_task_worker.h"
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

static gboolean
gridagent_running(void)
{
	int sock = gridagent_connect(NULL);
	if (sock < 0) {
		gchar *path = oio_cfg_get_agent();
		unlink(path);
		g_free(path);
		return 0;
	}
	metautils_pclose(&sock);
	return 1;
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

	if (gridagent_running()) {
		ERROR("An agent is already running");
		goto error_label;
	}

	if (!init_io_scheduler(&error)) {
		ERROR("Failed to init io scheduler : %s", gerror_get_message(error));
		goto error_label;
	}
	if (!start_server(&error)) {
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
	if (flag_check_services) {
		if (!services_task_check(&error)) {
			ERROR("Services crawler (detect_obsoletes) task error : %s",
					gerror_get_message(error));
			goto error_label;
		}
		INFO("Services tasks successfully started");
	}

	launch_io_scheduler();
	rc = 0;

error_label:
	if (error)
		g_clear_error(&error);
	return rc;
}

