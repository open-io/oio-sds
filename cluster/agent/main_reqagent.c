#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.reqagent"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <metautils/lib/metautils.h>

#include "./agent.h"
#include "./config.h"
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
	if (flag_check_services) {
		if (!services_task_check(&error)) {
			ERROR("Services crawler (detect_obsoletes) task error : %s", gerror_get_message(error));
			goto error_label;
		}
		INFO("Services tasks successfully started");
	}


	/* Conscience broken elements tasks */
	if (flag_manage_broken) {
		if (!agent_start_broken_task_get(&error)) {
			ERROR("Failed to start broken containers GET task: %s", gerror_get_message(error));
			goto error_label;
		}
		if (!agent_start_broken_task_push(&error)) {
			ERROR("Failed to start broken containers SEND task : %s", gerror_get_message(error));
			goto error_label;
		}
		INFO("Broken tasks successfully started");
	}

	/* Event tasks : config + incoming */
	if (!agent_start_event_task_config(&error)) {
		ERROR("Event handlers configuration task error : %s", gerror_get_message(error));
		goto error_label;
	}
	INFO("Events tasks successfully started");

	launch_io_scheduler();
	rc = 0;

error_label:
	if (error)
		g_clear_error(&error);
	return rc;
}


