#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.events"
#endif

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <metautils/lib/metautils.h>

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

	launch_io_scheduler();
	return 0;
error_label:
	g_clear_error(&error);
	return -1;
}

