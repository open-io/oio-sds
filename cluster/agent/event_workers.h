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

#ifndef OIO_SDS__cluster__agent__event_workers_h
# define OIO_SDS__cluster__agent__event_workers_h 1

# include <sys/types.h>
# include <sys/stat.h>
# include <unistd.h>

# include <cluster/agent/agent.h>
# include <cluster/agent/worker.h>
# include <cluster/conscience/conscience.h>
# include <cluster/events/gridcluster_events.h>
# include <cluster/events/gridcluster_eventhandler.h>

/* EVENT AGENT TASKS ------------------------------------------------------- */

/**
 * Crawl all the queues belonging to an agent.
 */
int agent_start_event_all_tasks(const gchar *ns_name, GError **error);

/**
 * DO NOT USE IN THE MAIN AGENT (child-req ou monoproc)
 */
int agent_start_indirect_event_config(const gchar *ns_name, GError **error);

/* MAIN AGENT TASKS -------------------------------------------------------- */

/**
 * Starts a monitoring task will itself start per-namespace tasks.
 * Each subtask is responsible to regularily poll the event_handler
 * configuration belonging to its namespace.
 */
int agent_start_event_task_config(GError **error);

/* REQUEST WORKERS --------------------------------------------------------- */

/**
 *
 */
int agent_receive_event_worker(worker_t *worker, GError **error);

int agent_reply_event_managed_patterns_worker(worker_t *worker, GError **error);

int agent_reply_event_configuration_worker(worker_t *worker, GError **error);

/* Helpers ----------------------------------------------------------------- */

typedef struct path_data_s path_data_t;

struct path_data_s
{
	gchar str_cid[STRLEN_CONTAINERID];
	container_id_t id;
	struct stat stat;
	time_t xattr_time;
	gint64 xattr_seq;
	gsize relpath_size;
	gchar relpath[1024];
};

/**
 * List the events in 'dir' that have been dropped at least 'delay'
 * seconds ago. Only one event per container is returned.
 *
 * @return a GSList of pointers to path_data_t, to be freed with g_free() 
 */
GSList* agent_list_earliest_events(const gchar *dir, guint max, time_t delay,
		gboolean(*filter)(path_data_t *));

#endif /*OIO_SDS__cluster__agent__event_workers_h*/