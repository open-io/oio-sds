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
# define LOG_DOMAIN "gridcluster.agent.task_scheduler"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <metautils.h>

#include "agent.h"
#include "task_scheduler.h"
#include "task.h"
#include "gridagent.h"
#include "message.h"

#define MAX_SCHEDULE_PERIOD 60

#ifdef AGENT_HYPERSPEED_MULTIVITAMINE
# define IS_TASK_READY(T) 1
#else
# define IS_TASK_READY(T) (T)->next_schedule <= now
#endif

static gboolean task_scheduler_running = TRUE;
static GHashTable *tasks = NULL;
static long global_next_schedule;

static void
task_cleaner(gpointer p)
{
	task_t *task;
	
	task = p;
	if (!task)
		return;
	if (task->id)
		g_free(task->id);
	if (task->udata && task->clean_udata)
		task->clean_udata(task->udata);

	memset(task,0x00,sizeof(task_t));
	g_free(task);
}

void
init_task_scheduler(void)
{
	tasks = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, task_cleaner);
	global_next_schedule = time(NULL) + MAX_SCHEDULE_PERIOD;
}

void
stop_task_scheduler(void)
{
	task_scheduler_running = FALSE;
}

int
add_task_to_schedule(task_t * task, GError ** error)
{
	long now;
	
	if (!task_scheduler_running) {
		GSETERROR(error,"The task scheduler has been stopped!");
		return 0;
	}

	if (!task) {
		GSETERROR(error, "Parameter <task> can't be NULL");
		return (0);
	}

	if (g_hash_table_lookup(tasks, task->id)) {
		GSETERROR(error, "A task already exists for this id [%s]", task->id);
		return (0);
	}

	now = time(NULL);
	task->next_schedule = now + task->period;

	if (task->next_schedule < global_next_schedule)
		global_next_schedule = task->next_schedule;

	g_hash_table_insert(tasks, task->id, task);
	return (1);
}

int
remove_task(const char *task_id, GError ** error)
{
	if (!g_hash_table_lookup(tasks, task_id)) {
		GSETERROR(error, "Task [%s] is not actually scheduled", task_id);
		return (0);
	}
	g_hash_table_remove(tasks, task_id);
	return (1);
}

static void
exec_scheduled_tasks(task_t *task)
{
	int rc;
	GError *error;

	error = NULL;
	if (!task->task_handler)
		return;
	rc = task->task_handler(task->udata, &error);
	if (!rc) {
		ERROR("Failed to execute task=[%s]: %s", task->id, gerror_get_message(error));
		task->busy = FALSE;
	}
	if (error)
		g_clear_error(&error);
}

void
exec_tasks(void)
{
	GList *list_of_keys, *l;
	long now;

	if (!task_scheduler_running) {
		DEBUG("The task_scheduler has been stopped");
		return;
	}

	now = time(NULL);
	global_next_schedule = now + MAX_SCHEDULE_PERIOD;
	list_of_keys = g_hash_table_get_keys(tasks);
	for (l=list_of_keys; l ;l=l->next) {
		task_t *task = g_hash_table_lookup(tasks, l->data);

		if (IS_TASK_READY(task)) {	/* This task needs to be executed */

			/* Build the next schedule */
			task->next_schedule += task->period;

			/* Check that task is not already executed, and if the
			 * task is detected busy it won't be destroyed because
			 * of the continue statement */
			if (task->busy) {
				WARN("Task [%s] is busy (still executed), waiting next schedule", task->id);
				continue;
			}

			task->busy = TRUE;

			/* Avoid schedule starvation (force next_schedule in 1 sec) */
			if (task->next_schedule <= now)
				task->next_schedule = now + 1;

			if (task->next_schedule < global_next_schedule)
				global_next_schedule = task->next_schedule;

			exec_scheduled_tasks(task);
		}
		if (task->flag_destroy)
			g_hash_table_remove(tasks, l->data);
		else if (task->next_schedule < global_next_schedule)
			global_next_schedule = task->next_schedule;
	}
	g_list_free(list_of_keys);
}

void
clean_task_scheduler(void)
{
	if (task_scheduler_running)
		ALERT("Warning, the task scheduler is still running. The GridStorage team hopes you know what you are doing...");
	if (tasks) {
		g_hash_table_destroy(tasks);
		tasks = NULL;
	}
}

long
get_time_to_next_task_schedule(void)
{
	long next;

	next = global_next_schedule - time(NULL);

	TRACE("Next schedule in %li sec", next);

	return (next);
}

void
task_stop(const char *id)
{
	task_t *task;
	TRACE_POSITION();
	task = g_hash_table_lookup(tasks, id);
	if (task != NULL)
		task->flag_destroy = TRUE;
}

void
task_done(const char *id)
{
	task_t *task;
	TRACE_POSITION();
	task = g_hash_table_lookup(tasks, id);
	if (task != NULL)
		task->busy = FALSE;
}

gboolean
is_task_scheduled(const char *id)
{

	if (g_hash_table_lookup(tasks, id))
		return (TRUE);
	else
		return (FALSE);

}

int
list_tasks_worker(worker_t * worker, GError ** error)
{
	struct bulk_s {
		char id[MAX_TASKID_LENGTH];
		long next_schedule;
		gboolean busy;
		gchar last[];
	} bulk;
	GHashTableIter iter;
	gpointer k, v;

	TRACE_POSITION();

	GByteArray *gba = g_byte_array_new();
	g_hash_table_iter_init(&iter, tasks);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		task_t *t;
		if (!(t = v))
			continue;
		memset(&bulk, 0, sizeof(bulk));
		g_strlcpy(bulk.id, t->id, sizeof(bulk.id));
		bulk.next_schedule = t->next_schedule;
		bulk.busy = t->busy;
		g_byte_array_append(gba, (guint8*)&bulk, offsetof(struct bulk_s, last));
	}

	return __respond(worker, 1, gba, error);
}

task_t*
create_task(long period, const gchar *id)
{
	task_t *task;
	TRACE_POSITION();
	task = g_try_malloc0(sizeof(task_t));
	if (!task)
		abort();
	task->period = period;
	task->id = g_strdup(id);
	return task;
}

task_t*
set_task_callbacks(task_t *task, task_handler_f handle, GDestroyNotify clean, gpointer udata)
{
	task->task_handler = handle;
	if (task->udata && task->clean_udata)
		task->clean_udata(task->udata);
	task->udata = udata;
	task->clean_udata = clean;
	return task;
}


