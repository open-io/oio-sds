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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.task_scheduler"
#endif

#include <stdlib.h>
#include <time.h>
#include <string.h>

#include <metautils/lib/metautils.h>

#include "agent.h"
#include "task_scheduler.h"
#include "task.h"
#include "gridagent.h"
#include "message.h"

static gboolean task_scheduler_running = TRUE;
static GHashTable *tasks = NULL;
static gint64 next_schedule = 0;

static gint64
task_first_schedule (void)
{
	gpointer k, v;
	GHashTableIter iter;
	gint64 next = G_MAXINT64;
	g_hash_table_iter_init(&iter, tasks);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		task_t *t = v;
		next = MIN(t->next_schedule, next);
	}
	return next;
}

static void
task_set_next_schedule (task_t *t, gint64 when)
{
	gint64 mod = when % 10;
	t->next_schedule = when + (mod>0 ? (10 - mod) : 0);
}

static void
task_cleaner(gpointer p)
{
	task_t *task = p;
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
}

void
stop_task_scheduler(void)
{
	task_scheduler_running = FALSE;
}

int
add_task_to_schedule(task_t * task, GError ** error)
{
	EXTRA_ASSERT (task != NULL);

	if (!task_scheduler_running) {
		GSETERROR(error,"The task scheduler has been stopped!");
		return 0;
	}

	if (g_hash_table_lookup(tasks, task->id)) {
		GSETERROR(error, "A task already exists for this id [%s]", task->id);
		return (0);
	}

	task_set_next_schedule(task, 0);
	g_hash_table_insert(tasks, task->id, task);
	return (1);
}

void
remove_task(const char *task_id)
{
	g_hash_table_remove(tasks, task_id);
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
exec_tasks (gint64 now)
{
	if (now <= next_schedule)
		return;

	if (!task_scheduler_running) {
		DEBUG("The task_scheduler has been stopped");
		return;
	}

	gboolean fired = FALSE;

	GList *list_of_keys = g_hash_table_get_keys(tasks);
	for (GList *l=list_of_keys; l ;l=l->next) {
		task_t *task = g_hash_table_lookup(tasks, l->data);

		if (now >= task->next_schedule) {
			/* advance the task */
			if (task->busy)
				task_set_next_schedule(task, now + 1000);
			else
				task_set_next_schedule(task, now + (task->period * 1000));

			/* then execute it */
			if (task->busy)
				WARN("Task [%s] is busy", task->id);
			else {
				fired = task->busy = TRUE;
				exec_scheduled_tasks(task);
			}
		}

		if (task->flag_destroy)
			g_hash_table_remove(tasks, l->data);
	}
	g_list_free(list_of_keys);

	if (fired)
		next_schedule = task_first_schedule ();
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

gint64
time_to_next_timed_out_task (gint64 now)
{
	if (now >= next_schedule)
		next_schedule = task_first_schedule();
	return (next_schedule < now) ? 0 : (next_schedule - now);
}

void
task_stop(const char *id)
{
	task_t *task = g_hash_table_lookup(tasks, id);
	if (task != NULL)
		task->flag_destroy = TRUE;
}

void
task_done(const char *id)
{
	task_t *task = g_hash_table_lookup(tasks, id);
	if (task != NULL)
		task->busy = FALSE;
}

gboolean
is_task_scheduled(const char *id)
{
	return NULL != g_hash_table_lookup(tasks, id);
}

int
list_tasks_worker(worker_t * worker, GError ** error)
{
	struct bulk_s {
		char id[MAX_TASKID_LENGTH];
		gint64 period;
		guint8 busy;
		// used to compute the length of the structure without padding, with
		// the help of offsetof().
		gchar last[];
	} bulk;
	GHashTableIter iter;
	gpointer k, v;

	GByteArray *gba = g_byte_array_new();
	g_hash_table_iter_init(&iter, tasks);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		task_t *t;
		if (!(t = v))
			continue;
		memset(&bulk, 0, sizeof(bulk));
		g_strlcpy(bulk.id, t->id, sizeof(bulk.id));
		bulk.period = t->period;
		bulk.busy = BOOL(t->busy);
		g_byte_array_append(gba, (guint8*)&bulk, offsetof(struct bulk_s, last));
	}

	return __respond(worker, 1, gba, error);
}

task_t*
create_task(long period, const gchar *id)
{
	task_t *task = g_malloc0(sizeof(task_t));
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

