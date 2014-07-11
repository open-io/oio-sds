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
static volatile time_t global_last_schedule = 0;

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
	global_last_schedule = 0;
}

void
stop_task_scheduler(void)
{
	task_scheduler_running = FALSE;
}

int
add_task_to_schedule(task_t * task, GError ** error)
{
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

	task->next_schedule = global_last_schedule + 1;

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
exec_tasks(void)
{
	if (!task_scheduler_running) {
		DEBUG("The task_scheduler has been stopped");
		return;
	}

	time_t now = time(NULL);
	gboolean rolled = now < global_last_schedule;

	GList *list_of_keys = g_hash_table_get_keys(tasks);
	for (GList *l=list_of_keys; l ;l=l->next) {
		task_t *task = g_hash_table_lookup(tasks, l->data);

		if (rolled || now >= task->next_schedule) {
			task->next_schedule = now + task->period;
			if (task->busy)
				WARN("Task [%s] is busy", task->id);
			else {
				task->busy = TRUE;
				exec_scheduled_tasks(task);
			}
		}

		if (task->flag_destroy)
			g_hash_table_remove(tasks, l->data);
	}
	g_list_free(list_of_keys);

	global_last_schedule = now;
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
	return time(NULL) <= global_last_schedule;
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
		long next_schedule;
		gboolean busy;
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
		bulk.next_schedule = t->next_schedule;
		bulk.busy = t->busy;
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

