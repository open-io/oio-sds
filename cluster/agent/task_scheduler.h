#ifndef _TASK_SCHEDULER_H
#define _TASK_SCHEDULER_H

#include <glib.h>
#include <cluster/agent/task.h>

void init_task_scheduler(void);

void stop_task_scheduler(void);

void clean_task_scheduler(void);

int add_task_to_schedule(task_t * task, GError ** error);

void remove_task(const char *task_id);

void exec_tasks(void);

long get_time_to_next_task_schedule(void);

void task_done(const char *id);

void task_stop(const char *id);

gboolean is_task_scheduled(const char *id);

task_t* create_task(long frequency, const gchar *id);

task_t* set_task_callbacks(task_t *task, task_handler_f handle,
		GDestroyNotify clean, gpointer udata);

/* ------------------------------------------------------------------------- */

int list_tasks_worker(worker_t * worker, GError ** error);

#endif /* _TASK_SCHEDULER_H */
