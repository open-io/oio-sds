/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include "metautils.h"

struct grid_task_s
{
	task_period_t next;
	task_period_t period;
	GDestroyNotify run;
	GDestroyNotify cleanup;
	gpointer u;
};

struct grid_task_queue_s
{
	gchar *name;
	gboolean stopped;
	task_period_t current;
	GArray *tasks;
};

struct grid_task_queue_s*
grid_task_queue_create(const gchar *name)
{
	EXTRA_ASSERT(name != NULL);

	struct grid_task_queue_s *gtq;
	gtq = g_malloc0(sizeof(struct grid_task_queue_s));
	gtq->name = g_strdup(name);
	gtq->tasks = g_array_new(TRUE, TRUE, sizeof(struct grid_task_s));
	return gtq;
}

static void
_cleanup(struct grid_task_queue_s *gtq)
{
	while (gtq->tasks->len > 0) {
		struct grid_task_s *task = &g_array_index(gtq->tasks, struct grid_task_s, 0);
		if (task->cleanup)
			task->cleanup(task->u);
		g_array_remove_index_fast(gtq->tasks, 0);
	}
}

void
grid_task_queue_destroy(struct grid_task_queue_s *gtq)
{
	if (!gtq)
		return;
	if (gtq->tasks) {
		_cleanup(gtq);
		g_array_free(gtq->tasks, TRUE);
		gtq->tasks = NULL;
	}
	if (gtq->name) {
		g_free(gtq->name);
		gtq->name = NULL;
	}
	g_free(gtq);
}

void
grid_task_queue_stop(struct grid_task_queue_s *gtq)
{
	EXTRA_ASSERT(gtq != NULL);
	gtq->stopped = TRUE;
}

void
grid_task_queue_fire(struct grid_task_queue_s *gtq)
{
	guint i, max;
	task_period_t current;

	EXTRA_ASSERT(gtq != NULL);
	EXTRA_ASSERT(gtq->tasks != NULL);
	current = gtq->current ++;

	for (i=0,max=gtq->tasks->len; i<max ;i++) {
		struct grid_task_s *task = &g_array_index(gtq->tasks, struct grid_task_s, i);
		if (task->next == current) {
			if (task->run)
				task->run(task->u);
			task->next = current + task->period;
		}
	}
}

void
grid_task_queue_register(struct grid_task_queue_s *gtq, task_period_t period,
		GDestroyNotify run, GDestroyNotify cleanup, gpointer udata)
{
	EXTRA_ASSERT(gtq != NULL);
	EXTRA_ASSERT(gtq->tasks != NULL);

	struct grid_task_s task;
	task.next = gtq->current;
	task.period = period;
	task.run = run;
	task.cleanup = cleanup;
	task.u = udata;

	g_array_append_vals(gtq->tasks, &task, 1);
}

static gpointer
_gtq_worker(gpointer p)
{
	metautils_ignore_signals();

	struct grid_task_queue_s *gtq = p;
	GRID_DEBUG("TaskQueue started [%s]", gtq->name);

	while (!gtq->stopped) {
		g_usleep(G_USEC_PER_SEC);
		grid_task_queue_fire(gtq);
	}

	GRID_DEBUG("TaskQueue exiting [%s]", gtq->name);
	return gtq;
}

GThread*
grid_task_queue_run(struct grid_task_queue_s *gtq, GError **err)
{
	return g_thread_try_new("queue", _gtq_worker, gtq, err);
}

