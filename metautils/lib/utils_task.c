#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.task"
#endif

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
	g_assert(name != NULL);

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
	g_assert(gtq != NULL);
	gtq->stopped = TRUE;
}

guint
grid_task_queue_sleepticks(struct grid_task_queue_s *gtq)
{
	g_assert(gtq != NULL);
	g_assert(gtq->tasks != NULL);

	if (!gtq->tasks->len)
		return 0;

	register struct grid_task_s *task;
	register task_period_t next;

	task = &g_array_index(gtq->tasks,struct grid_task_s, 0);
	next = task->next;

	for (register guint i=1; i < gtq->tasks->len ;++i) {
		task = &g_array_index(gtq->tasks, struct grid_task_s, i);
		register task_period_t t = task->next;
		next = MIN(next, t);
	}

	return next;
}

void
grid_task_queue_fire(struct grid_task_queue_s *gtq)
{
	guint i, max;
	task_period_t current;

	g_assert(gtq != NULL);
	g_assert(gtq->tasks != NULL);
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
	g_assert(gtq != NULL);
	g_assert(gtq->tasks != NULL);

	struct grid_task_s task;
	task.next = gtq->current;
	task.period = period;
	task.run = run;
	task.cleanup = cleanup;
	task.u = udata;

	g_array_append_vals(gtq->tasks, &task, 1);
}

struct gtq_args_s
{
	GTimeVal period_duration;
	struct grid_task_queue_s *gtq;
};

static gpointer
_gtq_worker(gpointer p)
{
	struct gtq_args_s *parg = p;

	metautils_ignore_signals();

	// extract variables
	GTimeVal period;
	struct grid_task_queue_s *gtq = parg->gtq;
	period = parg->period_duration;
	g_free(parg);

	GRID_DEBUG("TaskQueue started [%s]", gtq->name);

	while (!gtq->stopped) {
		g_usleep(period.tv_sec * G_USEC_PER_SEC + period.tv_usec);
		grid_task_queue_fire(gtq);
	}

	GRID_DEBUG("TaskQueue exiting [%s]", gtq->name);
	return gtq;
}

GThread*
grid_task_queue_run(struct grid_task_queue_s *gtq, GError **err)
{
	struct gtq_args_s args, *p;
	GThread *th;

	args.period_duration.tv_sec = 1;
	args.period_duration.tv_usec = 0;
	args.gtq = gtq;
	p = g_memdup(&args, sizeof(struct gtq_args_s));

	th = g_thread_create(_gtq_worker, p, TRUE, err);
	if (NULL != th)
		return th;

	g_free(p);
	return NULL;
}

