#ifndef GRID__tash_h
# define GRID__tash_h 1
# include <glib.h>

// Object style API

typedef guint task_period_t;

struct grid_task_queue_s;

struct grid_task_queue_s* grid_task_queue_create(const gchar *name);

void grid_task_queue_stop(struct grid_task_queue_s *gtq);

void grid_task_queue_destroy(struct grid_task_queue_s *gtq);

guint grid_task_queue_sleepticks(struct grid_task_queue_s *gtq);

void grid_task_queue_fire(struct grid_task_queue_s *gtq);

void grid_task_queue_register(struct grid_task_queue_s *gtq,
		task_period_t period, GDestroyNotify run, GDestroyNotify cleanup,
		gpointer udata);

/**
 * When the thread is joined, 'gtq' is returned.
 *
 * @param gtq
 * @param err
 * @return
 */
GThread* grid_task_queue_run(struct grid_task_queue_s *gtq, GError **err);

// Static API suitable in most cases

#endif // GRID__tash_h
