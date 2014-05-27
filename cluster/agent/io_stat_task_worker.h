#ifndef _IO_STAT_TASK_WORKER_H
#define _IO_STAT_TASK_WORKER_H

#include <glib.h>

int start_io_stat_task(GError **error);

int get_io_idle_for_path(const char *path, int *idle, GError **error);

#endif	/* _IO_STAT_TASK_WORKER_H */
