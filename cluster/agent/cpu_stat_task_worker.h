#ifndef _CPU_STAT_TASK_WORKER_H
#define _CPU_STAT_TASK_WORKER_H

#include <glib.h>
#include <cluster/agent/worker.h>

typedef struct proc_stat_s {
	unsigned long long user;		// time used by processes in user mode
	unsigned long long nice;		// time used by niced processes in user mode
	unsigned long long system;		// time used by processes in kernel mode
	unsigned long long idle;		// time unused
	unsigned long long io_wait;		// time spent waiting for io to complete
	unsigned long long irq;		// time spent servicing irq
	unsigned long long soft_irq;	// time spent servicing soft irq
} proc_stat_t;

struct cpu_stat_s {
	struct timeval previous_time;
	proc_stat_t previous;
	struct timeval current_time;
	proc_stat_t current;
};

int start_cpu_stat_task(GError **error);

int get_cpu_idle(int *idle, GError **error);

#endif	/* _CPU_STAT_TASK_WORKER_H */
