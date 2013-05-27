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

#ifndef _CPU_STAT_TASK_WORKER_H
#define _CPU_STAT_TASK_WORKER_H

#include <glib.h>
#include "worker.h"

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
