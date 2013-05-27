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

#ifndef _IO_STAT_TASK_WORKER_H
#define _IO_STAT_TASK_WORKER_H

#include <glib.h>
#include "worker.h"

typedef struct disk_stat_s {
	unsigned long reads;		// # of reads issued
	unsigned long read_merged;	// # of reads merged
	unsigned long read_sectors;	// # of sectors read
	unsigned long read_time;	// # of milliseconds spent reading
	unsigned long writes;		// # of writes completed
	unsigned long write_merged;	// # of writes merged
	unsigned long write_sectors;	// # of sectors written
	unsigned long write_time;	// # of milliseconds spent writing
	unsigned long io_in_progress;	// # of I/Os currently in progress
	unsigned long io_time;		// # of milliseconds spent doing I/Os
	unsigned long w_io_time;	// weighted # of milliseconds spent doing I/Os
} disk_stat_t;

struct io_stat_s {
	struct timeval previous_time;
	disk_stat_t previous;
	struct timeval current_time;
	disk_stat_t current;
};

int start_io_stat_task(GError **error);

int get_io_idle_for_device(const char *device, int *idle, GError **error);

int get_io_idle_for_path(const char *path, int *idle, GError **error);

gboolean get_device_from_path(const char *path_name, char *device_name, size_t device_name_size, GError **error);

#endif	/* _IO_STAT_TASK_WORKER_H */
