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

#ifndef _IO_SCHEDULER_H
#define _IO_SCHEDULER_H

#include <sys/epoll.h>
#include <glib.h>

#include "worker.h"

/**
  *	Init the io scheduler
  *
 */
int init_io_scheduler(GError **error);

/**
  *	Start the network io subsystem
  *
 */
int launch_io_scheduler(GError **error);

/**
  *	Stop IO scheduler
  *
 */
void stop_io_scheduler(void);

/**
  *	Add a new fd to the polling
  *
 */
int add_fd_to_io_scheduler(worker_t *worker, __uint32_t events, GError **error);

/**
  *	Change event polled for fd
  *
 */
int change_fd_events_in_io_scheduler(worker_t *worker, __uint32_t events, GError **error);

/**
  *	Remove a fd from the polling
  *
 */
int remove_fd_from_io_scheduler(worker_t *worker, GError **error);

#endif		/* _IO_SCHEDULER_H */
