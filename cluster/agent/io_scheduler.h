#ifndef _IO_SCHEDULER_H
#define _IO_SCHEDULER_H

#include <sys/epoll.h>
#include <glib.h>
#include <cluster/agent/worker.h>

/**
  *	Init the io scheduler
  *
 */
int init_io_scheduler(GError **error);

/**
  *	Start the network io subsystem
  *
 */
void launch_io_scheduler(void);

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
