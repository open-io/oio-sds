#ifndef _MESSAGE_WORKER_H
#define _MESSAGE_WORKER_H

#include <cluster/agent/worker.h>

/**
  *	Initialize the message_worker
  *
 */
int init_request_worker(GError **error);

/**
  *	The default worker for handling message
  *
 */
int request_worker(worker_t *worker, GError **error);

#endif		/* _MESSAGE_WORKER_H */
