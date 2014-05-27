#ifndef _WRITE_MESSAGE_WORKER_H
#define _WRITE_MESSAGE_WORKER_H

#include <cluster/agent/worker.h>

/**
  *	The default worker for handling message
  *
 */
int write_message_worker(worker_t *worker, GError **error);

#endif		/* _WRITE_MESSAGE_WORKER_H */
