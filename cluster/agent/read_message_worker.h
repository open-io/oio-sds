#ifndef _READ_MESSAGE_WORKER_H
#define _READ_MESSAGE_WORKER_H

#include <cluster/agent/worker.h>

/**
  *	The default worker for handling message
  *
 */
int read_message_size_worker(worker_t *worker, GError **error);

int read_message_data_worker(worker_t *worker, GError **error);

#endif		/* _READ_MESSAGE_WORKER_H */
