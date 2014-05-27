#ifndef _GET_NS_WORKER_H
#define _GET_NS_WORKER_H

#include <glib.h>
#include <cluster/agent/worker.h>

int get_ns_worker(worker_t *worker, GError **error);

#endif	/* _GET_NS_WORKER_H */
