#ifndef HTTP_REQUEST_WORKER_H
#define HTTP_REQUEST_WORKER_H

#include <metautils/lib/metatypes.h>
#include <cluster/agent/worker.h>

typedef struct http_session_s {
	addr_info_t *addr;
	enum {E_GET, E_POST} method;
	char *url;
	char *body;
	worker_t *worker;
	worker_func_f response_handler;
	worker_func_f error_handler;
} http_session_t;

int http_request_worker(worker_t *worker, GError **error);

#endif	/* HTTP_REQUEST_WORKER_H */
