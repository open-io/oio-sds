#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <glib.h>
#include <cluster/agent/gridagent.h>
#include <cluster/agent/worker.h>

/**
  *     Parse a message to find cmd and arg
  *
 */
int read_request_from_message(message_t *message, request_t *req, GError **error);

int __respond (worker_t *worker, int ok, GByteArray *content, GError **error);

int __respond_message (worker_t *worker, int ok, const char *msg, GError **error);

int __respond_error(worker_t *worker, GError *e, GError **error);

void message_clean(message_t *message);

void request_clean(request_t *request);

void message_cleanup(worker_t *worker);

void request_cleanup(worker_t *worker);

#endif	/* _MESSAGE_H */
