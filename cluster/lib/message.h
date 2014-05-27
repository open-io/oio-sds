#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <glib.h>
#include <cluster/agent/gridagent.h>

/**
  *     Build a message with the given request
  *
 */
int read_response_from_message(response_t *response, message_t *message, GError **error);

/**
  *	Parse response from message
  *
 */
int build_message_from_request(message_t *message, request_t *request, GError **error);

int send_request(request_t *req, response_t *resp, GError **error);

#endif	/* _MESSAGE_H */
