/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#ifndef OIO_SDS__cluster__lib__message_h
# define OIO_SDS__cluster__lib__message_h 1

#include <glib.h>
#include <cluster/agent/gridagent.h>

/* Build a message with the given request */
int read_response_from_message(response_t *response, message_t *message, GError **error);

/* Parse response from message */
int build_message_from_request(message_t *message, request_t *request, GError **error);

int send_request(request_t *req, response_t *resp, GError **error);

/* Opens a non-blocking socket to the gridagent */
int gridagent_connect(GError ** error);

/* Check if the gridagent's socket is present */
gboolean gridagent_available(void);

#endif /*OIO_SDS__cluster__lib__message_h*/