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

#ifndef _MESSAGE_H
#define _MESSAGE_H

#include <glib.h>

#include <gridagent.h>

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
