/*
OpenIO SDS cluster
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__cluster__agent__message_h
# define OIO_SDS__cluster__agent__message_h 1

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

#endif /*OIO_SDS__cluster__agent__message_h*/