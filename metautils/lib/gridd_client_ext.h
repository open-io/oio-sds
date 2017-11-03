/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__gridd_client_ext_h
# define OIO_SDS__metautils__lib__gridd_client_ext_h 1

# include "metautils.h"
# include "gridd_client.h"

struct gridd_client_s;

/* Wrappers for single clients --------------------------------------------- */

// Wraps .interest(), .get_fd(), .react() and poll()
GError* gridd_client_step(struct gridd_client_s *p);

// Wrap a loop on step() until finished() or error().
GError* gridd_client_loop(struct gridd_client_s *client);

// Wraps create_empty() and connect_url()
struct gridd_client_s * gridd_client_create_idle(const char *target);

// Wraps create_idle() and request()
struct gridd_client_s * gridd_client_create(const char *target,
		GByteArray *req, gpointer ctx, client_on_reply cb);

/* wraps start(), loop() and error() */
GError * gridd_client_run (struct gridd_client_s *self);

/* wraps crate(), run(), free() */
GError * gridd_client_exec4 (const char *to, gdouble timeout, GByteArray *req,
		GByteArray ***replies);

/* wraps gridd_client_exec4() */
GError * gridd_client_exec (const char *to, gdouble timeout, GByteArray *req);

/* wraps gridd_client_exec4() and decode each bodies as a sequence */
GError * gridd_client_exec_and_decode (const char *to, gdouble timeout,
		GByteArray *req, GSList **out, body_decoder_f decoder);

/* wraps gridd_client_exec4() and concat the bodies */
GError * gridd_client_exec_and_concat (const char *to, gdouble timeout,
		GByteArray *req, GByteArray **out);

/* wraps gridd_client_exec_and_concat() */
GError * gridd_client_exec_and_concat_string (const char *to, gdouble timeout, GByteArray *req,
		gchar **out);

/* Implementation specifics / array of structures -------------------------- */

// @return NULL if one of the subsequent client creation fails
struct gridd_client_s ** gridd_client_create_many(gchar **targets,
		GByteArray *request, gpointer ctx, client_on_reply cb);

// Cleans everything allocated by gridd_client_create_many()
void gridd_clients_free(struct gridd_client_s **clients);

// Calls set_timeout() on each pointed client
void gridd_clients_set_timeout(struct gridd_client_s **clients, gdouble seconds);

// Calls set_timeout_cnx() on each pointed client
void gridd_clients_set_timeout_cnx(struct gridd_client_s **clients, gdouble sec);

// Returns FALSE if at least finished() returns FALSE for at least one client
gboolean gridd_clients_finished(struct gridd_client_s **clients);

// Return the first non-NULL return of each call to error()
GError * gridd_clients_error(struct gridd_client_s **clients);

// Trigger a start on each client
void gridd_clients_start(struct gridd_client_s **clients);

// Poll for network events (using poll()), and call gridd_client_react()
// if a non-error event occured.
GError * gridd_clients_step(struct gridd_client_s **clients);

// Wraps gridd_clients_step() and gridd_clients_finished()
GError * gridd_clients_loop(struct gridd_client_s **clients);

gdouble oio_clamp_timeout(gdouble timeout, gint64 deadline);

gint64 oio_clamp_deadline(gdouble timeout, gint64 deadline);

#endif /*OIO_SDS__metautils__lib__gridd_client_ext_h*/
