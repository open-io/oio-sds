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

#ifndef OIO_SDS__metautils__lib__gridd_client_h
# define OIO_SDS__metautils__lib__gridd_client_h 1

# include <glib.h>
# include "metautils.h"

struct gridd_client_s;
struct gridd_client_factory_s;

struct addr_info_s;

enum client_interest_e
{
	CLIENT_RD = 0x01,
	CLIENT_WR = 0x02
};

/* Return TRUE to notify the reply management failed. */
typedef gboolean (*client_on_reply)(gpointer ctx, MESSAGE reply);

/* Destroy the gridd_client pointed by `self` and free all the linked memory */
void gridd_client_free (struct gridd_client_s *self);

/* Connect the gridd_client_s `self`to the network endpoint `u` (TCP) */
GError * gridd_client_connect_url (struct gridd_client_s *self, const gchar *u);

/* Configure the gridd_client_s `self` to send the request in
 * `req` and call `cb` upon each reply */
GError * gridd_client_request (struct gridd_client_s *self, GByteArray *req,
		gpointer ctx, client_on_reply cb);

/* Returns a copy of the last error that occured. */
GError * gridd_client_error (struct gridd_client_s *self);

/* Tells which among client_interest_e is to be monitored */
int gridd_client_interest (struct gridd_client_s *self);

/* Returns the last URL the gridd_client connected to */
const gchar * gridd_client_url (struct gridd_client_s *self);

/* Returns the file descriptor currently used by `self` */
int gridd_client_fd (struct gridd_client_s *self);

/* Force the file descriptor in `fd` to be used by `self` */
GError * gridd_client_set_fd(struct gridd_client_s *self, int fd);

/* Force the global timeout for the operation (all the request, including
 * the redirections */
void gridd_client_set_timeout (struct gridd_client_s *self, gdouble seconds);

/* Force the connection timeout for each unit request */
void gridd_client_set_timeout_cnx (struct gridd_client_s *self, gdouble sec);

/* Returns if the client's last change is older than 'now' */
gboolean gridd_client_expired(struct gridd_client_s *self, gint64 now);

/* Returns FALSE if the client is still expecting events */
gboolean gridd_client_finished (struct gridd_client_s *self);

/* Initiate the request */
gboolean gridd_client_start (struct gridd_client_s *self);

/* If expired() is true, sets the internal error and mark the client
 * as failed */
gboolean gridd_client_expire (struct gridd_client_s *self, gint64 now);

/* Manage the events raised */
void gridd_client_react (struct gridd_client_s *self);

/* Gives the ownership of `why` to the gridd_client_s `self` */
void gridd_client_fail (struct gridd_client_s *self, GError *why);

/* Instanciate a client with the default VTABLE */
struct gridd_client_s * gridd_client_create_empty(void);

/* Only works with clients of the default type */
void gridd_client_no_redirect (struct gridd_client_s *c);

/* Only works with clients of the default type */
void gridd_client_set_avoidance (struct gridd_client_s *c, gboolean on);

/* Only works with clients of the default type */
void gridd_client_set_keepalive(struct gridd_client_s *self, gboolean on);

/* ------------------------------------------------------------------------- */

/* If that list of peers odwn is not periodically refreshed, it ends up with
 * a set of blocked peers */
void gridd_client_learn_peers_down(const char * const * peers);

#endif /*OIO_SDS__metautils__lib__gridd_client_h*/
