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

// wrappers to the call to the vtable.

void gridd_client_free (struct gridd_client_s *self);
GError * gridd_client_connect_url (struct gridd_client_s *self, const gchar *u);
GError * gridd_client_request (struct gridd_client_s *self, GByteArray *req,
		gpointer ctx, client_on_reply cb);
GError * gridd_client_error (struct gridd_client_s *self);
int gridd_client_interest (struct gridd_client_s *self);
const gchar * gridd_client_url (struct gridd_client_s *self);
int gridd_client_fd (struct gridd_client_s *self);
GError * gridd_client_set_fd(struct gridd_client_s *self, int fd);
void gridd_client_set_timeout (struct gridd_client_s *self, gdouble seconds);
void gridd_client_set_timeout_cnx (struct gridd_client_s *self, gdouble sec);
gboolean gridd_client_expired(struct gridd_client_s *self, gint64 now);
gboolean gridd_client_finished (struct gridd_client_s *self);
gboolean gridd_client_start (struct gridd_client_s *self);
gboolean gridd_client_expire (struct gridd_client_s *self, gint64 now);
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

struct gridd_client_factory_vtable_s
{
	void (*clean) (struct gridd_client_factory_s *self);

	// Instatiates an empty client (no target, ni request).
	struct gridd_client_s* (*create) (struct gridd_client_factory_s *f);
};

struct abstract_client_factory_s
{
	struct gridd_client_factory_vtable_s *vtable;
};

#define gridd_client_factory_clean(p) \
	((struct abstract_client_factory_s*)(p))->vtable->clean(p)

#define gridd_client_factory_create_client(p) \
	((struct abstract_client_factory_s*)(p))->vtable->create(p)

// Instanciate a clients factory with the default VTABLE. This factory will
// provide clients with the same VTABLE than those created with
// gridd_client_create_empty().
struct gridd_client_factory_s * gridd_client_factory_create(void);

/* If that list of peers odwn is not periodically refreshed, it ends up with
 * a set of blocked peers */
void gridd_client_learn_peers_down(const char * const * peers);

#endif /*OIO_SDS__metautils__lib__gridd_client_h*/
