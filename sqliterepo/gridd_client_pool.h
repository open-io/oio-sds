/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__metautils__lib__gridd_client_pool_h
# define OIO_SDS__metautils__lib__gridd_client_pool_h 1

# include <glib.h>

struct gridd_client_s;
struct election_manager_s;

struct event_client_s;

struct gridd_client_pool_s;

typedef void (*gridd_client_end_f) (struct event_client_s*);

/* "abstract" structure destined to be extended by the implementor.
 * The "client" will react to network events (with a hook passed upon its
 * creation, and that hook is responsible to callback the upper layer of the
 * application. */
struct event_client_s
{
	struct gridd_client_s *client;
	gridd_client_end_f on_end;

	/* when should the command enter the queue? after that, the command result
	 * will be an error, and there won't even be a connection for it. */
	gint64 deadline_start;

	gsize struct_size;

	/* hidden abstract fields */
};

struct gridd_client_pool_s * gridd_client_pool_create(void);

void gridd_client_pool_destroy(struct gridd_client_pool_s *p);

void gridd_client_pool_notify(struct gridd_client_pool_s *p);

void gridd_client_pool_defer(struct gridd_client_pool_s *p, struct event_client_s *ev);

GError * gridd_client_pool_round(struct gridd_client_pool_s *p, time_t sec);

void gridd_client_pool_reconfigure(struct gridd_client_pool_s *p);

/* Should not be used on an event that has already been defered. Because this
 * will be called by the gridd_client_pool. */
void event_client_free(struct event_client_s *ec);

#endif /*OIO_SDS__metautils__lib__gridd_client_pool_h*/
