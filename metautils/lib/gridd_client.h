/*
OpenIO SDS metautils
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

#ifndef OIO_SDS__metautils__lib__gridd_client_h
# define OIO_SDS__metautils__lib__gridd_client_h 1

# include <glib.h>
# include <sys/time.h>

/**
 * @defgroup metautils_client
 * @ingroup metautils
 * @brief
 * @details
 *
 * @{
 */

# ifndef GRIDC_DEFAULT_TIMEOUT_STEP
#  define GRIDC_DEFAULT_TIMEOUT_STEP 10.0
# endif

# ifndef GRIDC_DEFAULT_TIMEOUT_OVERALL
#  define GRIDC_DEFAULT_TIMEOUT_OVERALL 30.0
# endif

struct gridd_client_s;
struct gridd_client_factory_s;

struct message_s;
struct addr_info_s;

enum client_interest_e
{
	CLIENT_RD = 0x01,
	CLIENT_WR = 0x02
};

typedef gboolean (*client_on_reply)(gpointer ctx, struct message_s *reply);

struct gridd_client_vtable_s
{
	// Destructor
	void (*clean) (struct gridd_client_s *c);

	// Connectors
	GError* (*connect_url) (struct gridd_client_s *c, const gchar *target);
	GError* (*connect_addr) (struct gridd_client_s *c, const struct addr_info_s *a);

	// Sets the next request to be sent, and what to do with the reply.
	GError* (*request) (struct gridd_client_s *c, GByteArray *req,
			gpointer ctx, client_on_reply cb);

	// Returns a copy of the last error that occured.
	GError* (*error) (struct gridd_client_s *c);

	// Tells which among client_interest_e is to be monitored
	int (*interest) (struct gridd_client_s *c);

	// Returns the last URL we connected to
	const gchar* (*get_url) (struct gridd_client_s *c);

	// Returns the file descriptor currently used
	int (*get_fd) (struct gridd_client_s *c);

	// Force a new descriptor
	GError* (*set_fd) (struct gridd_client_s *c, int fd);

	// Tells to keep the connection open between requests.
	void (*set_keepalive) (struct gridd_client_s *c, gboolean on);

	// Force the timeout for each signel request (step), and for each request
	// and its redirections.
	void (*set_timeout) (struct gridd_client_s *c, gdouble step, gdouble overall);

	// Returns if the client's last change is older than 'now'
	gboolean (*expired) (struct gridd_client_s *c, GTimeVal *now);

	// Returns FALSE if the client is still expecting events.
	gboolean (*finished) (struct gridd_client_s *c);

	// Initiate the request.
	gboolean (*start) (struct gridd_client_s *c);

	// Manage the events raised
	void (*react) (struct gridd_client_s *c);

	// If expired() is true, sets the internal error and mark the client
	// as failed.
	void (*expire) (struct gridd_client_s *c, GTimeVal *now);

	void (*fail) (struct gridd_client_s *c, GError *why);
};

struct abstract_client_s
{
	struct gridd_client_vtable_s *vtable;
};

#define VTABLE_CHECK(self,T,F) do { \
	g_assert(self != NULL); \
	g_assert(((T)self)->vtable != NULL); \
	g_assert(((T)self)->vtable-> F != NULL); \
} while (0)

#define VTABLE_CALL(self,T,F) \
	VTABLE_CHECK(self,T,F); \
	return ((T)self)->vtable-> F

#define GRIDD_CALL(self,F) \
	VTABLE_CALL(self,struct abstract_client_s*,F)

// wrappers to the call to the vtable.
//

void gridd_client_free (struct gridd_client_s *self);
GError * gridd_client_connect_url (struct gridd_client_s *self, const gchar *u);
GError * gridd_client_connect_addr (struct gridd_client_s *self, const struct addr_info_s *a);
GError * gridd_client_request (struct gridd_client_s *self, GByteArray *req,
		gpointer ctx, client_on_reply cb);
GError * gridd_client_error (struct gridd_client_s *self);
int gridd_client_interest (struct gridd_client_s *self);
const gchar * gridd_client_url (struct gridd_client_s *self);
int gridd_client_fd (struct gridd_client_s *self);
GError * gridd_client_set_fd(struct gridd_client_s *self, int fd);
void gridd_client_set_keepalive(struct gridd_client_s *self, gboolean on);
void gridd_client_set_timeout (struct gridd_client_s *self, gdouble t0, gdouble t1);
gboolean gridd_client_expired(struct gridd_client_s *self, GTimeVal *now);
gboolean gridd_client_finished (struct gridd_client_s *self);
gboolean gridd_client_start (struct gridd_client_s *self);
void gridd_client_expire (struct gridd_client_s *self, GTimeVal *now);
void gridd_client_react (struct gridd_client_s *self);
void gridd_client_fail (struct gridd_client_s *self, GError *why);

// Instanciate a client with the default VTABLE
struct gridd_client_s * gridd_client_create_empty(void);

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

/** @} */

#endif /*OIO_SDS__metautils__lib__gridd_client_h*/
