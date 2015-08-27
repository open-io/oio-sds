/*
OpenIO SDS server
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

#ifndef OIO_SDS__server__transport_gridd_h
# define OIO_SDS__server__transport_gridd_h 1

# include <glib.h>

# ifndef INNER_STAT_NAME_REQ_COUNTER
#  define INNER_STAT_NAME_REQ_COUNTER "gridd.counter.allreq"
# endif

# ifndef INNER_STAT_NAME_REQ_TIME
#  define INNER_STAT_NAME_REQ_TIME "gridd.counter.alltime"
# endif

/* Forward declarations externally defined */
struct network_client_s;
struct network_transport_s;

/* Hidden structures internally definied */
struct gridd_request_dispatcher_s;
struct grid_stats_holder_s;

/**
 * Given to the request dispatcher, it allows him to reply to
 * the client.
 */
struct gridd_reply_ctx_s
{
	void (*add_header) (const gchar *name, GByteArray *value);
	
	void (*add_body)   (GByteArray *body);

	void (*send_reply) (gint code, gchar *message);
	
	void (*send_error) (gint code, GError *err);

	void (*subject) (const gchar *fmt, ...);

	void (*uid) (const gchar *fmt, ...);

	void (*register_cnx_data) (const gchar *key, gpointer data,
			GDestroyNotify cleanup);

	/* Dissociates the data or does nothing if data not present */
	void (*forget_cnx_data) (const gchar *key);

	/* Return a data previously associated, or NULL if not found. */
	gpointer (*get_cnx_data) (const gchar *key);

	/* Provide access to the network layer */
	struct network_client_s *client;

	/* ASN.1 request decoded */
	MESSAGE request;

	/* extracted from the request */
	const struct hashstr_s *reqname;
};

/* Describes a request that can be managed by a GRIDD. */
struct gridd_request_descr_s
{
	/** The choice has been made to identify a request by its name,
	 * and not a pattern (as in the legacy gridd). This helps building
	 * a more efficient structure to match  */
	const gchar *name;

	/** How to manage this request.
	 * @param handler_data the arbitrary pointer registered with the request only
	 * @param group_data the arbitrary pointer registered with the request set
	 * @param reply all the callbacks to manage the replies flow
	 * @return FALSE in case of an error strong enough to require closing
	 *         the connection. A TRUE value if the connection might be
	 *         kept open.
	 */
	gboolean (*handler) (struct gridd_reply_ctx_s *reply,
			gpointer group_data, gpointer handler_data);

	gpointer handler_data;
};

/* Adds support for a requests to the given gridd_dispatcher. */
GError *
transport_gridd_dispatcher_add_requests(
		struct gridd_request_dispatcher_s *dispatcher,
		const struct gridd_request_descr_s *descr,
		gpointer group_data);

/* Build an optimized gridd_request dispatcher, without any request
 * configured. */
struct gridd_request_dispatcher_s * transport_gridd_build_empty_dispatcher(void);

/* Build an optimized gridd_request dispatcher, based on a set of
 * request handler descriptions.
 * Services that want to work on top of a gridd service just have to
 * provide an array of gridd_request_handler_s. */
struct gridd_request_dispatcher_s * transport_gridd_build_dispatcher(
		const struct gridd_request_descr_s *descriptions,
		gpointer u);

/* Cleans a GRIDD request dispatcher and all the internal structures
 * associated to requests.
 *
 * Obviously, please do not call this when still using the dispatcher.
 * Rather call this when no worker threads still exsist. */
void gridd_request_dispatcher_clean(struct gridd_request_dispatcher_s *disp);

/* Associates the given client to the given request dispatcher into
 * a transport object. */
void transport_gridd_factory0(struct gridd_request_dispatcher_s *disp,
		struct network_client_s *client);

/* Wrapper over transport_gridd_factory0() to provide a factory function,
 * without having to cast transport_gridd_factory0(). */
static inline void
transport_gridd_factory(gpointer dispatcher, struct network_client_s *client)
{
	return transport_gridd_factory0(dispatcher, client);
}

/* Adds zeroed stats for the given request handler.
 * Internal feature, do not use this directly unless you know what you're
 * doing! */
void gridd_register_requests_stats(struct grid_stats_holder_s *stats,
		struct gridd_request_dispatcher_s *dispatcher);

/* All these requests ignore their first argument */
const struct gridd_request_descr_s* gridd_get_common_requests(void);

#endif /*OIO_SDS__server__transport_gridd_h*/
