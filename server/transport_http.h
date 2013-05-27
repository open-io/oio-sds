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

/**
 * @file transport_http.h
 */

#ifndef GRID__TRANSPORT_HTTP__H
# define GRID__TRANSPORT_HTTP__H 1
# include "./slab.h"

/**
 * @defgroup server_transhttp HTTP features
 * @ingroup server
 * @brief
 * @details
 * @{
 */

/* Avoids an include */
struct network_client_s;

/* Hidden type, internally defined */
struct http_request_dispatcher_s;

/**
 *
 */
struct http_request_s
{
	struct network_client_s *client;
	void (*notify_body) (struct http_request_s *);

	/* unpacked request line */
	gchar *cmd;
	gchar *req_uri;
	gchar *version;
	/* unpacked 'request' */
	gchar *path;
	gchar **args;
	/* all the headers mapped as <hstr(name),value> */
	GTree *tree_headers;

	/* Request's headers of interest */
	struct {
		gchar body_chunked;
		gchar connection_keepalive;
		guint64 content_length;
		struct {
			gchar present;
			guint64 start;
			guint64 end;
		} range;
	} req_headers;
};

/**
 *
 */
struct http_reply_ctx_s
{
	void (*set_status) (int code, const gchar *msg);
	void (*add_header) (const gchar *name, GString *value);
	void (*send_headers) (void);

	void (*set_inlined) (guint64 size);
	void (*set_chunked) (void);

	void (*chunk_send_gba)(GByteArray *gba);
	void (*chunk_send_file)(int fd);
	void (*chunk_last)(void);
};

/**
 *
 */
struct http_request_descr_s
{
	const gchar *name;

	gboolean (*matcher)(gpointer u,
			struct http_request_s *request);

	gboolean (*handler)(gpointer u,
			struct http_request_s *request,
			struct http_reply_ctx_s *reply);
};


/**
 * Associates the given client to the given request dispatcher into
 * a transport object.
 *
 * @param dispatcher
 * @param client
 */
void transport_http_factory0(struct http_request_dispatcher_s *dispatcher,
		struct network_client_s *client);


/**
 * Wrapper over transport_http_factory0() to provide a factory function,
 * without having to cast transport_http_factory0().
 *
 * @see transport_http_factory0()
 * @param dispatcher
 * @param client
 */
static inline void
transport_http_factory(gpointer dispatcher, struct network_client_s *client)
{
	transport_http_factory0(dispatcher, client);
}


/**
 * @param d
 */
void http_request_dispatcher_clean(struct http_request_dispatcher_s *d);


/**
 * @param u
 * @param descr
 * @return
 */
struct http_request_dispatcher_s * transport_http_build_dispatcher(
		gpointer u, const struct http_request_descr_s *descr);


/**
 * @param req
 * @param n
 * @return
 */
const gchar * http_request_get_header(struct http_request_s *req,
		const gchar *n);


/** @} */

#endif /* GRID__TRANSPORT_HTTP__H */
