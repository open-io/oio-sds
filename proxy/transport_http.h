/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__proxy__transport_http_h
# define OIO_SDS__proxy__transport_http_h 1

# include <server/slab.h>

/* Avoids an include */
struct network_client_s;

struct http_request_s
{
	struct network_client_s *client;

	/* unpacked request line */
	gchar *cmd;
	gchar *req_uri;
	gchar *version;

	/* all the headers mapped as <gchar*,gchar*> */
	GTree *tree_headers;
	GByteArray *body;
};

struct http_reply_ctx_s
{
	void (*set_status) (int code, const gchar *msg);
	void (*set_content_type)(const gchar *type);
	void (*add_header) (const gchar *name, gchar *v);
	void (*add_header_gstr) (const gchar *name, GString *value);
	void (*set_body_gstr) (GString *gstr);
	void (*set_body_bytes) (GBytes *bytes);

	void (*subject) (const char *id);
	void (*finalize) (void);
	void (*access_tail) (const char *fmt, ...);
	void (*no_access) (void);
};

enum http_rc_e { HTTPRC_DONE, HTTPRC_ABORT };

typedef enum http_rc_e (*http_handler_f) (struct http_request_s *request,
			struct http_reply_ctx_s *reply);

/** Associates the given client to the given request handler, into
 * a transport object. */
void transport_http_factory0 (http_handler_f handler,
		struct network_client_s *client);

#endif /*OIO_SDS__proxy__transport_http_h*/
