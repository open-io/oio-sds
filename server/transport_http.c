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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.transport.http"
#endif

#include <stddef.h>
#include <string.h>

#include <sys/stat.h>

#include <glib.h>

#include "./internals.h"
#include "./slab.h"
#include "./hashstr.h"
#include "./network_server.h"
#include "./stats_holder.h"
#include "./transport_http.h"

#define HTTP_REPLY_404 "HTTP/1.0 404 Not found\r\n\r\n"
#define HTTP_REPLY_500 "HTTP/1.0 500 Server internal error\r\n\r\n"
#define HTTP_REPLY_502 "HTTP/1.0 502 Bad gateway\r\n\r\n"

struct transport_client_context_s
{
	struct http_request_dispatcher_s *dispatcher;
	guint headers_offset;
	GByteArray *headers;
	struct http_request_s *current_request;
};

struct http_request_handler_s
{
	gboolean (*matcher)(gpointer u,
			struct http_request_s *request);
	gboolean (*handler)(gpointer u,
			struct http_request_s *request,
			struct http_reply_ctx_s *reply);
	gchar stat_name_req[256];
	gchar stat_name_time[256];
};

struct http_request_dispatcher_s
{
	gpointer u;
	GTree *tree_requests;
};

static int http_notify_input(struct network_client_s *clt);

static void http_request_clean(struct http_request_s *req);

GQuark gquark_log = 0;

/* -------------------------------------------------------------------------- */

void
http_request_dispatcher_clean(struct http_request_dispatcher_s *d)
{
	if (!d)
		return ;
	if (d->tree_requests)
		g_tree_destroy(d->tree_requests);
	g_free(d);
}

struct http_request_dispatcher_s *
transport_http_build_dispatcher(gpointer u,
		const struct http_request_descr_s *descr)
{
	const struct http_request_descr_s *d;
	struct http_request_dispatcher_s *dispatcher;

	dispatcher = g_malloc0(sizeof(*dispatcher));
	dispatcher->u = u;
	dispatcher->tree_requests = g_tree_new_full(
			hashstr_quick_cmpdata, NULL, g_free, g_free);

	for (d=descr; d && d->name && d->matcher && d->handler ;d++) {

		struct http_request_handler_s *h = g_malloc0(sizeof(*h));
		h->matcher = d->matcher;
		h->handler = d->handler;
		g_snprintf(h->stat_name_req, sizeof(h->stat_name_req),
			"%s.%s", HTTP_STAT_PREFIX_REQ, d->name);
		g_snprintf(h->stat_name_time, sizeof(h->stat_name_time),
			"%s.%s", HTTP_STAT_PREFIX_TIME, d->name);

		g_tree_replace(dispatcher->tree_requests, hashstr_create(d->name), h);

		GRID_DEBUG("New handler added [%s] [%p] [%p}", d->name,
				d->matcher, d->handler);
	}

	return dispatcher;
}

/* -------------------------------------------------------------------------- */

static void
http_context_clean(struct transport_client_context_s *ctx)
{
	if (!ctx)
		return;
	if (ctx->headers)
		g_byte_array_free(ctx->headers, TRUE);
	if (ctx->current_request)
		http_request_clean(ctx->current_request);
	g_free(ctx);
}

void
transport_http_factory0(struct http_request_dispatcher_s *dispatcher,
		struct network_client_s *client)
{
	struct network_transport_s *transport;
	struct transport_client_context_s *client_context;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	(void) client;

	client_context = g_malloc0(sizeof(struct transport_client_context_s));
	client_context->headers_offset = 0;
	client_context->headers = NULL;
	client_context->current_request = NULL;
	client_context->dispatcher = dispatcher;

	transport = &(client->transport);
	transport->client_context = client_context;
	transport->clean_context = http_context_clean;
	transport->notify_input = http_notify_input;
	transport->notify_error = NULL;

	network_client_allow_input(client, TRUE);
}

/* -------------------------------------------------------------------------- */

static struct http_request_s *
http_request_create(struct network_client_s *client)
{
	struct http_request_s *req;
	req = g_malloc0(sizeof(*req));
	req->client = client;
	req->tree_headers = g_tree_new_full(hashstr_quick_cmpdata,
			NULL, g_free, g_free);
	return req;
}

static void
http_request_add_header(struct http_request_s *req,
		gchar *n, const gchar *v)
{

	HTTP_ASSERT(req != NULL);
	HTTP_ASSERT(req->tree_headers != NULL);
	
	/* Normalize the header name */
	register enum { MAJUSCULE, MINUSCULE } step = MAJUSCULE;
	register gchar *p;
	for (p=n; *p ;p++) {
		if (*p == '-')
			step = MAJUSCULE;
		else switch (step) {
			case MAJUSCULE:
				*p = g_ascii_toupper(*p);
				step = MINUSCULE;
				break;
			case MINUSCULE:
				*p = g_ascii_tolower(*p);
				break;
		}
	}
	
	GRID_DEBUG("Header [%s] : [%s]", n, v);
	g_tree_replace(req->tree_headers, hashstr_create(n), g_strdup(v));
}

const gchar *
http_request_get_header(struct http_request_s *req, const gchar *n)
{
	hashstr_t *hname;

	HTTP_ASSERT(req != NULL);
	HTTP_ASSERT(req->tree_headers != NULL);

	HASHSTR_ALLOCA(hname, n);
	return g_tree_lookup(req->tree_headers, hname);
}

static void
http_request_clean(struct http_request_s *req)
{
	if (req->cmd)
		g_free(req->cmd);
	if (req->req_uri)
		g_free(req->req_uri);
	if (req->version)
		g_free(req->version);
	if (req->tree_headers)
		g_tree_destroy(req->tree_headers);
	g_free(req);
}

/* -------------------------------------------------------------------------- */

struct req_ctx_s
{
	struct network_client_s *client;
	struct network_transport_s *transport;
	struct transport_client_context_s *context;
	struct http_request_dispatcher_s *dispatcher;
	struct http_request_s *request;
};

static inline void
_reply_fixed(struct req_ctx_s *req, const gchar *whole)
{
	network_client_send_slab(
			req->context->current_request->client,
			data_slab_make_static_string(whole));

	network_client_close_output(req->context->current_request->client, 0);
	http_request_clean(req->context->current_request);
	req->context->current_request = NULL;
}

static struct http_request_handler_s*
http_get_handler(struct req_ctx_s *req_ctx)
{
	struct http_request_handler_s *result = NULL;

	gboolean finder(gpointer k, gpointer v, gpointer u) {
		struct http_request_handler_s *handler, **p_result;

		(void) k;
		handler = v;
		p_result = u;

		HTTP_ASSERT(handler->matcher != NULL);
		HTTP_ASSERT(handler->handler != NULL);
		if (!handler->matcher(req_ctx->dispatcher->u, req_ctx->request))
			return FALSE;
		*p_result = handler;
		return TRUE;
	}

	g_tree_foreach(req_ctx->dispatcher->tree_requests, finder, &result);

	if (result) {
		GRID_DEBUG("Request matched");
		return result;
	}

	GRID_DEBUG("Request matched no handler");
	return NULL;
}

static void
send_status_line(struct network_client_s *client, int code, const gchar *msg)
{
	GString *gstr = g_string_sized_new(64);
	g_string_append(gstr, "HTTP/1.0 ");
	g_string_append_printf(gstr, "%d ", code);
	g_string_append(gstr, msg);
	g_string_append(gstr, "\r\n");

	gsize l = gstr->len;
	guint8 *b = (guint8*) g_string_free(gstr, FALSE);
	network_client_send_slab(client, data_slab_make_buffer(b, l));
}

static gboolean
sender(gpointer k, gpointer v, gpointer u)
{
	struct network_client_s *client = u;
	struct hashstr_s *hname = k;

	GString *gstr = g_string_sized_new(64);
	g_string_append(gstr, hashstr_str(hname));
	g_string_append_c(gstr, ':');
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, (gchar*)v);

	gsize l = gstr->len;
	guint8 *b = (guint8*) g_string_free(gstr, FALSE);
	network_client_send_slab(client, data_slab_make_buffer(b, l));
	return FALSE;
}

static GError *
http_manage_request(struct req_ctx_s *req_ctx)
{
	struct http_request_handler_s *h;

	gboolean headers_sent = 0;
	int code = 500;
	gchar *msg = NULL;
	GTree *headers = NULL;
	enum { NOTSET, INLINED, CHUNKED } body_encoding = NOTSET;

	void set_status(int c, const gchar *m) {
		HTTP_ASSERT(!headers_sent);
		code = c;
		msg = g_strdup(m);
	}
	void add_header (const gchar *name, GString *v) {
		HTTP_ASSERT(!headers_sent);
		g_tree_replace(headers,
				hashstr_create(name),
				g_string_free(v, FALSE));
	}
	void set_inlined (guint64 size) {
		HTTP_ASSERT(!headers_sent);
		HTTP_ASSERT(body_encoding == NOTSET);
		body_encoding = INLINED;
		g_tree_replace(headers,
				hashstr_create("Trasfer-Encoding"),
				g_strdup("identity"));
		g_tree_replace(headers,
				hashstr_create("Content-Length"),
				g_strdup_printf("%"G_GUINT64_FORMAT, size));
	}
	void set_chunked (void) {
		HTTP_ASSERT(!headers_sent);
		HTTP_ASSERT(body_encoding == NOTSET);
		body_encoding = CHUNKED;
		g_tree_replace(headers,
				hashstr_create("Trasfer-Encoding"),
				g_strdup("chunked"));
		g_tree_remove(headers,
				hashstr_create("Content-Length"));
	}
	void send_headers (void) {
		HTTP_ASSERT(!headers_sent);
		send_status_line(req_ctx->client, code, msg);
		g_tree_foreach(headers, sender, req_ctx->client);
		network_client_send_slab(req_ctx->client, data_slab_make_static_string("\r\n"));
		headers_sent = TRUE;
	}
	void chunk_send_gba(GByteArray *gba) {
		(void) gba;
		HTTP_ASSERT(headers_sent);
		HTTP_ASSERT(body_encoding == CHUNKED);

		GString *gstr = g_string_sized_new(8);
		g_string_append_printf(gstr, "%X\r\n", gba->len);

		network_client_send_slab(req_ctx->client, data_slab_make_string(g_string_free(gstr, FALSE)));
		network_client_send_slab(req_ctx->client, data_slab_make_gba(gba));
		network_client_send_slab(req_ctx->client, data_slab_make_static_string("\r\n"));
	}
	void chunk_send_file(int fd) {
		struct stat64 s;

		HTTP_ASSERT(headers_sent);
		HTTP_ASSERT(body_encoding == CHUNKED);

		fstat64(fd, &s);

		network_client_send_slab(req_ctx->client,
				data_slab_make_string(	
						g_strdup_printf("%"G_GUINT64_FORMAT"\r\n", s.st_size)
				)
		);
		network_client_send_slab(req_ctx->client, data_slab_make_file(fd, 0, s.st_size));
		network_client_send_slab(req_ctx->client, data_slab_make_static_string("\r\n"));
	}
	void chunk_last(void) {
		HTTP_ASSERT(headers_sent);
		HTTP_ASSERT(body_encoding == CHUNKED);
		network_client_send_slab(req_ctx->client, data_slab_make_static_string("0\r\n"));
	}

	(void) body_encoding;
	(void) headers_sent;

	/* Sanity checks + handler location */
	if (!req_ctx->dispatcher) {
		GRID_DEBUG("No dispatcher configured");
		_reply_fixed(req_ctx, HTTP_REPLY_404);
		return NULL;
	}
	if (!(h = http_get_handler(req_ctx))) {
		GRID_DEBUG("Handler not found");
		_reply_fixed(req_ctx, HTTP_REPLY_404);
		return NULL;
	}
	if (!h->handler) {
		GRID_DEBUG("Invalid handler");
		_reply_fixed(req_ctx, HTTP_REPLY_502);
		return NULL;
	}

	/* Handler calling */
	struct http_reply_ctx_s reply = {
		set_status,
		add_header,
		send_headers,
		set_inlined,
		set_chunked,
		chunk_send_gba,
		chunk_send_file,
		chunk_last
	};
	headers = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);
	h->handler(req_ctx->dispatcher->u, req_ctx->request, &reply);
	_reply_fixed(req_ctx, HTTP_REPLY_500);
	return NULL;
}

/* -------------------------------------------------------------------------- */

static GError *
http_parse_request(struct http_request_s *req)
{
	gchar *arg;
	gsize len = 0;

	req->args = g_malloc0(sizeof(gchar*));

	if (!(arg = strchr(req->req_uri, '?')))
		req->path = g_uri_unescape_string(req->req_uri, "");
	else {
		*arg = '\0';
		req->path = g_uri_unescape_string(req->req_uri, "");
		*arg = '?';

		for (++ arg;;) {
			gchar *ampersand;

			req->args = g_realloc(req->args, sizeof(gchar*) * (len+2));

			if (!(ampersand = strchr(arg, '&'))) {
				req->args[len] = g_uri_unescape_string(arg, "");
				req->args[len+1] = NULL;
				break;
			}

			*ampersand = '\0';
			req->args[len] = g_uri_unescape_string(arg, "");
			req->args[len+1] = NULL;
			*ampersand = '&';

			++ len;
			arg = ampersand + 1;
		}
	}

	return NULL;
}

static GError *
http_parse_request_line(struct http_request_s *req, gchar *raw)
{
	gchar *s;

	/* Unpack the request line */
	for (s=raw; *s ;s++) {
		if (g_ascii_isspace(*s)) {
			*s = '\0';
			req->cmd = g_strdup(raw);
			for (raw=s+1; *raw && g_ascii_isspace(*raw) ;raw++);
			break;
		}
	}
	for (s=raw; *s ;s++) {
		if (g_ascii_isspace(*s)) {
			*s = '\0';
			req->req_uri = g_strdup(raw);
			for (raw=s+1; *raw && g_ascii_isspace(*raw) ;raw++);
			break;
		}
	}
	if (*raw)
		req->version = g_strdup(raw);

	if (!req->cmd || !req->req_uri || !req->version)
		return g_error_new(gquark_log, 400, "Invalid request line");

	/* Unpack the request itself */
	GRID_DEBUG("Request line [%s] [%s] [%s]", req->cmd,
			req->req_uri, req->version);
	return http_parse_request(req);
}

static GError *
http_extract_rfc_headers(struct http_request_s *req)
{
	const gchar *v;

	if (NULL != (v = http_request_get_header(req, "Content-Length"))) {
		req->req_headers.content_length = g_ascii_strtoull(v, NULL, 10);
	}

	if (NULL != (v = http_request_get_header(req, "Transfer-Encoding"))) {
		if (!g_ascii_strcasecmp(v, "Chunked"))
			req->req_headers.body_chunked = 1;
	}
	
	if (NULL != (v = http_request_get_header(req, "Range"))) {
		gchar *e = NULL;
		if (!g_str_has_prefix(v, "bytes="))
			return g_error_new(gquark_log, 400, "Invalid Range");
		v += sizeof("bytes=")-1;
		e = NULL;
		req->req_headers.range.present = 1;
		req->req_headers.range.start = g_ascii_strtoull(v, &e, 10);
		req->req_headers.range.end = g_ascii_strtoull(e+1, NULL, 10);
		GRID_DEBUG("Getting only range "
				"[%"G_GUINT64_FORMAT"] to [%"G_GUINT64_FORMAT"]",
			req->req_headers.range.start, req->req_headers.range.end);
	}

	return NULL;
}

static GError *
http_parse_header(struct http_request_s *req, gchar *name, gsize len)
{
	gchar c, *value;

	(void) len;
	if (!(value = strchr(name, ':')))
		return g_error_new(gquark_log, 400, "Invalid header format");

	*(value++) = '\0';
	while ((c = *value) && g_ascii_isspace(c))
		*(value++) = '\0';

	http_request_add_header(req, name, value);
	return NULL;
}

static GError *
http_parse_headers(struct http_request_s *req, gchar *all_headers,
		gsize real_len)
{
	GError *err;
	gsize len;
	gchar *start, *crlf;
	
	(void) real_len;

	/* Parse the request line */
	start = all_headers;
	crlf = g_strstr_len(start, real_len, "\r\n");
	len = crlf - start;
	*crlf = '\0';
	if (NULL != (err = http_parse_request_line(req, start))) {
		g_prefix_error(&err, "Request error : ");
		return err;
	}

	/* Parse the headers */
	for (start = crlf+2; *start ; start = crlf+2) {

		/* try to find the end of a line */
		crlf = g_strstr_len(start, real_len - (all_headers - start), "\r\n");
		if (!crlf)
			break;
		*crlf = '\0';
		len = crlf - start;
		if (!len)
			break;

		/* manage the whole line */
		if (NULL != (err = http_parse_header(req, (gchar*)start, len))) {
			g_prefix_error(&err, "HTTP error : ");
			return err;
		}
	}

	err = http_extract_rfc_headers(req);
	if (NULL != err)
		return err;

	return NULL;
}

static gchar*
http_are_headers_complete(struct transport_client_context_s *ctx)
{
	guint i;
	gchar *sep;

	sep = g_strstr_len(
			(gchar*)ctx->headers->data + ctx->headers_offset,
			ctx->headers->len - ctx->headers_offset,
			"\r\n\r\n");

	if (sep) {
		*(sep+2) = *(sep+3) = '\0';
		return sep;
	}

	/* Keep the position at which we didn't meet the double CRLF
	 * This will help avoiding reparsing the whole buffer every
	 * time a small data is received. */
	ctx->headers_offset = ctx->headers->len;
	for (i=ctx->headers_offset; i > 1 ;i--) {
		gchar c = ctx->headers->data[i-1];
		if (c!='\r' && c!='\n')
			break;
	}

	return NULL;
}

static guint8*
strchr_len(guint8 *b, gsize s, gchar wanted)
{
	while ((s--)>0) {
		if (*(b++) == wanted)
			return b-1;
	}
	return NULL;
}

static void
_read_lines_from_slab(struct transport_client_context_s *ctx,
		struct data_slab_sequence_s *in)
{
	GByteArray *hdr;

	if (!(hdr = ctx->headers))
		ctx->headers = hdr = g_byte_array_new();

	while (data_slab_sequence_has_data(in)) {
		gsize size = 0;
		struct data_slab_s *ds;

		ds = data_slab_sequence_shift(in);
		if (!data_slab_has_data(ds))
			data_slab_free(ds);
		else {
			guint8 *data = NULL;
			guint8 *start = ds->data.buffer.buff + ds->data.buffer.start;
			size = ds->data.buffer.end - ds->data.buffer.start;
			guint8 *found = strchr_len(start, size, '\n');

			if (!found) { /* consume all */
				data_slab_consume(ds, &data, &size);
				g_byte_array_append(hdr, data, size);	
				data_slab_free(ds);
			}
			else {
				size = (found + 1) - start;
				data_slab_consume(ds, &data, &size);
				g_byte_array_append(hdr, data, size);
				data_slab_sequence_unshift(in, ds);
			}
		}

		if (size && http_are_headers_complete(ctx))
			break;
	}

	g_byte_array_append(hdr, (guint8*)"", 1);
	g_byte_array_set_size(hdr, hdr->len - 1);
}

static int
http_notify_input(struct network_client_s *clt)
{
	struct req_ctx_s r;
	gchar *sep;
	GError *err;

	if (r.context->current_request) {
		r.context->current_request->notify_body(r.context->current_request);
		return RC_PROCESSED;
	}

	r.client = clt;
	r.transport = &(clt->transport);
	r.context = r.transport->client_context;
	r.dispatcher = r.context->dispatcher;
	r.request = NULL;

	_read_lines_from_slab(r.context, &(r.client->input));

	if (!(sep = http_are_headers_complete(r.context)))
		return RC_PROCESSED;

	r.context->current_request = http_request_create(r.client);
	r.request = r.context->current_request;

	err = http_parse_headers(r.context->current_request,
			(gchar*)r.context->headers->data,
			sep - (gchar*)(r.context->headers->data));

	if (err != NULL) {
		g_warning("HTTP error : code=%d message=%s", err->code, err->message);
		g_clear_error(&err);
		network_client_close_output(clt, FALSE);
	}
	else {
		g_byte_array_free(r.context->headers, TRUE);
		r.context->headers = NULL;
		http_manage_request(&r);
	}

	return clt->transport.waiting_for_close ? RC_NODATA : RC_PROCESSED;
}

