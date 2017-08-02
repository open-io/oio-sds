/*
OpenIO SDS oio-event-benchmark
Copyright (C) 2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include <glib.h>

#include <server/network_server.h>
#include <proxy/path_parser.h>
#include <proxy/transport_http.h>
#include <core/url_ext.h>
#include <metautils/lib/metautils.h>

#include "event_benchmark.h"
#include "fake_service.h"

#define PATH_MAXLEN 64
#define METHOD_MAXLEN 64

// send_events.c
extern gint sent_events;
extern gint errors;
extern gint64 reception_time;
extern gdouble speed;

gboolean fake_service_ready = FALSE;

static struct path_parser_s *path_parser = NULL;
static struct network_server_s *server = NULL;

static GMutex mutex;

static gint received_events = 0;

// Reply

static void
_append_status(GString *out, gint code, const char * msg)
{
	EXTRA_ASSERT(out != NULL);
	oio_str_gstring_append_json_pair_int(out, "status", code);
	g_string_append_c(out, ',');
	oio_str_gstring_append_json_pair(out, "message", msg);
}

static GString *
_create_status(gint code, const gchar * msg)
{
	GString *gstr = g_string_sized_new(256);
	g_string_append_c(gstr, '{');
	_append_status(gstr, code, msg);
	g_string_append_c(gstr, '}');
	return gstr;
}

static GString *
_create_status_error(GError * e)
{
	if (!e)
		return _create_status(CODE_INTERNAL_ERROR, "unknown error");
	GString *gstr = _create_status(e->code, e->message);
	g_error_free(e);
	return gstr;
}

static enum http_rc_e
_reply_bytes(struct http_reply_ctx_s *rp,
		int code, const gchar * msg, GBytes * bytes)
{
	rp->set_status(code, msg);
	if (bytes) {
		if (g_bytes_get_size(bytes) > 0) {
			rp->set_content_type("application/json");
			rp->set_body_bytes(bytes);
		} else {
			g_bytes_unref(bytes);
			rp->set_body_bytes(NULL);
		}
	} else {
		rp->set_body_bytes(NULL);
	}
	rp->finalize();
	return HTTPRC_DONE;
}

static enum http_rc_e
_reply_json(struct http_reply_ctx_s *rp,
		int code, const gchar * msg, GString * gstr)
{
	return _reply_bytes(rp, code, msg,
			gstr ? g_string_free_to_bytes(gstr) : NULL);
}

static enum http_rc_e
_reply_ok(struct http_reply_ctx_s *rp, GString *body)
{
	if (!body || !body->len)
		return _reply_json(rp, HTTP_CODE_NO_CONTENT, "OK", body);
	return _reply_json(rp, HTTP_CODE_OK, "OK", body);
}

static enum http_rc_e
_reply_json_error(struct http_reply_ctx_s *rp,
		int code, const char *msg, GString * gstr)
{
	if (gstr && gstr->len)
		rp->access_tail("e=%.*s", gstr->len, gstr->str);
	return _reply_json(rp, code, msg, gstr);
}

static enum http_rc_e
_reply_not_found(struct http_reply_ctx_s *rp, GError *err)
{
	return _reply_json_error(rp, HTTP_CODE_NOT_FOUND,
			"Not found", _create_status_error(err));
}

// Match route

static struct path_matching_s **
_fake_service_match(const gchar *method, const gchar *path)
{
	gsize lp = strlen(path), lm = strlen(method);
	if (lp > PATH_MAXLEN || lm > METHOD_MAXLEN)
		return g_malloc0(sizeof(struct path_matching_s*));

	gchar *key = g_alloca(lp + 2 + lm + 1);
	gchar *pk = key;

	// Copy and purify the path
	register int slash = 1;
	for (register const gchar *p = path; *p ;++p) {
		if (slash && *p == '/')
			continue;
		slash = 0;
		*(pk++) = *p;
	}

	// add a separator
	if (*(pk-1) != '/')
		*(pk++) = '/';
	*(pk++) = '#';

	// copy the method without slashes
	for (register const gchar *p = method; *p ;++p) {
		if (*p != '/')
			*(pk++) = *p;
	}
	*pk = '\0';

	gchar **tokens = g_strsplit(key, "/", -1);
	for (gchar **p=tokens; *p ;++p) {
		gchar *unescaped = g_uri_unescape_string(*p,NULL);
		oio_str_reuse(p, unescaped);
	}
	struct path_matching_s **result = path_parser_match(path_parser, tokens);
	g_strfreev(tokens);

	return result;
}

// Handler action

struct req_args_s
{
	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;
	struct oio_requri_s *ruri;
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

static enum http_rc_e
handler_action(struct http_request_s *request, struct http_reply_ctx_s *reply)
{
	// Get a request id for the current request
	const gchar *reqid = g_tree_lookup(request->tree_headers,
			PROXYD_HEADER_REQID);
	if (reqid)
		oio_ext_set_reqid(reqid);
	else
		oio_ext_set_random_reqid();

	// Then parse the request to find a handler
	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};
	oio_requri_parse(request->req_uri, &ruri);

	struct path_matching_s **matchings = _fake_service_match(request->cmd,
			ruri.path);

	enum http_rc_e rc;
	if (!*matchings) {
		rc = _reply_not_found(reply, BADREQ("Route not managed"));
	} else {
		struct req_args_s args = {0};
		args.ruri = &ruri;
		args.rq = request;
		args.rp = reply;

		req_handler_f handler = (*matchings)->last->u;
		rc = (*handler) (&args);
	}

	path_matching_cleanv(matchings);
	oio_requri_clear(&ruri);
	oio_ext_set_reqid(NULL);

	return rc;
}

// Route action

static enum http_rc_e
action_global(struct req_args_s *args)
{
	g_atomic_int_inc(&received_events);

	if ((received_events + errors) == sent_events
			&& g_mutex_trylock(&mutex)) {
		reception_time = g_get_monotonic_time() - reception_time;

		if ((received_events + errors) == sent_events) {
			gdouble reception_time_sec = reception_time / 1000000.0;
			speed = received_events / reception_time_sec;

			printf("%d events sent (errors: %d) in %f seconds, %f events/sec\n",
					sent_events, errors, reception_time_sec, speed);

			received_events = 0;
			fake_service_ready = TRUE;
		}

		g_mutex_unlock(&mutex);
	}

	return _reply_ok(args->rp, NULL);
}

static enum http_rc_e
action_chunk_new(struct req_args_s *args)
{
	return action_global(args);
}

static enum http_rc_e
action_chunk_delete(struct req_args_s *args)
{
	return action_global(args);
}

static enum http_rc_e
action_account(struct req_args_s *args)
{
	return action_global(args);
}

static enum http_rc_e
action_rawx(struct req_args_s *args)
{
	return action_global(args);
}

static void
configure_request_handlers(void)
{
#define SET(Url,Callback) path_parser_configure(path_parser, Url, Callback)

	SET("v1/rdir/push/#POST", action_chunk_new);
	SET("v1/rdir/delete/#DELETE", action_chunk_delete);
	SET("v1.0/account/container/update/#POST", action_account);
	SET("rawx/#DELETE", action_rawx);
}

// Main functions

gboolean
fake_service_configure(void)
{
	server = network_server_init();
	path_parser = path_parser_init();
	configure_request_handlers();

	network_server_bind_host(server, FAKE_SERVICE_ADDRESS, handler_action,
			(network_transport_factory) transport_http_factory0);

	g_mutex_init(&mutex);

	return TRUE;
}

gboolean
fake_service_run(void)
{
	GError *err = NULL;

	err = network_server_open_servers(server);
	if (err) {
		GRID_ERROR("Server opening error: %d %s", err->code, err->message);
		g_clear_error(&err);

		return FALSE;
	}

	fake_service_ready = TRUE;

	err = network_server_run(server, NULL);
	if (err) {
		GRID_ERROR("Server opening error: %d %s", err->code, err->message);
		g_clear_error(&err);

		return FALSE;
	}

	return TRUE;
}

void
fake_service_too_long(void)
{
	if (g_mutex_trylock(&mutex)) {
		printf("Too long... %d events weren't received\n", sent_events - received_events);

		received_events = 0;
		fake_service_ready = TRUE;

		g_mutex_unlock(&mutex);
	}
}

void
fake_service_stop(void)
{
	if (server) {
		network_server_stop(server);
	}
}

void
fake_service_fini(void)
{
	if (server) {
		network_server_close_servers(server);
		network_server_stop(server);
		network_server_clean(server);
		server = NULL;
	}

	g_mutex_clear(&mutex);
}
