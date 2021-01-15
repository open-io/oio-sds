/*
OpenIO SDS server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <server/server_variables.h>
#include <core/internals.h>

#include "network_server.h"
#include "transport_gridd.h"
#include "internals.h"

/* Associates a dispatcher and a working buffer to a client. */
struct transport_client_context_s
{
	struct gridd_request_dispatcher_s *dispatcher;
	GByteArray *gba_l4v;
};

struct gridd_request_handler_s
{
	const gchar *name;
	gpointer hdata;
	gpointer gdata;
	gboolean (*handler) (struct gridd_reply_ctx_s *reply,
			gpointer gdata, gpointer hdata);
	GQuark stat_name_req;
	GQuark stat_name_time;
};

struct gridd_request_dispatcher_s
{
	GTree *tree_requests;

	/* By default to 0, set to a monotonic time value when an I/O
	 * error occurs, periodically checked for recent acctivity */
	gint64 last_io_error;
	gint64 last_io_success;
	gchar last_io_msg[LIMIT_LENGTH_VOLUMENAME];
};

struct req_ctx_s
{
	gint64 tv_start, tv_parsed, tv_end;

	MESSAGE request;
	struct network_client_s *client;
	struct transport_client_context_s *clt_ctx;
	struct network_transport_s *transport;
	struct gridd_request_dispatcher_s *disp;
	struct hashstr_s *reqname;
	gchar *subject;
	const gchar *reqid;
	gboolean final_sent;
	gboolean access_disabled;
};

static int is_code_final(int code) { return CODE_IS_FINAL(code); }

static int transport_gridd_notify_input(struct network_client_s *clt);

static void transport_gridd_notify_error(struct network_client_s *clt);

static void transport_gridd_clean_context(struct transport_client_context_s *);

static gboolean _client_manage_l4v(struct network_client_s *clt, GByteArray *gba);

/* XXX(jfs): ugly quirk, ok, but helpful to keep simple the stats support in
 * the server but allow it to reply "config volume /path/to/docroot" in its
 * stats. */
const char *oio_server_volume = NULL;

static int _local_variable = 0;

/* -------------------------------------------------------------------------- */

void
gridd_request_dispatcher_clean(struct gridd_request_dispatcher_s *disp)
{
	if (!disp)
		return;
	if (disp->tree_requests) {
		g_tree_destroy(disp->tree_requests);
		disp->tree_requests = NULL;
	}
	g_free(disp);
}

GError *
transport_gridd_dispatcher_add_requests(
		struct gridd_request_dispatcher_s *dispatcher,
		const struct gridd_request_descr_s *descr,
		gpointer gdata)
{
	const struct gridd_request_descr_s *d;

	if (!dispatcher)
		return NEWERROR(EINVAL, "Invalid dispatcher");
	if (!descr)
		return NEWERROR(EINVAL, "Invalid request descriptor");

	for (d = descr; descr && d->name && d->handler; d++) {
		struct hashstr_s *hname;
		struct gridd_request_handler_s *handler;

		HASHSTR_ALLOCA(hname, d->name);
		if (NULL != g_tree_lookup(dispatcher->tree_requests, hname))
			return NEWERROR(CODE_INTERNAL_ERROR, "Overriding another request with '%s'", hashstr_str(hname));

		handler = g_malloc0(sizeof(*handler));
		handler->name = d->name;
		handler->handler = d->handler;
		handler->gdata = gdata;
		handler->hdata = d->handler_data;

		gchar tmp[256];
		g_snprintf(tmp, sizeof(tmp), "%s.%s", OIO_STAT_PREFIX_REQ, d->name);
		handler->stat_name_req = g_quark_from_string (tmp);
		g_snprintf(tmp, sizeof(tmp), "%s.%s", OIO_STAT_PREFIX_TIME, d->name);
		handler->stat_name_time = g_quark_from_string (tmp);

		g_tree_insert(dispatcher->tree_requests, hashstr_dup(hname), handler);
	}

	return NULL;
}

struct gridd_request_dispatcher_s *
transport_gridd_build_empty_dispatcher(void)
{
	struct gridd_request_dispatcher_s *dispatcher = g_malloc0(sizeof(*dispatcher));
	dispatcher->tree_requests = g_tree_new_full(
			hashstr_quick_cmpdata, NULL, g_free, g_free);
	transport_gridd_dispatcher_add_requests(dispatcher,
			gridd_get_common_requests(), NULL);

	return dispatcher;
}

void
transport_gridd_factory0(struct gridd_request_dispatcher_s *dispatcher,
		struct network_client_s *client)
{
	EXTRA_ASSERT(dispatcher != NULL);
	EXTRA_ASSERT(client != NULL);

	struct transport_client_context_s *transport_context = g_malloc0(sizeof(*transport_context));
	transport_context->dispatcher = dispatcher;
	transport_context->gba_l4v = NULL;

	client->transport.client_context = transport_context;
	client->transport.clean_context = transport_gridd_clean_context;
	client->transport.notify_input = transport_gridd_notify_input;
	client->transport.notify_error = transport_gridd_notify_error;

	network_client_allow_input(client, TRUE);
}

/* -------------------------------------------------------------------------- */

static const gchar * ensure (const gchar *s) { return s && *s ? s : "-"; }

struct log_item_s
{
	struct req_ctx_s *req_ctx;
	gint code;
	const gchar *msg;
	gsize out_len;
};

static void
network_client_log_access(struct log_item_s *item)
{
	struct req_ctx_s *r = item->req_ctx;

	if (r->access_disabled && CODE_IS_OK(item->code) && !GRID_DEBUG_ENABLED())
		return;

	if (!r->tv_end)
		r->tv_end = oio_ext_monotonic_time ();

	gint64 diff_total = r->tv_end - r->tv_start;
	gint64 diff_handler = r->tv_end - r->tv_parsed;

	GString *gstr = g_string_sized_new(256);

	/* mandatory */
	g_string_append(gstr, ensure(r->client->local_name));
	g_string_append_c(gstr, ' ');
	g_string_append(gstr, ensure(r->client->peer_name));
	g_string_append_c(gstr, ' ');
	g_string_append_len(gstr, ensure(hashstr_str(r->reqname)),
			hashstr_len(r->reqname)?:1);
	g_string_append_printf(gstr, " %d %"G_GINT64_FORMAT" %"G_GSIZE_FORMAT" - ",
			item->code, diff_total, item->out_len);
	g_string_append(gstr, ensure(r->reqid));

	/* arbitrary */
	g_string_append_printf(gstr, " t=%"G_GINT64_FORMAT, diff_handler);
	GHashTable *perfdata = oio_ext_get_perfdata();
	if (perfdata) {
		void __log_perfdata(gpointer key, gpointer val, gpointer udata UNUSED)
		{
			g_string_append_printf(gstr, " %s=%"G_GINT64_FORMAT,
				(char*)key, (gint64)GPOINTER_TO_INT(val));
		}
		g_hash_table_foreach(perfdata, __log_perfdata, NULL);
	}
	if (r->subject) {
		g_string_append_c (gstr, ' ');
		g_string_append(gstr, ensure(r->subject));
	}

	INCOMING("%s", gstr->str);
	g_string_free(gstr, TRUE);
}

/* -------------------------------------------------------------------------- */

static guint32
_l4v_size(GByteArray *gba)
{
	EXTRA_ASSERT(gba != NULL);
	EXTRA_ASSERT(gba->len >= 4);

	guint32 size = *((guint32*)gba->data);
	return g_ntohl(size);
}

static struct hashstr_s *
_request_get_name(MESSAGE req)
{
	gsize name_len = 0;
	void *name = metautils_message_get_NAME(req, &name_len);
	if (!name || !name_len)
		return hashstr_create("");
	return hashstr_create_len((gchar*)name, name_len);
}

static gchar *
_req_get_ID(MESSAGE req, gchar *d, gsize dsize)
{
	memset(d, 0, dsize);

	gsize flen = 0;
	guint8 *f = metautils_message_get_ID(req, &flen);
	if (!f || !flen) {
		*d = '-';
	} else if (oio_str_is_printable((gchar*)f, flen)) {
		g_strlcpy(d, (gchar*)f, MIN(dsize, flen + 1));
	} else {
		oio_str_bin2hex(f, MIN(flen,dsize/2), d, dsize);
	}

	return d;
}

static gsize
gba_read(GByteArray *gba, struct data_slab_s *ds, guint32 max)
{
	guint8 *data = NULL;
	gsize data_size = 0;

	EXTRA_ASSERT(max >= gba->len);
	if (max <= gba->len)
		return 0;

	data_size = max - gba->len;
	GRID_TRACE("About to consume a maximum of %"G_GSIZE_FORMAT" bytes among %"G_GSIZE_FORMAT,
			data_size, data_slab_size(ds));

	if (data_slab_consume(ds, &data, &data_size)) {
		if (data_size > 0 && data)
			g_byte_array_append(gba, data, data_size);
		GRID_TRACE("Consumed %"G_GSIZE_FORMAT" bytes (now gba=%u ds=%"G_GSIZE_FORMAT")",
				data_size, gba->len, data_slab_size(ds));
		return data_size;
	}
	else {
		GRID_TRACE("consumed 0 bytes (now gba=%u ds=%"G_GSIZE_FORMAT")",
				gba->len, data_slab_size(ds));
		return 0;
	}
}

static void
_ctx_reset(struct transport_client_context_s *ctx)
{
	if (!ctx->gba_l4v)
		return;
	g_byte_array_free(ctx->gba_l4v, TRUE);
	ctx->gba_l4v = NULL;
}

/* ------------------------------------------------------------------------- */

static void
transport_gridd_notify_error(struct network_client_s *clt)
{
	(void) clt;
	EXTRA_ASSERT(clt != NULL);
	/* No access log must be written here, for an unknown network error.
	 * This always happens, periodically, for monitoring purposes (TCP hits
	 * without data, connect() and close() */
}

static int
transport_gridd_notify_input(struct network_client_s *clt)
{
	struct transport_client_context_s *ctx;

	EXTRA_ASSERT(clt != NULL);

	ctx = clt->transport.client_context;
	/* read the data */
	while (data_slab_sequence_has_data(&(clt->input))) {

		struct data_slab_s *ds;

		if (!ctx->gba_l4v)
			ctx->gba_l4v = g_byte_array_sized_new(256);

		if (!(ds = data_slab_sequence_shift(&(clt->input))))
			break;

		if (!data_slab_has_data(ds)) {
			data_slab_free(ds);
			continue;
		}

		if (ctx->gba_l4v->len < 4) { /* read the size */
			gba_read(ctx->gba_l4v, ds, 4);
			data_slab_sequence_unshift(&(clt->input), ds);
			continue;
		}

		guint32 payload_size = _l4v_size(ctx->gba_l4v);

		if (!payload_size) { /* empty message : reset the buffer */
			data_slab_sequence_unshift(&(clt->input), ds);
			_ctx_reset(ctx);
			continue;
		}

		if (payload_size > (1024 * 1024 * 1024)) { /* to big */
			GRID_WARN("fd=%d Request too big (%u)", clt->fd, payload_size);
			data_slab_sequence_unshift(&(clt->input), ds);
			_ctx_reset(ctx);
			network_client_close_output(clt, FALSE);
			return RC_ERROR;
		}

		gba_read(ctx->gba_l4v, ds, payload_size + 4);
		data_slab_sequence_unshift(&(clt->input), ds);

		if (ctx->gba_l4v->len >= 4 + payload_size) { /* complete */
			if (!_client_manage_l4v(clt, ctx->gba_l4v)) {
				network_client_close_output(clt, FALSE);
				GRID_WARN("fd=%d Transport error", clt->fd);
				return RC_ERROR;
			}
			_ctx_reset(ctx);
		}
	}

	return clt->transport.waiting_for_close ? RC_NODATA : RC_PROCESSED;
}

static void
transport_gridd_clean_context(struct transport_client_context_s *ctx)
{
	_ctx_reset(ctx);
	g_free(ctx);
}

/* Request handling --------------------------------------------------------- */

static void
_notify_request(struct req_ctx_s *ctx, GQuark gq_count, GQuark gq_time)
{
	if (!ctx->tv_end)
		ctx->tv_end = oio_ext_monotonic_time();

	gint64 diff = ctx->tv_end - ctx->tv_start;

	oio_stats_add(
			gq_count, 1, gq_count_all, 1,
			gq_time, diff, gq_time_all, diff);
}

static gsize
_reply_message(struct network_client_s *clt, MESSAGE reply)
{
	gint64 start = oio_ext_monotonic_time();
	GByteArray *encoded = message_marshall_gba_and_clean(reply);
	gint64 encode = oio_ext_monotonic_time();
	gsize encoded_size = encoded->len;
	network_client_send_slab(clt, data_slab_make_gba(encoded));
	gint64 send = oio_ext_monotonic_time();
	if (server_perfdata_enabled) {
		oio_ext_add_perfdata("resp_encode", encode - start);
		oio_ext_add_perfdata("resp_send", send - encode);
	}
	return encoded_size;
}

static MESSAGE
metaXServer_reply_simple(MESSAGE request UNUSED, gint code, const gchar *message)
{
	MESSAGE reply = metautils_message_create_named(NAME_MSGNAME_METAREPLY, 0);

	if (CODE_IS_NETWORK_ERROR(code))
		code = CODE_PROXY_ERROR;
	metautils_message_add_field_strint(reply, NAME_MSGKEY_STATUS, code);

	if (message)
		metautils_message_add_field_str (reply, NAME_MSGKEY_MESSAGE, message);
	return reply;
}

static gboolean
_client_reply_fixed(struct req_ctx_s *req_ctx, gint code, const gchar *msg)
{
	EXTRA_ASSERT(!req_ctx->final_sent);

	MESSAGE reply = metaXServer_reply_simple(req_ctx->request, code, msg);
	gsize answer_size = _reply_message(req_ctx->client, reply);

	if ((req_ctx->final_sent = is_code_final(code))) {
		struct log_item_s item = {0};
		item.req_ctx = req_ctx;
		item.code = code;
		item.msg = msg;
		item.out_len = answer_size;
		network_client_log_access(&item);
	}
	return (gboolean) answer_size;
}

static gboolean
_client_call_handler(struct req_ctx_s *req_ctx)
{
	struct gridd_reply_ctx_s ctx = {};
	GHashTable *headers = NULL;
	GByteArray *body = NULL;

	void _subject(const gchar *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		gchar *tail = g_strdup_vprintf(fmt, args);
		va_end(args);

		const gchar *old = req_ctx->subject;
		gchar *s = g_strconcat (old?:"", old?" ":"", tail, NULL);
		oio_str_reuse(&req_ctx->subject, s);
		g_free0 (tail);
	}
	void _add_header(const gchar *n, GByteArray *v) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		EXTRA_ASSERT(n != NULL);
		EXTRA_ASSERT(v != NULL);
		if (!headers)
			headers = g_hash_table_new_full(g_str_hash, g_str_equal,
					g_free, metautils_gba_unref);
		g_hash_table_insert(headers, g_strdup(n), v);
	}
	void _no_access (void) {
		req_ctx->access_disabled = TRUE;
	}
	void _add_body(GByteArray *b) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		EXTRA_ASSERT(body == NULL);
		body = b;
	}
	void _send_reply(gint code, gchar *msg) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		GRID_TRACE("fd=%d REPLY code=%d message=%s", req_ctx->client->fd, code, msg);

		MESSAGE answer = metaXServer_reply_simple(req_ctx->request, code, msg);
		if (body) {
			metautils_message_add_body_unref(answer, body);
			body = NULL;
		}
		if (headers) {
			GHashTableIter iter;
			gpointer n, v;
			g_hash_table_iter_init(&iter, headers);
			while (g_hash_table_iter_next(&iter, &n, &v)) {
				metautils_message_add_field(answer, (gchar*)n,
						((GByteArray*)v)->data, ((GByteArray*)v)->len);
			}
		}

		/* encode and send */
		gsize answer_size = _reply_message(req_ctx->client, answer);

		if ((req_ctx->final_sent = is_code_final(code))) {
			struct log_item_s item;
			item.req_ctx = req_ctx;
			item.code = code;
			item.msg = msg;
			item.out_len = answer_size;
			network_client_log_access(&item);
		}
	}
	void _send_error(gint code, GError *e) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		EXTRA_ASSERT(e != NULL);
		EXTRA_ASSERT(body == NULL);
		if (e->code == CODE_REDIRECT
				|| e->code == CODE_REDIRECT_SHARD_CONTAINER)
			_subject ("e=(%d) redirect to %s", e->code, e->message);
		else
			_subject ("e=(%d) %s", e->code, e->message);
		if (code)
			e->code = code;
		if (CODE_IS_NETWORK_ERROR(e->code))
			e->code = CODE_PROXY_ERROR;
		else if (CODE_IS_OK(e->code) || CODE_IS_TEMP(e->code))
			e->code = CODE_INTERNAL_ERROR;
		_send_reply(e->code, e->message);
		g_clear_error(&e);
	}

	const gint64 now = req_ctx->tv_parsed;

	/* reply data */
	ctx.add_header = _add_header;
	ctx.add_body = _add_body;
	ctx.send_reply = _send_reply;
	ctx.send_error = _send_error;
	ctx.subject = _subject;
	ctx.no_access = _no_access;
	/* request data */
	ctx.client = req_ctx->client;
	ctx.request = req_ctx->request;
	ctx.deadline = now + sqlx_request_max_run_time;

	/* Patch the deadline with a potential max delay in the request itself */
	gchar tostr[32] = {};
	if (metautils_message_extract_string_noerror(req_ctx->request,
				NAME_MSGKEY_TIMEOUT, tostr, sizeof(tostr))) {
		gint64 to = 0;
		if (oio_str_is_number(tostr, &to) && to > 0) {
			const gint64 req_deadline = now + to;
			ctx.deadline = MIN(ctx.deadline, req_deadline);
		}
	}
	gint64 req_perfdata_enabled = FALSE;
	if (metautils_message_extract_string_noerror(req_ctx->request,
				NAME_MSGKEY_PERFDATA, tostr, sizeof(tostr))) {
		oio_str_is_number(tostr, &req_perfdata_enabled);
	}

	/* Ugly quirk: it is currently too expansive to alter all the calls to
	 * the meta2 backend, especially right now while we are writing this
	 * comment in the 4.x branch. There is currently no support of a single
	 * context with all the common open args, in 4.x, while there is one in
	 * the 'master' branch. */
	oio_ext_set_deadline(ctx.deadline);
	if (req_perfdata_enabled || server_perfdata_enabled) {
		oio_ext_enable_perfdata(TRUE);
		oio_ext_add_perfdata("req_decode", now - req_ctx->tv_start);
	}

	gboolean rc = FALSE;
	if (req_ctx->tv_start < OLDEST(now, meta_queue_max_delay)) {
		/* check the request wasn't queued for too long in regard to
		 * the max time allowed in the queue (not the deadline!) */
		gchar msg[128] = "";
		g_snprintf(msg, sizeof(msg),
				"Queued for too long (%" G_GINT64_FORMAT "ms)",
				(now - req_ctx->tv_start) / G_TIME_SPAN_MILLISECOND);
		rc = _client_reply_fixed(req_ctx, CODE_GATEWAY_TIMEOUT, msg);
		_notify_request(req_ctx, gq_count_overloaded, gq_time_overloaded);
	} else {
		struct gridd_request_handler_s *hdl =
			g_tree_lookup(req_ctx->disp->tree_requests, req_ctx->reqname);
		if (!hdl) {
			rc = _client_reply_fixed(req_ctx, CODE_NOT_FOUND, "No handler found");
			_notify_request(req_ctx, gq_count_unexpected, gq_time_unexpected);
		} else {
			EXTRA_ASSERT(hdl->handler != NULL);
			if (hdl->hdata != &_local_variable
					&& !grid_daemon_is_io_ok(req_ctx->disp)) {
				gchar msg[128] = "";
				g_snprintf(msg, sizeof(msg), "IO errors reported: %s",
						grid_daemon_last_io_msg(req_ctx->disp));
				rc = _client_reply_fixed(req_ctx, CODE_UNAVAILABLE, msg);
				_notify_request(req_ctx, gq_count_ioerror, gq_time_ioerror);
			} else {
				rc = hdl->handler(&ctx, hdl->gdata, hdl->hdata);
				_notify_request(req_ctx, hdl->stat_name_req, hdl->stat_name_time);
			}
		}
	}

	EXTRA_ASSERT(body == NULL);
	if (headers)
		g_hash_table_destroy(headers);
	oio_ext_enable_perfdata(FALSE);
	return rc;
}

static gboolean
_client_manage_l4v(struct network_client_s *client, GByteArray *gba)
{
	gchar reqid[LIMIT_LENGTH_REQID];
	struct req_ctx_s req_ctx = {0};
	gboolean rc = FALSE;
	GError *err = NULL;

	EXTRA_ASSERT(gba != NULL);
	EXTRA_ASSERT(client != NULL);

	req_ctx.client = client;
	req_ctx.transport = &(client->transport);
	req_ctx.clt_ctx = req_ctx.transport->client_context;
	req_ctx.disp = req_ctx.clt_ctx->dispatcher;

	MESSAGE request = message_unmarshall(gba->data, gba->len, &err);

	// take the encoding into account
	req_ctx.tv_start = client->time.evt_in;
	req_ctx.tv_parsed = oio_ext_monotonic_time ();

	if (!request) {
		struct log_item_s item;
		item.req_ctx = &req_ctx;
		item.code = 400;
		item.msg = "Malformed ASN.1/BER Message";
		item.out_len = 0;
		network_client_log_access(&item);
		GRID_INFO("fd=%d ASN.1 decoder error: (%d) %s",
				client->fd, err->code, err->message);
		goto label_exit;
	}

	req_ctx.request = request;
	req_ctx.reqname = _request_get_name(request);
	req_ctx.reqid = _req_get_ID(request, reqid, sizeof(reqid));
	oio_ext_set_reqid(req_ctx.reqid);
	rc = TRUE;

	/* TODO check the socket is still active, specially if it seems old (~long
	 * time spent in the queue). */

	/* check the request is well formed */
	if (!req_ctx.reqname) {
		_client_reply_fixed(&req_ctx, CODE_BAD_REQUEST, "Invalid/No request name");
		goto label_exit;
	}

	GRID_TRACE("fd=%d ACCESS [%s]", client->fd, hashstr_str(req_ctx.reqname));

	rc = _client_call_handler(&req_ctx);

	if (!req_ctx.final_sent) {
		_client_reply_fixed(&req_ctx, CODE_INTERNAL_ERROR, "BUG : no reply sent");
		rc = FALSE;
	}

label_exit:
	metautils_message_destroy(request);
	if (err)
		g_clear_error(&err);
	if (req_ctx.reqname)
		g_free(req_ctx.reqname);
	oio_str_clean(&req_ctx.subject);
	memset(&req_ctx, 0, sizeof(req_ctx));
	oio_ext_set_reqid (NULL);
	return rc;
}

/* -------------------------------------------------------------------------- */

static gboolean
_stats_runner(gpointer k, gpointer v, gpointer u)
{
	(void) v;
	g_byte_array_append((GByteArray*)u, (guint8*)hashstr_str(k),
			(guint) hashstr_len(k));
	g_byte_array_append((GByteArray*)u, (guint8*)"\n", 1);
	return FALSE;
}

static gboolean
dispatch_LISTHANDLERS(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	GByteArray *body = g_byte_array_sized_new(256);
	g_tree_foreach(reply->client->transport.client_context->dispatcher->tree_requests,
			_stats_runner, body);
	reply->add_body(body);
	reply->no_access();
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_LEAN(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	malloc_trim (malloc_trim_size_ondemand);
	g_thread_pool_stop_unused_threads();
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_PING(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	reply->no_access();
	reply->add_body(metautils_gba_from_string("OK\r\n"));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_KILL(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	if (reply->client->server->abort_allowed) {
		abort();
		reply->send_reply(CODE_FINAL_OK, "OK");
	} else {
		reply->send_reply(CODE_NOT_ALLOWED, "abort disabled");
	}
	return TRUE;
}

static gboolean
dispatch_SETCFG(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	gsize length = 0;
	void *body = metautils_message_get_BODY(reply->request, &length);

	json_object *jbody = NULL;
	GError *err = JSON_parse_buffer(body, length, &jbody);
	if (err) {
		reply->send_error(0, err);
	} else {
		if (!json_object_is_type(jbody, json_type_object))
			reply->send_error(0, BADREQ("Object argument expected"));
		else if (json_object_object_length(jbody) <= 0)
			reply->send_error(0, BADREQ("Empty object argument"));
		else {
			GString *gstr = g_string_new("{");
			json_object_object_foreach(jbody, k, jv) {
				if (gstr->len > 1)
					g_string_append_c(gstr, ',');
				oio_str_gstring_append_json_pair_boolean(gstr, k,
						oio_var_value_one(k, json_object_get_string(jv)));
			}
			g_string_append_c(gstr, '}');
			reply->add_body(g_bytes_unref_to_array(
					g_string_free_to_bytes(gstr)));
			reply->send_reply(CODE_FINAL_OK, "OK");
		}
	}

	if (jbody)
		json_object_put (jbody);
	return TRUE;
}

static gboolean
dispatch_GETCFG(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	GString *gstr = oio_var_list_as_json();
	reply->add_body(g_bytes_unref_to_array(g_string_free_to_bytes(gstr)));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_REDIRECT(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	gchar **endpoints = network_server_endpoints(reply->client->server);
	reply->send_error(0, NEWERROR(CODE_REDIRECT, "%s", endpoints[0]));
	g_strfreev(endpoints);
	return TRUE;
}

#define VOLPREFIX "config volume="

static gboolean
dispatch_STATS(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	GArray *array = network_server_stat_getall();
	// Rough estimate, will be automatically resized if needed
	GByteArray *body = g_byte_array_sized_new(array->len * 32);
	for (guint i = 0; i < array->len; ++i) {
		const struct stat_record_s *st =
				&g_array_index(array, struct stat_record_s, i);
		gchar tmp[256];
		gint len = g_snprintf(tmp, sizeof(tmp), "%s=%"G_GUINT64_FORMAT"\n",
				g_quark_to_string(st->which), st->value);
		g_byte_array_append(body, (guint8*)tmp, len);
	}
	g_array_free(array, TRUE);

	if (oio_server_volume) {
		g_byte_array_append (body,
				(guint8*)VOLPREFIX, sizeof(VOLPREFIX)-1);
		g_byte_array_append (body,
				(guint8*)oio_server_volume, strlen(oio_server_volume));
	}

	reply->no_access();
	reply->add_body(body);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_VERSION(struct gridd_reply_ctx_s *reply,
		gpointer gdata UNUSED, gpointer hdata UNUSED)
{
	reply->no_access();
	reply->add_body(metautils_gba_from_string(OIOSDS_PROJECT_VERSION));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

const struct gridd_request_descr_s*
gridd_get_common_requests(void)
{
	/* The marker is used to detect local low-level handlers */
	static struct gridd_request_descr_s descriptions[] = {
		/* ping mustwill fail because of I/O errors */
		{"REQ_PING",      dispatch_PING,          NULL},
		{"REQ_STATS",     dispatch_STATS,         NULL},
		{"REQ_VERSION",   dispatch_VERSION,       &_local_variable},
		{"REQ_HANDLERS",  dispatch_LISTHANDLERS,  &_local_variable},
		{"REQ_GETCFG",    dispatch_GETCFG,        &_local_variable},
		{"REQ_SETCFG",    dispatch_SETCFG,        &_local_variable},
		{"REQ_REDIRECT",  dispatch_REDIRECT,      &_local_variable},
		{"REQ_LEAN",      dispatch_LEAN,          &_local_variable},
		{"REQ_KILL",      dispatch_KILL,          &_local_variable},
		{NULL, NULL, NULL}
	};

	return descriptions;
}

void
grid_daemon_bind_host(struct network_server_s *server, const gchar *url,
		struct gridd_request_dispatcher_s *dispatcher)
{
	EXTRA_ASSERT(server != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(dispatcher != NULL);

	/* register all the requests handlers so that those never hit by request
	 * have zored stats (instead of just being absent) */
	gboolean _traverser(gpointer k, gpointer v, gpointer u) {
		(void) k; (void) u;
		struct gridd_request_handler_s *h = (struct gridd_request_handler_s*) v;
		oio_stats_set(
				h->stat_name_req, 0, h->stat_name_time, 0,
				0, 0, 0, 0);
		return FALSE;
	}
	g_tree_foreach (dispatcher->tree_requests, _traverser, NULL);
	oio_stats_set(
			gq_count_all, 0, gq_count_unexpected, 0,
			gq_time_all, 0, gq_time_unexpected, 0);

	network_server_bind_host(server, url, dispatcher,
			(network_transport_factory)transport_gridd_factory);
}

void
grid_daemon_notify_io_status(
		struct gridd_request_dispatcher_s *disp, gboolean ok, const gchar *msg)
{
	EXTRA_ASSERT(disp != NULL);
	if (ok) {
		disp->last_io_success = oio_ext_monotonic_time();
	} else {
		disp->last_io_error = oio_ext_monotonic_time();
	}
	g_strlcpy(disp->last_io_msg, msg? : "n/a", sizeof(disp->last_io_msg));
}

gboolean
grid_daemon_is_io_ok(struct gridd_request_dispatcher_s *disp)
{
	EXTRA_ASSERT(disp != NULL);

	/* Never touched -> OK */
	if (!disp->last_io_error && !disp->last_io_success)
		return TRUE;

	/* The most recent activity is an error -> KO */
	if (disp->last_io_error > disp->last_io_success)
		return FALSE;

	/* check the probe thread was not stalled */
	const gint64 now = oio_ext_monotonic_time();
	gboolean ok = disp->last_io_success > OLDEST(now, G_TIME_SPAN_MINUTE);
	if (!ok) {
		/* If this function is called often, only report once per minute. */
		static gint64 last_report = 0;
		if ((now - last_report) > G_TIME_SPAN_MINUTE) {
			last_report = now;
			GRID_WARN(
					"IO error checker stalled for %"G_GINT64_FORMAT" minutes",
					(now - disp->last_io_success) / G_TIME_SPAN_MINUTE);
		}
	}
	return ok;
}

const gchar*
grid_daemon_last_io_msg(struct gridd_request_dispatcher_s *disp)
{
	return disp->last_io_msg;
}
