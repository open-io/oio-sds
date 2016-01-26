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

#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include "internals.h"
#include "stats_holder.h"
#include "network_server.h"
#include "transport_gridd.h"

struct cnx_data_s
{
	gchar *key;
	gpointer data;
	GDestroyNotify cleanup;
};

/* Associates a dispatcher and a working buffer to a client. */
struct transport_client_context_s
{
	struct gridd_request_dispatcher_s *dispatcher;
	GByteArray *gba_l4v;
	GArray *cnx_data;
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
	gchar *uid;
	const gchar *reqid;
	gboolean final_sent;
};

static int is_code_final(int code) { return CODE_IS_FINAL(code); }

static int transport_gridd_notify_input(struct network_client_s *clt);

static void transport_gridd_notify_error(struct network_client_s *clt);

static void transport_gridd_clean_context(struct transport_client_context_s *);

static gboolean _client_manage_l4v(struct network_client_s *clt, GByteArray *gba);

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

	for (d=descr; d && d->name && d->handler ;d++) {
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

struct gridd_request_dispatcher_s *
transport_gridd_build_dispatcher( const struct gridd_request_descr_s *descr,
		gpointer context)
{
	struct gridd_request_dispatcher_s *dispatcher;

	dispatcher = transport_gridd_build_empty_dispatcher();
	if (descr)
		(void) transport_gridd_dispatcher_add_requests(dispatcher, descr, context);
	return dispatcher;
}

void
transport_gridd_factory0(struct gridd_request_dispatcher_s *dispatcher,
		struct network_client_s *client)
{
	EXTRA_ASSERT(dispatcher != NULL);
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->fd >= 0);

	struct transport_client_context_s *transport_context = g_malloc0(sizeof(*transport_context));
	transport_context->dispatcher = dispatcher;
	transport_context->gba_l4v = NULL;
	transport_context->cnx_data = g_array_sized_new(FALSE, TRUE,
			sizeof(struct cnx_data_s), 4);

	client->transport.client_context = transport_context;
	client->transport.clean_context = transport_gridd_clean_context;
	client->transport.notify_input = transport_gridd_notify_input;
	client->transport.notify_error = transport_gridd_notify_error;

	network_client_allow_input(client, TRUE);
}

/* -------------------------------------------------------------------------- */

static const gchar * ensure (const gchar *s) { return s && *s ? s : "-";
}

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
	if (!item->req_ctx->tv_end)
		item->req_ctx->tv_end = oio_ext_monotonic_time ();

	gint64 diff_total = item->req_ctx->tv_end - item->req_ctx->tv_start;
	gint64 diff_handler = item->req_ctx->tv_end - item->req_ctx->tv_parsed;

	GString *gstr = g_string_sized_new(256);

	g_string_append(gstr, ensure(item->req_ctx->client->local_name));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(item->req_ctx->client->peer_name));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(hashstr_str(item->req_ctx->reqname)));

	g_string_append_printf(gstr, " %d", item->code);

	g_string_append_printf(gstr, " %"G_GINT64_FORMAT".%06"G_GINT64_FORMAT,
			diff_total / G_TIME_SPAN_SECOND,
			diff_total % G_TIME_SPAN_SECOND);

	g_string_append_printf(gstr, " %"G_GSIZE_FORMAT" ", item->out_len); // reply size

	g_string_append(gstr, ensure(item->req_ctx->uid));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(item->req_ctx->reqid));

	g_string_append_printf(gstr, " t=%"G_GINT64_FORMAT".%06"G_GINT64_FORMAT" ",
			diff_handler / G_TIME_SPAN_SECOND,
			diff_handler % G_TIME_SPAN_SECOND);

	g_string_append(gstr, ensure(item->req_ctx->subject));

	g_log("access", GRID_LOGLVL_INFO, "%s", gstr->str);
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
_req_get_hex_ID(MESSAGE req, gchar *d, gsize dsize)
{
	memset(d, 0, dsize);

	gsize flen = 0;
	guint8 *f = metautils_message_get_ID(req, &flen);
	if (!f || !flen)
		*d = '-';
	else if (oio_str_ishexa((gchar*)f, flen)) {
		for (gchar *p=d; flen-- > 0 && dsize-- > 0;)
			*(p++) = *(f++);
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

static void
_cnx_data_reset(struct cnx_data_s *cd, gboolean key_only)
{
	if (cd->key)
		g_free(cd->key);
	if (!key_only && cd->data && cd->cleanup)
		cd->cleanup(cd->data);
}

static void
_ctx_reset_cnx_data(struct transport_client_context_s *ctx)
{
	while (ctx->cnx_data->len > 0) {
		register guint i = ctx->cnx_data->len - 1;
		_cnx_data_reset(&g_array_index(ctx->cnx_data, struct cnx_data_s, i), FALSE);
		g_array_remove_index_fast(ctx->cnx_data, i);
	}
}

static void
_ctx_append_cnx_data(struct transport_client_context_s *ctx,
		const gchar *key, gpointer data, GDestroyNotify cleanup)
{
	struct cnx_data_s cd;

	cd.key = g_strdup(key);
	cd.data = data;
	cd.cleanup = cleanup;
	g_array_append_vals(ctx->cnx_data, &cd, 1);
}

static gboolean
_ctx_replace_cnx_data(struct transport_client_context_s *ctx,
		const gchar *key, gpointer data, GDestroyNotify cleanup)
{
	guint i, max;
	struct cnx_data_s *pdata;

	for (i=0,max=ctx->cnx_data->len; i<max ;i++) {
		pdata = &g_array_index(ctx->cnx_data, struct cnx_data_s, i);
		if (!strcmp(pdata->key, key)) {
			if (pdata->data && pdata->cleanup)
				pdata->cleanup(pdata->data);
			pdata->data = data;
			pdata->cleanup = cleanup;
			return TRUE;
		}
	}

	return FALSE;
}

static void
_ctx_store_cnx_data(struct transport_client_context_s *ctx,
		const gchar *key, gpointer data, GDestroyNotify cleanup)
{
	if (!_ctx_replace_cnx_data(ctx, key, data, cleanup))
		_ctx_append_cnx_data(ctx, key, data, cleanup);
}

static gboolean
_ctx_forget_cnx_data(struct transport_client_context_s *ctx,
		const gchar *key)
{
	guint i, max;
	struct cnx_data_s *pdata;

	for (i=0,max=ctx->cnx_data->len; i<max ;i++) {
		pdata = &g_array_index(ctx->cnx_data, struct cnx_data_s, i);
		if (!strcmp(pdata->key, key)) {
			_cnx_data_reset(&g_array_index(ctx->cnx_data, struct cnx_data_s, i), TRUE);
			g_array_remove_index_fast(ctx->cnx_data, i);
			return TRUE;
		}
	}

	return FALSE;
}

static gpointer
_ctx_get_cnx_data(struct transport_client_context_s *ctx, const gchar *key)
{
	guint i, max;
	struct cnx_data_s *pdata;

	for (i=0,max=ctx->cnx_data->len; i<max ;i++) {
		pdata = &g_array_index(ctx->cnx_data, struct cnx_data_s, i);
		if (!strcmp(pdata->key, key))
			return pdata->data;
	}

	return NULL;
}

/* ------------------------------------------------------------------------- */

static void _client_send_error(struct network_client_s *);

static void
transport_gridd_notify_error(struct network_client_s *clt)
{
	EXTRA_ASSERT(clt != NULL);
	// @todo TODO write an access log trace
	_client_send_error(clt);
	_ctx_reset_cnx_data(clt->transport.client_context);
}

static int
transport_gridd_notify_input(struct network_client_s *clt)
{
	struct transport_client_context_s *ctx;

	EXTRA_ASSERT(clt != NULL);
	EXTRA_ASSERT(clt->fd >= 0);

	ctx = clt->transport.client_context;
	/* read the data */
	while (data_slab_sequence_has_data(&(clt->input))) {

		struct data_slab_s *ds;

		if (!ctx->gba_l4v)
			ctx->gba_l4v = g_byte_array_new();

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
		ds = NULL;
		/*data_slab_sequence_trace(&(clt->input));*/

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

	if (ctx->cnx_data) {
		_ctx_reset_cnx_data(ctx);
		g_array_free(ctx->cnx_data, TRUE);
	}

	g_free(ctx);
}

/* Request handling --------------------------------------------------------- */

static void
_notify_request(struct req_ctx_s *ctx, GQuark gq_count, GQuark gq_time)
{
	if (!ctx->tv_end)
		ctx->tv_end = oio_ext_monotonic_time();

	gint64 diff = ctx->tv_end - ctx->tv_start;

	network_server_stat_push4 (ctx->client->server, TRUE,
			gq_count, 1, gq_count_all, 1,
			gq_time, diff, gq_time_all, diff);
}

static gboolean
_reply_message(struct network_client_s *clt, MESSAGE reply)
{
	GByteArray *encoded = message_marshall_gba_and_clean(reply);
	network_client_send_slab(clt, data_slab_make_gba(encoded));
	return TRUE;
}

static gboolean
_client_reply_fixed(struct req_ctx_s *req_ctx, gint code, const gchar *msg)
{
	EXTRA_ASSERT(!req_ctx->final_sent);
	if ((req_ctx->final_sent = is_code_final(code))) {
		struct log_item_s item;
		item.req_ctx = req_ctx;
		item.code = code;
		item.msg = msg;
		item.out_len = 0;
		network_client_log_access(&item);
	}
	MESSAGE reply = metaXServer_reply_simple(req_ctx->request, code, msg);
	return _reply_message(req_ctx->client, reply);
}

static void
_client_send_error(struct network_client_s *clt)
{
	GError *err = clt->current_error;
	if (!err)
		return;
	/* TODO FIXME WTF!? */
	MESSAGE request = metautils_message_create ();
	MESSAGE reply = metaXServer_reply_simple(request, err->code, err->message);
	(void) _reply_message(clt, reply);
	metautils_message_destroy(request);
}

static gboolean
_client_call_handler(struct req_ctx_s *req_ctx)
{
	struct gridd_reply_ctx_s ctx;
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
		if (v) {
			if (!n)
				metautils_gba_unref(v);
			else {
				if (!headers)
					headers = g_hash_table_new_full(g_str_hash, g_str_equal,
							g_free, metautils_gba_unref);
				g_hash_table_insert(headers, g_strdup(n), v);
			}
		}
	}
	void _add_body(GByteArray *b) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		if (body) {
			metautils_gba_unref(body);
			body = NULL;
		}
		body = b;
	}
	void _send_reply(gint code, gchar *msg) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		GRID_DEBUG("fd=%d REPLY code=%d message=%s", req_ctx->client->fd, code, msg);

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
				if (!n || !v)
					continue;
				metautils_message_add_field(answer, (gchar*)n, ((GByteArray*)v)->data, ((GByteArray*)v)->len);
			}
		}
		/* encode and send */
		if ((req_ctx->final_sent = is_code_final(code))) {
			struct log_item_s item;
			item.req_ctx = req_ctx;
			item.code = code;
			item.msg = msg;
			item.out_len = 0;
			network_client_log_access(&item);
		}
		_reply_message(req_ctx->client, answer);
	}
	void _send_error(gint code, GError *e) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		if (!e) {
			_subject ("e=(0) NULL");
			_send_reply(code, "OK");
		}
		else {
			_add_body(NULL);
			if (e->code == CODE_REDIRECT)
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
	}
	void _uid(const gchar *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		oio_str_reuse(&req_ctx->uid, g_strdup_vprintf(fmt, args));
		va_end(args);
	}
	void _register_cnx_data(const gchar *key, gpointer data,
			GDestroyNotify cleanup) {
		EXTRA_ASSERT(key != NULL);
		_ctx_store_cnx_data(req_ctx->clt_ctx, key, data, cleanup);
	}
	void _forget_cnx_data(const gchar *key) {
		EXTRA_ASSERT(key != NULL);
		_ctx_forget_cnx_data(req_ctx->clt_ctx, key);
	}
	gpointer _get_cnx_data(const gchar *key) {
		EXTRA_ASSERT(key != NULL);
		return _ctx_get_cnx_data(req_ctx->clt_ctx, key);
	}

	gboolean rc = FALSE;
	struct gridd_request_handler_s *hdl;

	/* reply data */
	ctx.add_header = _add_header;
	ctx.add_body = _add_body;
	ctx.send_reply = _send_reply;
	ctx.send_error = _send_error;
	ctx.uid = _uid;
	ctx.subject = _subject;
	ctx.register_cnx_data = _register_cnx_data;
	ctx.forget_cnx_data = _forget_cnx_data;
	ctx.get_cnx_data = _get_cnx_data;
	/* request data */
	ctx.client = req_ctx->client;
	ctx.request = req_ctx->request;
	ctx.reqname = req_ctx->reqname;

	hdl = g_tree_lookup(req_ctx->disp->tree_requests, req_ctx->reqname);
	if (!hdl) {
		rc = _client_reply_fixed(req_ctx, CODE_NOT_FOUND, "No handler found");
		_notify_request(req_ctx, gq_count_unexpected, gq_time_unexpected);
	} else {
		EXTRA_ASSERT(hdl->handler != NULL);
		rc = hdl->handler(&ctx, hdl->gdata, hdl->hdata);
		_notify_request(req_ctx, hdl->stat_name_req, hdl->stat_name_time);
	}

	if (body) {
		metautils_gba_unref(body);
		body = NULL;
	}
	if (headers) {
		g_hash_table_destroy(headers);
	}
	return rc;
}

static gchar *
_request_get_cid (MESSAGE request)
{
	GError *err;
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];

	err = metautils_message_extract_cid(request, NAME_MSGKEY_CONTAINERID, &cid);
	if (!err) {
		oio_str_bin2hex (cid, sizeof(container_id_t), strcid, sizeof(strcid));
		return g_strdup(strcid);
	}
	g_clear_error(&err);

	gchar *out = metautils_message_extract_string_copy (request, NAME_MSGKEY_BASENAME);
	if (out) {
		gchar *p = strchr(out, '.');
		if (p) *p = '\0';
		return out;
	}
	g_clear_error (&err);

	return NULL;
}

static gboolean
_client_manage_l4v(struct network_client_s *client, GByteArray *gba)
{
	gchar hexid[65];
	struct req_ctx_s req_ctx = {0};
	gboolean rc = FALSE;
	GError *err = NULL;

	EXTRA_ASSERT(gba != NULL);
	EXTRA_ASSERT(client != NULL);

	req_ctx.uid = NULL;
	req_ctx.subject = NULL;
	req_ctx.final_sent = FALSE;
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
	req_ctx.uid = _request_get_cid(request);
	req_ctx.reqid = _req_get_hex_ID(request, hexid, sizeof(hexid));
	oio_ext_set_reqid(req_ctx.reqid);
	rc = TRUE;

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
	oio_str_clean(&req_ctx.uid);
	memset(&req_ctx, 0, sizeof(req_ctx));
	return rc;
}

/* -------------------------------------------------------------------------- */

static gboolean
dispatch_LISTHANDLERS(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	GByteArray *body;

	gboolean _runner(gpointer k, gpointer v, gpointer u) {
		(void) v;
		g_byte_array_append((GByteArray*)u, (guint8*)hashstr_str(k), hashstr_ulen(k));
		g_byte_array_append((GByteArray*)u, (guint8*)"\n", 1);
		return FALSE;
	}

	(void) gdata;
	(void) hdata;

	body = g_byte_array_new();
	g_tree_foreach(reply->client->transport.client_context->dispatcher->tree_requests, _runner, body);
	reply->add_body(body);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_LEAN(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	gchar buf[128] = "Freed:";
	(void) gdata, (void) hdata;

	if (metautils_message_extract_flag (reply->request, "LIBC", FALSE)) {
		if (malloc_trim (0))
			g_strlcat (buf, " malloc-heap", sizeof(buf));
	}

	if (metautils_message_extract_flag (reply->request, "THREADS", FALSE)) {
		g_thread_pool_stop_unused_threads ();
		g_strlcat (buf, " idle-threads", sizeof(buf));
	}

	if (buf[strlen(buf)-1] != ':')
		g_strlcat (buf, " nothing", sizeof(buf));

	reply->send_reply(CODE_FINAL_OK, buf);
	return TRUE;
}

static gboolean
dispatch_PING(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata, (void) hdata;
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_KILL(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata, (void) hdata;
	if (reply->client->server->abort_allowed) {
		abort();
		reply->send_reply(CODE_FINAL_OK, "OK");
	} else {
		reply->send_reply(CODE_NOT_ALLOWED, "abort disabled");
	}
	return TRUE;
}

static gboolean
dispatch_STATS(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata, (void) hdata;
	GByteArray *body = g_byte_array_new();

	GArray *array = network_server_stat_getall(reply->client->server);
	for (guint i=0; i<array->len ;++i) {
		struct server_stat_s *st = &g_array_index (array, struct server_stat_s, i);
		gchar tmp[256];
		gsize len = g_snprintf (tmp, sizeof(tmp), "%s=%"G_GUINT64_FORMAT"\n",
				g_quark_to_string (st->which), st->value);
		g_byte_array_append (body, (guint8*)tmp, len);
	}
	g_array_free (array, TRUE);

	reply->add_body(body);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
dispatch_VERSION(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata, (void) hdata;
	reply->add_body(metautils_gba_from_string(OIOSDS_API_VERSION));
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

const struct gridd_request_descr_s*
gridd_get_common_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{"REQ_LEAN",      dispatch_LEAN,          NULL},
		{"REQ_PING",      dispatch_PING,          NULL},
		{"REQ_STATS",     dispatch_STATS,         NULL},
		{"REQ_VERSION",   dispatch_VERSION,       NULL},
		{"REQ_HANDLERS",  dispatch_LISTHANDLERS,  NULL},
		{"REQ_KILL",      dispatch_KILL,          NULL},
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
		network_server_stat_push2 (server, FALSE,
				h->stat_name_req, 0, h->stat_name_time, 0);
		return FALSE;
	}
	g_tree_foreach (dispatcher->tree_requests, _traverser, NULL);
	network_server_stat_push4 (server, FALSE,
			gq_count_all, 0, gq_count_unexpected, 0,
			gq_time_all, 0, gq_time_unexpected, 0);

	network_server_bind_host_lowlatency(server, url, dispatcher,
			(network_transport_factory)transport_gridd_factory);
}

