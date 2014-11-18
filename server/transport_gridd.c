#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.transport.gridd"
#endif

#include <stddef.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

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

/**
 * Associates a dispatcher and a working buffer to a client.
 */
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
	gchar stat_name_req[256];
	gchar stat_name_time[256];
};

struct gridd_request_dispatcher_s
{
	GTree *tree_requests;
};

struct req_ctx_s
{
	struct timespec tv_start, tv_parsed, tv_end;

	struct message_s *request;
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

static inline int
is_code_final(int code)
{
	return code < 100 || code == 200 || code >= 300;
}


static int transport_gridd_notify_input(struct network_client_s *clt);

static void transport_gridd_notify_error(struct network_client_s *clt);

static void transport_gridd_clean_context(struct transport_client_context_s *);

static gboolean _client_manage_l4v(struct network_client_s *clt, GByteArray *gba);

/* -------------------------------------------------------------------------- */

static GQuark gquark_log = 0;

void
gridd_register_requests_stats(struct grid_stats_holder_s *stats,
		struct gridd_request_dispatcher_s *disp)
{
	EXTRA_ASSERT(stats != NULL);
	EXTRA_ASSERT(disp != NULL);

	gboolean _traverser(gpointer k, gpointer v, gpointer u) {
		(void) k; (void) u;
		grid_stats_holder_increment(stats,
				((struct gridd_request_handler_s*)(v))->stat_name_req, 0LLU,
				((struct gridd_request_handler_s*)(v))->stat_name_time, 0LLU,
				NULL);
		return FALSE;
	}

	grid_stats_holder_increment(stats,
			INNER_STAT_NAME_REQ_TIME, 0LLU,
			INNER_STAT_NAME_REQ_COUNTER, 0LLU,
			NULL);
	g_tree_foreach(disp->tree_requests, _traverser, NULL);
}

void
gridd_request_dispatcher_clean(struct gridd_request_dispatcher_s *disp)
{
	if (!gquark_log)
		gquark_log = g_quark_from_static_string("utils.proto.gridd");

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

	if (!gquark_log)
		gquark_log = g_quark_from_static_string("utils.proto.gridd");

	if (!dispatcher)
		return g_error_new(gquark_log, EINVAL, "Invalid dispatcher");
	if (!descr)
		return g_error_new(gquark_log, EINVAL, "Invalid request descriptor");

	for (d=descr; d && d->name && d->handler ;d++) {
		struct hashstr_s *hname;
		struct gridd_request_handler_s *handler;

		HASHSTR_ALLOCA(hname, d->name);
		if (NULL != g_tree_lookup(dispatcher->tree_requests, hname))
			return g_error_new(gquark_log, 500, "Overriding another request with '%s'", hashstr_str(hname));

		handler = g_malloc0(sizeof(*handler));
		handler->name = d->name;
		handler->handler = d->handler;
		handler->gdata = gdata;
		handler->hdata = d->handler_data;

		g_snprintf(handler->stat_name_req, sizeof(handler->stat_name_req),
			"%s.%s", GRID_STAT_PREFIX_REQ, d->name);
		g_snprintf(handler->stat_name_time, sizeof(handler->stat_name_time),
			"%s.%s", GRID_STAT_PREFIX_TIME, d->name);

		g_tree_insert(dispatcher->tree_requests, hashstr_dup(hname), handler);
	}

	return NULL;
}

struct gridd_request_dispatcher_s *
transport_gridd_build_empty_dispatcher(void)
{
	struct gridd_request_dispatcher_s *dispatcher;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string("utils.proto.gridd");

	dispatcher = g_malloc0(sizeof(*dispatcher));
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
	struct transport_client_context_s *transport_context;

	if (!gquark_log)
		gquark_log = g_quark_from_static_string("utils.proto.gridd");

	EXTRA_ASSERT(dispatcher != NULL);
	EXTRA_ASSERT(client != NULL);
	EXTRA_ASSERT(client->fd >= 0);

	transport_context = g_malloc0(sizeof(*transport_context));
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
network_client_log_access(struct log_item_s *log)
{
	struct timespec diff_total, diff_handler;

	if (!log->req_ctx->tv_end.tv_sec)
		network_server_now(&log->req_ctx->tv_end);
	timespec_sub(&log->req_ctx->tv_end, &log->req_ctx->tv_start, &diff_total);
	timespec_sub(&log->req_ctx->tv_end, &log->req_ctx->tv_parsed, &diff_handler);

	GString *gstr = g_string_sized_new(256);

	g_string_append(gstr, ensure(log->req_ctx->client->local_name));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(log->req_ctx->client->peer_name));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(hashstr_str(log->req_ctx->reqname)));

	g_string_append_printf(gstr, " %d", log->code);

	g_string_append_printf(gstr, " %ld.%06ld", diff_total.tv_sec, diff_total.tv_nsec / 1000);

	g_string_append_printf(gstr, " %"G_GSIZE_FORMAT" ", log->out_len); // reply size

	g_string_append(gstr, ensure(log->req_ctx->uid));
	g_string_append_c(gstr, ' ');

	g_string_append(gstr, ensure(log->req_ctx->reqid));

	g_string_append_printf(gstr, " t=%ld.%06ld ", diff_handler.tv_sec, diff_handler.tv_nsec / 1000);

	g_string_append(gstr, ensure(log->req_ctx->subject));

	g_log("access", GRID_LOGLVL_INFO, "%s", gstr->str);
	g_string_free(gstr, TRUE);
}

/* -------------------------------------------------------------------------- */

static inline guint32
_l4v_size(GByteArray *gba)
{
	guint32 size;

	EXTRA_ASSERT(gba != NULL);
	EXTRA_ASSERT(gba->len >= 4);

	size = *((guint32*)gba->data);
	return g_ntohl(size);
}

static struct hashstr_s *
_request_get_name(struct message_s *req)
{
	void *name;
	gsize name_len;

	if (0 >= message_get_NAME(req, &name, &name_len, NULL))
		return hashstr_create("");
	if (!name || !name_len || !((guint8*)name))
		return hashstr_create("");
	if (!*((guint8*)name) || !name_len)
		return hashstr_create("");
	return hashstr_create_len((gchar*)name, name_len);
}

static gchar *
_req_get_hex_ID(MESSAGE req, gchar *d, gsize dsize)
{
	void *f;
	gsize flen = 0;

	*((int*)d) = 0;
	
	if (0 >= message_get_ID(req, &f, &flen, NULL))
		*d = '-';
	else {
		buffer2str(f, MIN(flen,dsize/2), d, dsize);
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

static inline void
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
	//GRID_TRACE("Transport: error on fd=%d", clt->fd);
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

static inline void
_notify_request(struct req_ctx_s *ctx,
		const gchar *name_req, const gchar *name_time)
{
	struct timespec diff;
	guint64 e_s, e_us, e_sum;

	if (!ctx->tv_end.tv_sec)
		network_server_now(&ctx->tv_end);
	timespec_sub(&ctx->tv_end, &ctx->tv_start, &diff);

	e_s = diff.tv_sec;
	e_us = diff.tv_nsec / 1000;
	e_sum = e_s * 1000000LLU + e_us;

	grid_stats_holder_increment(ctx->client->local_stats,
			name_req, guint_to_guint64(1),
			INNER_STAT_NAME_REQ_COUNTER, guint_to_guint64(1),
			name_time, e_sum,
			INNER_STAT_NAME_REQ_TIME, e_sum,
			NULL);
}

static gboolean
_reply_message(struct network_client_s *clt, struct message_s *reply)
{
	int rc;
	void *encoded = NULL;
	gsize encoded_size = 0;

	rc = message_marshall(reply, &encoded, &encoded_size, NULL);
	message_destroy(reply, NULL);

	if (rc) {
		network_client_send_slab(clt, data_slab_make_buffer(encoded, encoded_size));
		return TRUE;
	}

	if (encoded)
		g_free(encoded);
	return FALSE;
}

static gboolean
_client_reply_fixed(struct req_ctx_s *req_ctx, gint code, const gchar *msg)
{
	MESSAGE reply = NULL;

	EXTRA_ASSERT(!req_ctx->final_sent);
	if ((req_ctx->final_sent = is_code_final(code))) {
		struct log_item_s log;
		log.req_ctx = req_ctx;
		log.code = code;
		log.msg = msg;
		log.out_len = 0;
		network_client_log_access(&log);
	}
	return metaXServer_reply_simple(&reply, req_ctx->request, code, msg, NULL)
		&& _reply_message(req_ctx->client, reply);
}

static void
_client_send_error(struct network_client_s *clt)
{
	MESSAGE request = NULL, reply = NULL;
	GError *err = clt->current_error;
	if (!err)
		return;
	if (!message_create(&request, NULL)) {
		g_warning("Memory allocation failure");
		return;
	}
	// reply is destroyed in _reply_message
	if (metaXServer_reply_simple(&reply, request, err->code, err->message, NULL))
		(void) _reply_message(clt, reply);
	message_destroy(request, NULL);
}

static gboolean
_client_call_handler(struct req_ctx_s *req_ctx)
{
	struct gridd_reply_ctx_s ctx;
	GHashTable *headers = NULL;
	GByteArray *body = NULL;

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
		struct message_s *answer = NULL;

		EXTRA_ASSERT(!req_ctx->final_sent);
		GRID_DEBUG("fd=%d REPLY code=%d message=%s", req_ctx->client->fd, code, msg);

		/* Create the request */
		if (!metaXServer_reply_simple(&answer, req_ctx->request, code, msg, NULL)) {
			g_error("Memory allocation faire");
			return ;
		}

		/* add the body and the headers */
		if (body) {
			message_set_BODY(answer, body->data, body->len, NULL);
			metautils_gba_unref(body);
			body = NULL;
		}
		if (headers) {
			GHashTableIter iter;
			gpointer n, v;
			g_hash_table_iter_init(&iter, headers);
			while (g_hash_table_iter_next(&iter, &n, &v)) {
				if (!n || !v)
					continue;
				message_add_field(answer, (gchar*)n, strlen((gchar*)n),
						((GByteArray*)v)->data, ((GByteArray*)v)->len, NULL);
			}
		}

		/* encode and send */
		if ((req_ctx->final_sent = is_code_final(code))) {
			struct log_item_s log;
			log.req_ctx = req_ctx;
			log.code = code;
			log.msg = msg;
			log.out_len = 0;
			network_client_log_access(&log);
		}
		_reply_message(req_ctx->client, answer);
	}
	void _send_error(gint code, GError *e) {
		EXTRA_ASSERT(!req_ctx->final_sent);
		if (!e) {
			GRID_WARN("code=%d but no error", code);
			_send_reply(code, "OK");
		}
		else {
			_add_body(NULL);
			if (code)
				e->code = code;
			if (e->code < 300)
				e->code += 500;
			_send_reply(e->code, e->message);
			g_clear_error(&e);
		}
	}
	void _uid(const gchar *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		metautils_str_reuse(&req_ctx->uid, g_strdup_vprintf(fmt, args));
		va_end(args);
	}
	void _subject(const gchar *fmt, ...) {
		va_list args;
		va_start(args, fmt);
		metautils_str_reuse(&req_ctx->subject, g_strdup_vprintf(fmt, args));
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
		rc = _client_reply_fixed(req_ctx, 404, "No handler found");
		_notify_request(req_ctx,
				GRID_STAT_PREFIX_REQ ".UNEXPECTED", 
				GRID_STAT_PREFIX_TIME".UNEXPECTED");
	}
	else {
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
_request_get_cid (struct message_s *request)
{
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];
	GError *err = message_extract_cid(request, "CONTAINER_ID", &cid);
	if (err) {
		g_clear_error(&err);
		return NULL;
	}
	container_id_to_string(cid, strcid, sizeof(strcid));
	return g_strdup(strcid);
}


static gboolean
_client_manage_l4v(struct network_client_s *client, GByteArray *gba)
{
	gchar hexid[65];
	struct req_ctx_s req_ctx;
	gboolean rc = FALSE;
	GError *err = NULL;
	MESSAGE request = NULL;
	gsize offset;

	EXTRA_ASSERT(gba != NULL);
	EXTRA_ASSERT(client != NULL);
	memset(&req_ctx, 0, sizeof(req_ctx));

	if (!message_create(&request, NULL)) {
		g_warning("Memory allocation failure");
		return FALSE;
	}

	req_ctx.uid = NULL;
	req_ctx.subject = NULL;
	req_ctx.final_sent = FALSE;
	req_ctx.client = client;
	req_ctx.transport = &(client->transport);
	req_ctx.clt_ctx = req_ctx.transport->client_context;
	req_ctx.disp = req_ctx.clt_ctx->dispatcher;

	offset = gba->len;
	int asn1_rc = message_unmarshall(request, gba->data, &offset, &err);

	// take the encoding into account
	memcpy(&req_ctx.tv_start, &client->time.evt_in, sizeof(req_ctx.tv_start));
	network_server_now(&req_ctx.tv_parsed);

	if (!asn1_rc) {
		struct log_item_s log;
		log.req_ctx = &req_ctx;
		log.code = 400;
		log.msg = "Malformed ASN.1/BER Message";
		log.out_len = 0;
		network_client_log_access(&log);
		GRID_INFO("fd=%d ASN.1 decoder error: (%d) %s",
				client->fd, err->code, err->message);
		goto label_exit;
	}

	req_ctx.request = request;
	req_ctx.reqname = _request_get_name(request);
	req_ctx.uid = _request_get_cid(request);
	req_ctx.reqid = _req_get_hex_ID(request, hexid, sizeof(hexid));
	rc = TRUE;

	if (!req_ctx.reqname) {
		_client_reply_fixed(&req_ctx, 400, "Invalid/No request name");
		goto label_exit;
	}

	GRID_TRACE("fd=%d ACCESS [%s]", client->fd, hashstr_str(req_ctx.reqname));

	rc = _client_call_handler(&req_ctx);

	if (!req_ctx.final_sent) {
		_client_reply_fixed(&req_ctx, 500, "BUG : no reply sent");
		rc = FALSE;
	}

label_exit:
	if (request)
		message_destroy(request, NULL);
	if (err)
		g_clear_error(&err);
	if (req_ctx.reqname)
		g_free(req_ctx.reqname);
	metautils_str_clean(&req_ctx.subject);
	metautils_str_clean(&req_ctx.uid);
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
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
dispatch_PING(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata;
	(void) hdata;
	reply->send_reply(200, "PONG");
	return TRUE;
}

static gboolean
dispatch_STATS(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	gboolean runner(const gchar *n, guint64 v) {
		gchar *name, value[64];
		name = g_strdup_printf("stat:%s", n);
		g_snprintf(value, sizeof(value), "%"G_GUINT64_FORMAT, v);
		reply->add_header(name, metautils_gba_from_string(value));
		g_free(name);
		return TRUE;
	}

	(void) gdata;
	(void) hdata;
	grid_stats_holder_foreach(reply->client->main_stats, NULL, runner);	
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
dispatch_VERSION(struct gridd_reply_ctx_s *reply,
		gpointer gdata, gpointer hdata)
{
	(void) gdata;
	(void) hdata;
	reply->send_reply(200, *(API_VERSION) ? API_VERSION : "unknown");
	return TRUE;
}

const struct gridd_request_descr_s*
gridd_get_common_requests(void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{"PING",          dispatch_PING,          NULL},
		{"REQ_STATS",     dispatch_STATS,         NULL},
		{"REQ_VERSION",   dispatch_VERSION,       NULL},
		{"REQ_HANDLERS",  dispatch_LISTHANDLERS,  NULL},
		{NULL, NULL, NULL}
	};

	return descriptions;
}

