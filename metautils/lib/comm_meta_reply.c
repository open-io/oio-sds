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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include "./metautils.h"
#include "./metacomm.h"
#include "./gridd_client.h"
#include "./gridd_client_ext.h"

static gdouble
ms_to_s(int ms)
{
	gdouble dms = ms;
	return dms / 1000.0;
}

MESSAGE
metaXServer_reply_simple(MESSAGE request, gint code, const gchar *message)
{
	EXTRA_ASSERT (request != NULL);
	MESSAGE reply = message_create_named(NAME_MSGNAME_METAREPLY);

	gsize mIDSize = 0;
	void *mID = message_get_ID (request, &mIDSize);
	if (mID && mIDSize)
		message_set_ID (reply, mID, mIDSize);

	if (CODE_IS_NETWORK_ERROR(code))
		code = CODE_PROXY_ERROR;
	message_add_field_strint(reply, NAME_MSGKEY_STATUS, code);

	if (message)
		message_add_field_str (reply, NAME_MSGKEY_MESSAGE, message);
	return reply;
}

GError *
metaXClient_reply_simple(MESSAGE reply, guint * status, gchar ** msg)
{
	EXTRA_ASSERT (reply != NULL);
	EXTRA_ASSERT (status != NULL);
	EXTRA_ASSERT (msg != NULL);

	GError *err = message_extract_struint(reply, NAME_MSGKEY_STATUS, status);
	if (err) {
		g_prefix_error (&err, "Invalid reply: no status: ");
		return err;
	}
	*msg = message_extract_string_copy(reply, NAME_MSGKEY_MESSAGE);
	if (!*msg)
		*msg = g_strdup("?");
	return NULL;
}

struct repseq_ctx_s
{
	struct reply_sequence_data_s *data;
	GError *err;
};

static struct code_handler_s*
_find_handler(struct reply_sequence_data_s *data, int code)
{
	struct code_handler_s *h;
	for (h=data->codes; h->code != 0 ;h++) {
		if (h->code < 0 || h->code == code)
			return h;
	}
	return NULL;
}

static gboolean
rep_handler(gpointer u, MESSAGE reply)
{
	struct repseq_ctx_s *ctx = u;
	int rc=TRUE;
	gint64 s64 = 0;
	struct code_handler_s *h;

	ctx->err = message_extract_strint64(reply, NAME_MSGKEY_STATUS, &s64);
	if (ctx->err != NULL)
		return FALSE;

	if (!(h = _find_handler(ctx->data, s64))) { // Unexpected reply received
		ctx->err = NEWERROR(CODE_INTERNAL_ERROR, "Unexpected reply status [%"G_GINT64_FORMAT"]", s64);
		return FALSE;
	}

	/* BODY management */
	gsize bodylen = 0;
	void *body = message_get_BODY(reply, &bodylen);

	if ((h->flags & REPSEQ_BODYMANDATORY) && (!body || !bodylen)) {
		ctx->err = NEWERROR(CODE_INTERNAL_ERROR, "Missing body (mandatory for status " "[%"G_GINT64_FORMAT"])", s64);
		return FALSE;
	}

	if (body && bodylen && h->content_handler) { // call the body handler
		rc = h->content_handler(&(ctx->err), ctx->data->udata, s64, body, bodylen);
		if (!rc || ctx->err != NULL) {
			if (!ctx->err)
				ctx->err = NEWERROR(CODE_INTERNAL_ERROR, "Unknown content handler error for status [%"G_GINT64_FORMAT"]", s64);
			return FALSE;
		}
	}

	/* REPLY management */

	if (h->msg_handler) {
		rc = h->msg_handler(&(ctx->err), ctx->data->udata, s64, reply);
		if (!rc || ctx->err != NULL) {
			if (!ctx->err)
				ctx->err = NEWERROR(CODE_INTERNAL_ERROR, "Unknown reply handler error for status [%"G_GINT64_FORMAT"]", s64);
			return FALSE;
		}
	}

	if (h->flags & REPSEQ_ERROR) {
		ctx->err = NEWERROR(CODE_INTERNAL_ERROR, "ReplySequence error : explicit bad code [%"G_GINT64_FORMAT"]", s64);
		return FALSE;
	}

	return TRUE;
}

static GError*
_repseq_run(MESSAGE req, struct metacnx_ctx_s *cnx,
		struct reply_sequence_data_s *data)
{
	struct repseq_ctx_s ctx;

	if (cnx == NULL || req == NULL || data == NULL)
		return NEWERROR(1, "BUG : Invalid parameters");

	memset(&ctx, 0, sizeof(ctx));
	ctx.data = data;

	struct gridd_client_s *client = gridd_client_create_empty();

	int keepalive = cnx->flags & METACNX_FLAGMASK_KEEPALIVE;
	gridd_client_set_keepalive(client, keepalive);

	int to = MAX(cnx->timeout.cnx, cnx->timeout.req);
	gridd_client_set_timeout(client, ms_to_s(to), ms_to_s(to));

	if (NULL == (ctx.err = gridd_client_set_fd(client, cnx->fd))) {
		cnx->fd = -1;
		GByteArray *gba = message_marshall_gba(req, NULL);
		ctx.err = gridd_client_request(client, gba, &ctx, rep_handler);
		g_byte_array_unref(gba);

		if (!ctx.err) { // Run the request
			gridd_client_start(client);
			if (!(ctx.err = gridd_client_loop(client)))
				ctx.err = gridd_client_error(client);
		}
	}

	cnx->fd = gridd_client_fd(client);
	(void) gridd_client_set_fd(client, -1);

	gridd_client_free(client);
	return ctx.err;
}

gboolean
metaXClient_reply_sequence_run_context(GError ** err, struct metacnx_ctx_s *cnx,
		MESSAGE request, struct reply_sequence_data_s * h)
{
	if (cnx == NULL || request == NULL || h == NULL) {
		GSETERROR(err, "BUG invalid parameter");
		return FALSE;
	}

	if (!metacnx_is_open(cnx) && !metacnx_open(cnx, err))
		return FALSE;

	GError *e;
	if (!(e = _repseq_run(request, cnx, h))) {
		if (!(cnx->flags & METACNX_FLAGMASK_KEEPALIVE))
			metacnx_close(cnx);
		return TRUE;
	} else {
		if (err && NULL == *err)
			g_propagate_error(err, e);
		else
			g_clear_error(&e);
		metacnx_close(cnx);
		return FALSE;
	}
}

gboolean
metaXClient_reply_sequence_run_from_addrinfo(GError ** err, MESSAGE request,
		const addr_info_t * addr, gint ms, struct reply_sequence_data_s * h)
{
	struct metacnx_ctx_s cnx;
	gboolean rc;

	if (addr == NULL || request == NULL || h == NULL) {
		GSETERROR(err, "BUG invalid parameter");
		return FALSE;
	}

	metacnx_clear(&cnx);
	metacnx_init_with_addr(&cnx, addr, NULL);
	cnx.timeout.cnx = cnx.timeout.req = ms;
	rc = metaXClient_reply_sequence_run_context(err, &cnx, request, h);
	metacnx_close(&cnx);
	metacnx_clear(&cnx);

	return rc;
}

gboolean
metaXClient_reply_sequence_run(GError ** err, MESSAGE req, int *fd, gint ms,
		struct reply_sequence_data_s *h)
{
	struct metacnx_ctx_s cnx;

	if (fd == NULL || req == NULL || h == NULL) {
		GSETERROR(err, "BUG invalid parameter");
		return FALSE;
	}

	metacnx_clear(&cnx);
	cnx.timeout.cnx = cnx.timeout.req = ms;
	cnx.fd = *fd;
	cnx.flags = METACNX_FLAGMASK_KEEPALIVE;
	gboolean rc = metaXClient_reply_sequence_run_context(err, &cnx, req, h);
	*fd = cnx.fd;
	cnx.fd = -1;
	metacnx_clear(&cnx);

	return rc;
}

/* ------------------------------------------------------------------------- */

void
metacnx_clear(struct metacnx_ctx_s *ctx)
{
	if (!ctx)
		return;
	memset(ctx, 0x00, sizeof(struct metacnx_ctx_s));
	ctx->fd = -1;
}

gboolean
metacnx_open(struct metacnx_ctx_s *ctx, GError ** err)
{
	if (!ctx) {
		GSETERROR(err, "invalid parameter");
		return FALSE;
	}
	if (metacnx_is_open(ctx))
		metacnx_close(ctx);
	ctx->fd = addrinfo_connect(&(ctx->addr), ctx->timeout.cnx, err);
	return ctx->fd >= 0;
}

gboolean
metacnx_is_open(struct metacnx_ctx_s * ctx)
{
	if (!ctx)
		return FALSE;
	if (ctx->fd < 0)
		return FALSE;

	return socket_get_errcode(ctx->fd) ? FALSE : TRUE;
}

void
metacnx_close(struct metacnx_ctx_s *ctx)
{
	if (!ctx)
		return;
	metautils_pclose(&(ctx->fd));
}

struct metacnx_ctx_s *
metacnx_create(void)
{
	struct metacnx_ctx_s *ctx = g_malloc0(sizeof(struct metacnx_ctx_s));
	ctx->fd = -1;
	return ctx;
}

void
metacnx_destroy(struct metacnx_ctx_s *ctx)
{
	if (!ctx)
		return;
	g_free(ctx);
}

gboolean
metacnx_init_with_url(struct metacnx_ctx_s *ctx, const gchar *url, GError ** err)
{
	if (!ctx || !url) {
		GSETERROR(err, "Invalid parameter ctx=%p url=%p", ctx, url);
		return FALSE;
	}

	if (!l4_address_init_with_url(&(ctx->addr), url, err))
		return FALSE;
	ctx->timeout.req = 60000;
	ctx->timeout.cnx = 30000;
	return TRUE;
}

gboolean
metacnx_init_with_addr(struct metacnx_ctx_s *ctx, const addr_info_t* addr, GError** err)
{
	if (!ctx) {
		GSETERROR(err, "Invalid parameter ctx=%p", ctx);
		return FALSE;
	}
	memcpy(&(ctx->addr), addr, sizeof(addr_info_t));
	ctx->timeout.req = 60000;
	ctx->timeout.cnx = 30000;
	return TRUE;
}

gboolean
metacnx_init(struct metacnx_ctx_s *ctx, const gchar * host, int port, GError ** err)
{
	addr_info_t *ai;
	gboolean rc;

	if (!ctx) {
		GSETERROR(err, "Invalid parameter ctx=%p", ctx);
		return FALSE;
	}
	ai = build_addr_info(host, port, err);
	if (!ai)
		return FALSE;
	rc = metacnx_init_with_addr(ctx, ai, err);
	g_free(ai);
	return rc;
}
