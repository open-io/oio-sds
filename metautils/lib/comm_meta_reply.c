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

static inline gdouble
ms_to_s(int ms)
{
	gdouble dms = ms;
	return dms / 1000.0;
}

gint
metaXServer_reply_simple(MESSAGE * reply, MESSAGE request, gint code,
		const gchar * message, GError ** err)
{
	MESSAGE tmpReply = NULL;

	if (!reply || !request) {
		GSETERROR(err, "Invalid parameter");
		return 0;
	}

	if (!message_create(&tmpReply, err)) {
		GSETERROR(err, "Cannot create message");
		goto errorLabel;
	}

	if (!message_set_NAME(tmpReply, NAME_MSGNAME_METAREPLY, sizeof(NAME_MSGNAME_METAREPLY) - 1, err)) {
		GSETERROR(err, "Cannot set the NAME of the message");
		goto errorLabel;
	}

	/*If the original request carries an identifier, we keep it in the reply */
	if (0 < message_has_ID(request, NULL)) {
		void *mID;
		gsize mIDSize;

		mID = NULL;
		mIDSize = 0;
		if (0>=message_get_ID(request, &mID, &mIDSize, err) || 0>=message_set_ID(tmpReply, mID, mIDSize, err)) {
			GSETERROR(err, "Cannot copy the ID of the message");
			goto errorLabel;
		}
	}

	do {			/*If the original request carries a timestamp, we keep it in the reply */
		void *stamp = NULL;
		gsize stampLen = 0;

		switch (message_get_field(request, NAME_MSGKEY_TIMESTAMP, sizeof(NAME_MSGKEY_TIMESTAMP) - 1, &stamp,
			&stampLen, err)) {
		case 1:
			if (!message_add_field(tmpReply, NAME_MSGKEY_TIMESTAMP, sizeof(NAME_MSGKEY_TIMESTAMP) - 1,
				stamp, stampLen, err)) {
				GSETERROR(err, "Cannot copy the TIMESTAMP of the message");
				goto errorLabel;
			}
		case 0:
			break;
		case -1:
			GSETERROR(err, "Cannot copy the TIMESTAMP of the message");
			goto errorLabel;
		}
	} while (0);

	do {			/*ensures and formats the error code */
		gchar bufCode[4];

		if (code < 100)
			code = 598;
		if (code > 699)
			code = 699;
		g_snprintf(bufCode, 4, "%03i", code);

		if (!message_add_field(tmpReply, NAME_MSGKEY_STATUS, sizeof(NAME_MSGKEY_STATUS) - 1, bufCode, 3, err)) {
			GSETERROR(err, "%s", "Cannot add the status in the reply");
			goto errorLabel;
		}
	} while (0);

	/*writes the message */
	if (message) {
		if (!message_add_field(tmpReply, NAME_MSGKEY_MESSAGE, sizeof(NAME_MSGKEY_MESSAGE) - 1, message,
			strlen(message), err)) {
			GSETERROR(err, "%s", "Cannot add the error-message in the reply");
			goto errorLabel;
		}
	}

	*reply = tmpReply;

	return 1;
      errorLabel:
	if (tmpReply)
		message_destroy(tmpReply, NULL);

	return 0;
}


gint
metaXClient_reply_simple(MESSAGE reply, gint * status, gchar ** msg, GError ** err)
{
	/*sanity checks */
	if (!reply || !status || !msg) {
		GSETERROR(err, "%s", "Invalid parameter");
		return 0;
	}

	*msg = NULL;
	*status = 0;

	/*check it is an answer */
	{
		gsize nameSize = 0;
		gchar *name = NULL;

		switch (message_has_NAME(reply, NULL)) {
		case 0:
			GSETERROR(err, "The message cannot be a reply (%s)", "no name is present");
		case -1:
			goto errorLabel;
		}

		if (!message_get_NAME(reply, (void *) &name, &nameSize, err))
			goto errorLabel;

		if (0 != g_ascii_strncasecmp(name, NAME_MSGNAME_METAREPLY, MIN(sizeof(NAME_MSGNAME_METAREPLY) - 1, nameSize))) {
			GSETERROR(err, "The message cannot be a reply (%s)",
			    "invalid message name, '" NAME_MSGNAME_METAREPLY "' expected");
			goto errorLabel;
		}
	}

	{			/*get the message (copy) if present */
		gchar *tmpMsg = NULL, *newMsg = NULL;
		gsize tmpMsgSize = 0, i;

		switch (message_get_field(reply, NAME_MSGKEY_MESSAGE, sizeof(NAME_MSGKEY_MESSAGE) - 1, (void *) &tmpMsg,
			&tmpMsgSize, err)) {
		case 1:
			newMsg = g_try_malloc0(sizeof(gchar) * (tmpMsgSize + 1));
			if (!newMsg) {
				GSETERROR(err, "%s", "Memory allocation error");
				goto errorLabel;
			}
			memcpy(newMsg, tmpMsg, tmpMsgSize);
			newMsg[tmpMsgSize] = '\0';

			/*check the message is pure ASCII */
			for (i = 0; i < tmpMsgSize; i++) {
				if (!g_ascii_isprint(newMsg[i]) && !g_ascii_isspace(newMsg[i]))
					newMsg[i] = '?';
			}

			*msg = newMsg;
			break;
		case 0:
			*msg = NULL;
			break;
		case -1:
			*msg = NULL;
			goto errorLabel;
		}
	}

	{			/*XXX MANDATORY XXX get the status */
		gchar *tmpStatus = NULL, *end = NULL, wrkStatus[4] = { 0, 0, 0, 0 };
		gsize tmpStatusSize = 0;

		switch (message_get_field(reply, NAME_MSGKEY_STATUS, sizeof(NAME_MSGKEY_STATUS) - 1,
			(void *) &tmpStatus, &tmpStatusSize, err)) {
		case 0:
			GSETERROR(err, "%s", "Status not found");
		case -1:
			goto errorLabel;
		}

		if (tmpStatusSize != 3) {
			GSETERROR(err, "Status has a bad size : [%d]", tmpStatusSize);
			goto errorLabel;
		}

		wrkStatus[0] = tmpStatus[0];
		wrkStatus[1] = tmpStatus[1];
		wrkStatus[2] = tmpStatus[2];
		*status = (gint) g_ascii_strtoull(wrkStatus, &end, 10);
		if (end != wrkStatus + 3) {
			GSETERROR(err, "%s", "Invalid status format");
			goto errorLabel;
		}
	}

	return 1;
      errorLabel:
	if (*msg)
		g_free(*msg);

	return 0;
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
rep_handler(gpointer u, struct message_s *reply)
{
	struct repseq_ctx_s *ctx = u;
	int rc=TRUE, body;
	gint64 s64 = 0;
	struct code_handler_s *h;

	ctx->err = message_extract_strint64(reply, "STATUS", &s64);
	if (ctx->err != NULL)
		return FALSE;

	if (!(h = _find_handler(ctx->data, s64))) { // Unexpected reply received
		ctx->err = NEWERROR(500, "Unexpected reply status [%"G_GINT64_FORMAT"]", s64);
		return FALSE;
	}

	/* BODY management */
	body = message_has_BODY(reply, NULL);

	if ((h->flags & REPSEQ_BODYMANDATORY) && body <= 0) {
		ctx->err = NEWERROR(500, "Missing body (mandatory for status " "[%"G_GINT64_FORMAT"])", s64);
		return FALSE;
	}

	if (body > 0 && h->content_handler) { // call the body handler
		void *b = NULL;
		gsize blen = 0;
		message_get_BODY(reply, &b, &blen, NULL);
		rc = h->content_handler(&(ctx->err), ctx->data->udata, s64, b, blen);
		if (!rc || ctx->err != NULL) {
			if (!ctx->err)
				ctx->err = NEWERROR(500, "Unknown content handler error for status [%"G_GINT64_FORMAT"]", s64);
			return FALSE;
		}
	}

	/* REPLY management */

	if (h->msg_handler) {
		rc = h->msg_handler(&(ctx->err), ctx->data->udata, s64, reply);
		if (!rc || ctx->err != NULL) {
			if (!ctx->err)
				ctx->err = NEWERROR(500, "Unknown reply handler error for status [%"G_GINT64_FORMAT"]", s64);
			return FALSE;
		}
	}

	if (h->flags & REPSEQ_ERROR) {
		ctx->err = NEWERROR(500, "ReplySequence error : explicit bad code [%"G_GINT64_FORMAT"]", s64);
		return FALSE;
	}

	return TRUE;
}

static GError*
_repseq_run(struct message_s *req, struct metacnx_ctx_s *cnx,
		struct reply_sequence_data_s *data)
{
	struct repseq_ctx_s ctx;

	if (cnx == NULL || req == NULL || data == NULL)
		return NEWERROR(1, "BUG : Invalid parameters");

	memset(&ctx, 0, sizeof(ctx));
	ctx.data = data;

	struct client_s *client = gridd_client_create_empty();

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
	}
	else {
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
		addr_info_t * addr, gint ms, struct reply_sequence_data_s * h)
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

	return sock_get_error(ctx->fd) ? FALSE : TRUE;
}

void
metacnx_close(struct metacnx_ctx_s *ctx)
{
	if (!ctx)
		return;
	metautils_pclose(&(ctx->fd));
}

struct metacnx_ctx_s *
metacnx_create(GError ** err)
{
	gsize i;
	struct metacnx_ctx_s *ctx;

	ctx = g_try_malloc0(sizeof(struct metacnx_ctx_s));
	if (!ctx) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	ctx->fd = -1;
#define IDSIZE (4*sizeof(int))
	ctx->id = g_byte_array_sized_new(IDSIZE);

	for (i = sizeof(int); i < IDSIZE; i += sizeof(int)) {
		int r = random();
		g_byte_array_append(ctx->id, (guint8 *) (&r), sizeof(int));
	}

	return ctx;
}

void
metacnx_destroy(struct metacnx_ctx_s *ctx)
{
	if (!ctx)
		return;
	if (ctx->id)
		g_byte_array_free(ctx->id, TRUE);
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
