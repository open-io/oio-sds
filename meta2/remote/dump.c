#include "internals.h"

struct dump_ctx_s {
	struct meta2_dumpv1_hooks_remote_s hooks;
	gpointer u;
};

static gint
manage_contents(GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	struct dump_ctx_s *ctx = udata;
	GSList *result = NULL;

	(void) code;
	g_assert(ctx != NULL);
	TRACE("<%s>", __FUNCTION__);
	
	if (!meta2_raw_content_v2_unmarshall(&result, body, &bodySize, err)) {
		GSETERROR(err, "Decode error");
		return 0;
	}

	if (!ctx->hooks.on_content) {
		g_slist_foreach(result, meta2_raw_content_v2_gclean, NULL);
	}
	else {
		GSList *l;
		gboolean may_continue = TRUE;

		for (l=result; l && may_continue ;l=l->next) {
			if (!l->data)
				continue;
			if (!ctx->hooks.on_content(ctx->u, l->data))
				may_continue = FALSE;
			l->data = NULL;
		}
		g_slist_foreach(l, meta2_raw_content_v2_gclean, NULL);
	}
	g_slist_free(result);

	return 1;
}

static gint
manage_properties(GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
	struct dump_ctx_s *ctx = udata;
	GSList *l, *result = NULL;

	g_assert(ctx);
	TRACE("<%s>", __FUNCTION__);

	if (!meta2_property_concat(err, &result, code, body, bodySize)) {
		GSETERROR(err, "Decode error");
		return 0;
	}

	if (!ctx->hooks.on_property)
		g_slist_foreach(result, meta2_property_gclean, NULL);
	else {
		gboolean may_continue = TRUE;
		for (l=result; l && may_continue ;l=l->next) {
			if (!l->data)
				continue;
			if (!ctx->hooks.on_property(ctx->u, l->data))
				may_continue = FALSE;
		}
		g_slist_foreach(l, meta2_property_gclean, NULL);
	}
	g_slist_free(result);

	return 1;
}

static gint
manage_admin(GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
        struct dump_ctx_s *ctx = udata;
        GSList *l, *result = NULL;

        g_assert(ctx);
	TRACE("<%s>", __FUNCTION__);

	if (!key_value_pairs_concat(err, &result, code, body, bodySize)) {
		GSETERROR(err, "Decode error");
		return 0;
	}

	if (!ctx->hooks.on_admin)
		g_slist_foreach(result, key_value_pair_gclean, NULL);
	else {
		gboolean may_continue = TRUE;
		for (l=result; l && may_continue ;l=l->next) {
			if (!l->data)
				continue;
			if (!ctx->hooks.on_admin(ctx->u, l->data))
				may_continue = FALSE;
			l->data = NULL;
		}
		g_slist_foreach(l, key_value_pair_gclean, NULL);
	}
	g_slist_free(result);

	return 1;
}

static gint
manage_events(GError **err, gpointer udata, gint code, guint8 *body, gsize bodySize)
{
        struct dump_ctx_s *ctx = udata;
        GSList *l, *result = NULL;

        g_assert(ctx != NULL);
	TRACE("<%s>", __FUNCTION__);

	if (!container_event_concat(err, &result, code, body, bodySize)) {
		GSETERROR(err, "Decode error");
		return 0;
	}

	if (!ctx->hooks.on_event)
		g_slist_foreach(result, container_event_gclean, NULL);
	else {
		gboolean may_continue = TRUE;
		for (l=result; l && may_continue ;l=l->next) {
			if (!l->data)
				continue;
			if (!ctx->hooks.on_event(ctx->u, l->data))
				may_continue = FALSE;
		}
		g_slist_foreach(l, container_event_gclean, NULL);
	}
	g_slist_free(result);

	return 1;
}

status_t
meta2_remote_dumpv1_container(struct metacnx_ctx_s *ctx, const container_id_t container_id, 
		struct meta2_dumpv1_hooks_remote_s *hooks, gpointer u, GError **err)
{
	static struct code_handler_s codes [] = {
		{ 200, REPSEQ_FINAL, NULL, NULL },
		{ 201, REPSEQ_BODYMANDATORY, manage_contents, NULL },
		{ 202, REPSEQ_BODYMANDATORY, manage_admin, NULL },
		{ 203, REPSEQ_BODYMANDATORY, manage_properties, NULL },
		{ 204, REPSEQ_BODYMANDATORY, manage_events, NULL },
		{ 0,0,NULL,NULL}
	};
	
	struct dump_ctx_s dump_ctx;
	struct reply_sequence_data_s data = { &dump_ctx , 0 , codes };
	MESSAGE request = NULL;
	status_t status = 0;

	if (!ctx || !container_id) {
		GSETERROR(err,"Invalid parameter (container_id=%p)" , (void*)container_id);
		goto error_check;
	}

	request = meta2_remote_build_request( err, ctx->id, "REQ_M2RAW_DUMP_CONTAINER");
	if (!request) {
		GSETERROR(err,"Memory allocation failure");
		goto error_check;
	}

	/*prepare the request, fill all the fields*/
	if (!message_add_field(request, "CONTAINER_ID", sizeof("CONTAINER_ID")-1,
			(guint8*)container_id, sizeof(container_id_t), err)) {
		GSETERROR(err,"Request configuration failure");
		goto error_label;
	}

	/*Now send the request*/
	if (!metacnx_open(ctx, err)) {
		GSETERROR(err,"Failed to open the connexion");
		goto error_label;
	}

	memcpy(&(dump_ctx.hooks), hooks, sizeof(dump_ctx.hooks));
	dump_ctx.u = u;
	if (!metaXClient_reply_sequence_run_context (err, ctx, request, &data)) {
		GSETERROR(err,"Cannot execute the query and receive all the responses");
		goto error_label;
	}

	status = 1;
error_label:
	message_destroy(request,NULL);
error_check:
	return status;
}

