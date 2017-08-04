/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#include <glib.h>

#include <core/internals.h>
#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <events/oio_events_queue.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <cluster/lib/gridcluster.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

enum content_action_e
{
	PUT=1,
	APPEND,
	DELETE,
};

static void
_m2b_notify_beans(struct meta2_backend_s *m2b, struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks)
{
	guint n_events = 1;
	guint cur_event = 0;
	void forward(GSList *list_of_beans) {
		gchar tmp[256];
		g_snprintf (tmp, sizeof(tmp), "%s.%s", META2_EVENTS_PREFIX, name);

		GString *gs = oio_event__create(tmp, url);
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair_int(gs, "part", cur_event++);
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair_int(gs, "parts", n_events);
		g_string_append_static (gs, ",\"data\":[");
		meta2_json_dump_all_xbeans (gs, list_of_beans);
		g_string_append_static (gs, "]}");
		oio_events_queue__send (m2b->notifier, g_string_free (gs, FALSE));
	}

	if (!m2b->notifier)
		return;

	guint beans_len = g_slist_length(beans);
	if (!send_chunks) {
		GSList *non_chunks = NULL;
		for (GSList *l = beans; l; l = l->next) {
			if (DESCR(l->data) != &descr_struct_CHUNKS)
				non_chunks = g_slist_prepend(non_chunks, l->data);
		}
		forward(non_chunks);
		g_slist_free(non_chunks);
	} else if (beans_len < 16) {
		forward(beans);
	} else {
		/* first, notify everything but the chunks */
		GSList *non_chunks = NULL;
		struct bean_CONTENTS_HEADERS_s *header = NULL;
		for (GSList *l = beans; l; l = l->next) {
			if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
				if (header)
					GRID_WARN("Several content headers in same event!");
				else
					header = l->data;
				non_chunks = g_slist_prepend (non_chunks, l->data);
			} else if (&descr_struct_CHUNKS != DESCR(l->data)) {
				non_chunks = g_slist_prepend (non_chunks, l->data);
			}
		}
		n_events += 1 + (beans_len - g_slist_length(non_chunks)) / 16;
		if (non_chunks) {
			forward (non_chunks);
			g_slist_free (non_chunks);
		}

		if (!header)
			GRID_WARN("No content header in event data! (type: %s)", name);

		/* then notify each chunks by batches of 16 items */
		GSList *batch = NULL;
		guint count = 0;
		for (GSList *l = beans; l; l = l->next) {
			if (&descr_struct_CHUNKS != DESCR(l->data))
				continue;
			batch = g_slist_prepend (batch, l->data);
			if (!((++count)%16)) {
				/* We send the header each time because the event handlers
				 * may need the chunk method, which is not saved in chunks. */
				if (header)
					batch = g_slist_prepend(batch, header);
				forward (batch);
				g_slist_free (batch);
				batch = NULL;
			}
		}
		if (batch) {
			if (header)
				batch = g_slist_prepend(batch, header);
			forward (batch);
			g_slist_free (batch);
			batch = NULL;
		}
	}
}

static GError*
_check_content(struct gridd_filter_ctx_s * ctx,
		struct gridd_reply_ctx_s *reply)
{
	const gboolean is_update = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_UPDATE, FALSE);

	GSList *beans = NULL;
	GError *e = metautils_message_extract_body_encoded (
			reply->request, TRUE, &beans, bean_sequence_decoder);
	if (NULL != e)
		return NULL;

	GString *message = g_string_new("");
	e = meta2_backend_check_content(ctx->backend, beans, message, is_update);
	if (!e) {
		g_string_free(message, TRUE);
		return NULL;
	}

	GString *gs = oio_event__create("storage.content.broken", ctx->base.url);
	g_string_append(gs, ",\"data\":{");
	g_string_append(gs, message->str);
	g_string_free(message, TRUE);
	g_string_append(gs, "}}");
	oio_events_queue__send (ctx->backend->notifier, g_string_free (gs, FALSE));

	if (e->code != CODE_CONTENT_CORRUPTED) {
		g_clear_error(&e);
		return NULL;
	}

	return NULL;
}

static int
_put_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GSList *added = NULL, *deleted = NULL, *beans = NULL;

	const gboolean overwrite = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_OVERWRITE, FALSE);
	const gboolean update = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_UPDATE, FALSE);

	GError *e = metautils_message_extract_body_encoded (
			reply->request, TRUE, &beans, bean_sequence_decoder);
	if (e) {
		_bean_cleanl2 (beans);
		return _reply_no_body(ctx, reply, e);
	}

	if (overwrite) {
		reply->subject("(overwrite)");
		e = meta2_backend_force_alias(ctx->backend, &ctx->base, beans, &deleted, &added);
	} else if (update) {
		reply->subject("(update)");
		e = meta2_backend_update_content(ctx->backend, &ctx->base, beans, &deleted, &added);
	} else {
		/* TODO(jfs): the event should not be sent prior to the information saved in the DB */
		e = _check_content(ctx, reply);
		if (!e)
			e = meta2_backend_put_alias(ctx->backend, &ctx->base, beans, &deleted, &added);
	}

	if (!e) {
		_m2b_notify_beans(ctx->backend, ctx->base.url, added, "content.new", FALSE);
		if (deleted)
			_m2b_notify_beans(ctx->backend, ctx->base.url, deleted, "content.deleted", TRUE);
	}

	_bean_cleanl2 (added);
	_bean_cleanl2 (deleted);
	return _reply_no_body(ctx, reply, e);
}

int
meta2_filter_action_check_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	const gboolean is_update = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_UPDATE, FALSE);

	GSList *beans = NULL;
	GError *e = metautils_message_extract_body_encoded (
			reply->request, TRUE, &beans, bean_sequence_decoder);
	if (e) {
		_bean_cleanl2 (beans);
		return _reply_no_body(ctx, reply, e);
	}

	int rc;
	GString *message= g_string_new("");
	e = meta2_backend_check_content(ctx->backend, beans, message, is_update);
	if (e) {
		GString *gs = oio_event__create("storage.content.broken", ctx->base.url);
		g_string_append(gs, ",\"data\":{");
		g_string_append(gs, message->str);
		g_string_append(gs, "}}");
		oio_events_queue__send (ctx->backend->notifier, g_string_free (gs, FALSE));
		if (e->code == CODE_CONTENT_CORRUPTED)
			rc = FILTER_KO;
		g_clear_error(&e);
	}
	g_string_free(message, TRUE);
	return rc;
}

static int
_copy_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		const char *source)
{
	GError *e = meta2_backend_copy_alias(ctx->backend, &ctx->base, source);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);

	GSList *beans = NULL;
	e = meta2_backend_get_alias(ctx->backend, &ctx->base,
			M2V2_FLAG_NOPROPS, _bean_list_cb, &beans);
	/* TODO(jfs): notify the beans */
	return _reply_beans_and_clean(reply, beans);
}

int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gchar source[LIMIT_LENGTH_CONTENTPATH] = "";
	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_COPY, source, sizeof(source));

	if (!oio_str_is_set(source))
		return _put_alias(ctx, reply);

	reply->subject("%s|%s|COPY(%s)",
			oio_url_get(ctx->base.url, OIOURL_WHOLE),
			oio_url_get(ctx->base.url, OIOURL_HEXID),
			source);
	return _copy_alias(ctx, reply, source);
}

int
meta2_filter_action_append_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e;

	GSList *beans_in = NULL;
	e = metautils_message_extract_body_encoded(reply->request, TRUE, &beans_in, bean_sequence_decoder);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);

	GSList *beans_out = NULL;
	e = meta2_backend_append_to_alias(ctx->backend, &ctx->base,
			beans_in, _bean_list_cb, &beans_out);
	_bean_cleanl2(beans_in);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);

	_m2b_notify_beans(ctx->backend, ctx->base.url, beans_out, "content.append", FALSE);
	_bean_cleanl2(beans_out);
	return _reply_no_body(ctx, reply, NULL);
}

int
meta2_filter_action_get_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	guint32 flags = 0;
	metautils_message_extract_flags32(reply->request, NAME_MSGKEY_FLAGS, &flags);

	GSList *beans_out = NULL;
	GError *e = meta2_backend_get_alias(ctx->backend, &ctx->base, flags, _bean_list_cb, &beans_out);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);

	for (GSList *l = beans_out; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS &&
				!strcmp(CONTENTS_HEADERS_get_chunk_method(l->data)->str,
						CHUNK_METHOD_DRAINED)) {
			e = NEWERROR(CODE_CONTENT_DRAINED, "The content is drained");
			goto cleanup;
		}
	}

	return _reply_beans_and_clean(reply, beans_out);
cleanup:
	_bean_cleanl2(beans_out);
	return _reply_no_body(ctx, reply, e);
}

int
meta2_filter_action_drain_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans_out = NULL;
	GError *e = meta2_backend_drain_content(ctx->backend, &ctx->base, _bean_list_cb, &beans_out);
	if (e != NULL)
		return _reply_no_body(ctx, reply, e);

	_m2b_notify_beans(ctx->backend, ctx->base.url, beans_out, "content.drained", TRUE);
	_bean_cleanl2(beans_out);
	return _reply_no_body(ctx, reply, NULL);
}

int
meta2_filter_action_delete_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans_out = NULL;
	GError *e = meta2_backend_delete_alias(ctx->backend, &ctx->base, _bean_list_cb, &beans_out);
	if (e)
		return _reply_no_body(ctx, reply, e);

	_m2b_notify_beans(ctx->backend, ctx->base.url, beans_out, "content.deleted", TRUE);
	_bean_cleanl2(beans_out);
	return _reply_no_body(ctx, reply, NULL);
}

int
meta2_filter_action_truncate_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gint64 truncate_size = 0;
	GError *err = metautils_message_extract_strint64(reply->request, NAME_MSGKEY_CONTENTLENGTH, &truncate_size);
	if (err)
		return _reply_no_body(ctx, reply, err);

	GSList *added = NULL, *deleted = NULL;
	err = meta2_backend_truncate_content(ctx->backend, &ctx->base, truncate_size,
			&deleted, &added);
	if (err)
		return _reply_no_body(ctx, reply, err);

	if (deleted)
		_m2b_notify_beans(ctx->backend, ctx->base.url, deleted, "content.deleted", TRUE);
	if (added)
		_m2b_notify_beans(ctx->backend, ctx->base.url, added, "content.new", FALSE);

	_bean_cleanl2(added);
	_bean_cleanl2(deleted);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans_in = NULL;
	GError *e = metautils_message_extract_body_encoded (reply->request,
			FALSE, &beans_in, bean_sequence_decoder);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);

	const gboolean flush = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FLUSH, FALSE);

	GSList *beans_out = NULL;
	e = meta2_backend_set_properties(ctx->backend, &ctx->base,
				flush, beans_in, _bean_list_cb, &beans_out);
	_bean_cleanl2(beans_in);
	beans_in = NULL;

	if (NULL != e)
		return _reply_no_body(ctx, reply, e);
	return _reply_beans_and_clean(reply, beans_out);
}

int
meta2_filter_action_get_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	guint32 flags = 0;
	metautils_message_extract_flags32(reply->request, NAME_MSGKEY_FLAGS, &flags);

	GSList *beans = NULL;
	GError *e = meta2_backend_get_properties(ctx->backend, &ctx->base, flags, _bean_list_cb, &beans);
	if (NULL != e)
		return _reply_no_body(ctx, reply, e);
	return _reply_beans_and_clean(reply, beans);
}

int
meta2_filter_action_del_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);

	gchar **namev = NULL;
	GError *e = STRV_decode_buffer(buf, len, &namev);
	if (!e) {
		e = meta2_backend_del_properties(ctx->backend, &ctx->base, namev);
		g_strfreev(namev);
	}

	return _reply_no_body(ctx, reply, e);
}

static GError*
_spare_with_blacklist(
		struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		GSList **beans_out, const char *polname)
{
	GSList *notin = NULL, *broken = NULL;

	GSList *beans_in = NULL;
	GError *err = metautils_message_extract_body_encoded(reply->request,
			TRUE, &beans_in, bean_sequence_decoder);
	if (!err) {
		for (GSList *beans = beans_in; beans != NULL; beans = beans->next) {
			if (DESCR(beans->data) != &descr_struct_CHUNKS)
				continue;
			if (CHUNKS_get_size(beans->data) == -1)
				broken = g_slist_prepend(broken, beans->data);
			else
				notin = g_slist_prepend(notin, beans->data);
		}
		err = meta2_backend_get_conditionned_spare_chunks_v2(
				ctx->backend, &ctx->base,
				polname, notin, broken, beans_out);
	}

	g_slist_free(notin);
	g_slist_free(broken);
	_bean_cleanl2(beans_in);
	return err;
}

int
meta2_filter_action_generate_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar policy[LIMIT_LENGTH_STGPOLICY] = "",
		  spare_type[LIMIT_LENGTH_SRVTYPE] = "",
		  strsize[32] = "";

	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_STGPOLICY, policy, sizeof(policy));
	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_SPARE, spare_type, sizeof(spare_type));
	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_CONTENTLENGTH, strsize, sizeof(strsize));

	const gboolean append = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_APPEND, FALSE);

	GSList *beans = NULL;
	if (oio_str_is_set(spare_type)) {  /* Spare beans request */
		reply->subject("%s|%s|%s",
				oio_url_get(ctx->base.url, OIOURL_WHOLE),
				oio_url_get(ctx->base.url, OIOURL_HEXID), spare_type);
		if (strcmp(spare_type, M2V2_SPARE_BY_BLACKLIST) == 0) {
			e = _spare_with_blacklist(ctx, reply, &beans, policy);
		} else if (strcmp(spare_type, M2V2_SPARE_BY_STGPOL) == 0) {
			e = meta2_backend_get_spare_chunks(ctx->backend, &ctx->base,
					policy, &beans);
		} else {
			e = BADREQ("Unknown type of spare request: %s", spare_type);
		}
	} else {  /* Standard beans request */
		gint64 size = 0;
		e = metautils_message_extract_strint64(reply->request,
				NAME_MSGKEY_CONTENTLENGTH, &size);
		if (!e) {
			e = meta2_backend_generate_beans(ctx->backend, &ctx->base,
					size, policy, append, _bean_list_cb, &beans);
		}
	}

	if (NULL != e) {
		_bean_cleanl2(beans);
		return _reply_no_body(ctx, reply, e);
	}
	return _reply_beans_and_clean(reply, beans);
}

int
meta2_filter_action_touch_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans = NULL;
	GError *err = meta2_backend_get_alias( ctx->backend, &ctx->base,
			M2V2_FLAG_ALLPROPS|M2V2_FLAG_HEADERS, _bean_list_cb, &beans);
	if (!err && beans)
		_m2b_notify_beans(ctx->backend, ctx->base.url, beans, "content.new", FALSE);
	_bean_cleanl2(beans);
	return _reply_no_body(ctx, reply, err);
}
