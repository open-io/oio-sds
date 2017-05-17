/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, as part of OpenIO Software Defined Storage

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
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2v2_remote.h>
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
		GSList *beans, const char *name)
{
	void forward (GSList *list_of_beans) {
		gchar tmp[256];
		g_snprintf (tmp, sizeof(tmp), "%s.%s", META2_EVENTS_PREFIX, name);

		GString *gs = oio_event__create (tmp, url);
		g_string_append (gs, ",\"data\":[");
		meta2_json_dump_all_xbeans (gs, list_of_beans);
		g_string_append (gs, "]}");
		oio_events_queue__send (m2b->notifier, g_string_free (gs, FALSE));
	}

	if (!m2b->notifier)
		return;

	if (g_slist_length (beans) < 16)
		forward (beans);
	else {
		/* first, notify everything but the chunks */
		GSList *non_chunks = NULL;
		struct bean_CONTENTS_HEADERS_s *header = NULL;
		for (GSList *l=beans; l ;l=l->next) {
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
		if (non_chunks) {
			forward (non_chunks);
			g_slist_free (non_chunks);
		}

		if (!header)
			GRID_WARN("No content header in event data! (type: %s)", name);

		/* then notify each chunks by batches of 16 items */
		GSList *batch = NULL;
		guint count = 0;
		for (GSList *l=beans; l ;l=l->next) {
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

static int
_put_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gint rc = FILTER_OK;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	// FIXME: this context is useless: we do not answer beans anymore
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	GSList *added = NULL, *deleted = NULL;

	GRID_DEBUG("Putting %d beans in [%s]%s%s", g_slist_length(beans),
			oio_url_get(url, OIOURL_WHOLE),
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)?
			" (overwrite)":"",
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE)?
			" (update)":"");

	if (NULL != meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)) {
		e = meta2_backend_force_alias(m2b, url, beans, &deleted, &added);
	} else if (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE)) {
		reply->subject("(update)");
		e = meta2_backend_update_content(m2b, url, beans, &deleted, &added);
	} else {
		e = meta2_backend_put_alias(m2b, url, beans, &deleted, &added);
	}

	if (NULL != e) {
		GRID_DEBUG("Fail to put alias (%s)", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		rc = FILTER_KO;
	} else {
		_m2b_notify_beans(m2b, url, added, "content.new");
		if (deleted)
			_m2b_notify_beans(m2b, url, deleted, "content.deleted");
		_on_bean_ctx_send_list(obc);
		rc = FILTER_OK;
	}

	_bean_cleanl2 (added);
	_bean_cleanl2 (deleted);
	_on_bean_ctx_clean(obc);
	return rc;
}

static int
_copy_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		const char *source)
{
	GError *e = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GRID_DEBUG("Copying %s from %s", oio_url_get(url, OIOURL_WHOLE), source);

	e = meta2_backend_copy_alias(m2b, url, source);
	if (NULL != e) {
		GRID_DEBUG("Fail to copy alias (%s) to (%s)", source, oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	} else {
		// For notification purposes, we need to load all the beans
		struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
		e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NOPROPS,
				_bean_list_cb, &obc->l);
		if (!e)
			_on_bean_ctx_send_list(obc);
		_on_bean_ctx_clean(obc);
	}

	return FILTER_OK;
}

int
meta2_filter_action_check_content(struct gridd_filter_ctx_s * ctx,
		struct gridd_reply_ctx_s *reply) {
	(void) reply;
	GError *e = NULL;
	int rc = FILTER_OK;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *copy_source = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_COPY);
	if (copy_source != NULL)
		return rc;

	gboolean is_update = false;
	const char *update = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE);
	if (update != NULL)
		is_update=true;

	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	GString *message= g_string_new("");
	e = meta2_backend_check_content(m2b, beans, message, is_update);
	if (e) {
		GString *gs = oio_event__create("storage.content.broken", url);
		g_string_append(gs, ",\"data\":{");
		g_string_append(gs, message->str);
		g_string_append(gs, "}}");
		oio_events_queue__send (m2b->notifier, g_string_free (gs, FALSE));
		g_string_free(message,TRUE);
		if (e->code == CODE_CONTENT_CORRUPTED)
			rc = FILTER_KO;
		g_clear_error(&e);
	}
	return rc;
}

int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	const char *copy_source = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_COPY);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (NULL != copy_source) {
		reply->subject("%s|%s|COPY(%s)", oio_url_get(url, OIOURL_WHOLE),
				oio_url_get(url, OIOURL_HEXID), copy_source);
		return _copy_alias(ctx, reply, copy_source);
	}

	return _put_alias(ctx, reply);
}

int
meta2_filter_action_append_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	(void) reply;
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	GRID_DEBUG("Appending %d beans", g_slist_length(beans));

	e = meta2_backend_append_to_alias(m2b, url, beans, _bean_list_cb, &obc->l);
	if(NULL != e) {
		GRID_DEBUG("Fail to append to alias (%s)", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_m2b_notify_beans(m2b, url, obc->l, "content.append");
	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_get_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	int rc = FILTER_KO;
	GError *e = NULL;
	guint32 flags = 0;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	TRACE_FILTER();

	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr)
		flags = atoi(fstr);

	e = meta2_backend_get_alias(m2b, url, flags, _bean_list_cb, &obc->l);
	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", oio_url_get(
					url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		goto cleanup;
	}

	_on_bean_ctx_send_list(obc);
	rc = FILTER_OK;

cleanup:
	_on_bean_ctx_clean(obc);
	return rc;
}

int
meta2_filter_action_delete_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	TRACE_FILTER();
	e = meta2_backend_delete_alias(m2b, url, _bean_list_cb, &obc->l);
	if (NULL != e) {
		GRID_DEBUG("Fail to delete alias for url: %s", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_m2b_notify_beans(m2b, url, obc->l, "content.deleted");
	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_truncate_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const char *trunc_size_str = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_CONTENTLENGTH);
	gint64 truncate_size = g_ascii_strtoll(trunc_size_str, NULL, 10);
	GSList *added = NULL, *deleted = NULL;

	TRACE_FILTER();
	err = meta2_backend_truncate_content(m2b, url, truncate_size,
			&deleted, &added);
	if (err != NULL) {
		GRID_DEBUG("Fail to truncate content %s", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (deleted)
		_m2b_notify_beans(m2b, url, deleted, "content.deleted");
	if (added)
		_m2b_notify_beans(m2b, url, added, "content.new");

	_bean_cleanl2(added);
	_bean_cleanl2(deleted);
	return FILTER_OK;
}

int
meta2_filter_action_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	guint32 flags = 0;
	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr)
		flags = atoi(fstr);

	if (!oio_url_has(url, OIOURL_PATH))
		e = BADREQ("Missing content path");
	else
		e = meta2_backend_set_properties(m2b, url, BOOL(flags&M2V2_FLAG_FLUSH),
				beans, _bean_list_cb, &obc->l);

	if (NULL != e) {
		GRID_DEBUG("Failed to set properties to [%s] : (%d) %s",
				oio_url_get(url, OIOURL_WHOLE), e->code, e->message);
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_get_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	guint32 flags = 0;

	TRACE_FILTER();

	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr)
		flags = atoi(fstr);

	e = meta2_backend_get_properties(m2b, url, flags, _bean_list_cb, &obc->l);
	if (NULL != e) {
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_del_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();

	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);

	gchar **namev = NULL;
	GError *e = STRV_decode_buffer(buf, len, &namev);
	if (!e) {
		e = meta2_backend_del_properties(m2b, url, namev);
		g_strfreev(namev);
	}

	if (e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}
	return FILTER_OK;
}

static GError*
_spare_with_blacklist(struct meta2_backend_s *m2b,
		struct gridd_filter_ctx_s *ctx, struct on_bean_ctx_s *obc,
		struct oio_url_s *url, const gchar *polname)
{
	GError *err = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	GSList *notin = NULL, *broken = NULL;

	for (; beans != NULL; beans = beans->next) {
		if (DESCR(beans->data) != &descr_struct_CHUNKS)
			continue;
		if (CHUNKS_get_size(beans->data) == -1)
			broken = g_slist_prepend(broken, beans->data);
		else
			notin = g_slist_prepend(notin, beans->data);
	}

	err = meta2_backend_get_conditionned_spare_chunks_v2(m2b, url, polname,
			notin, broken, &(obc->l));

	g_slist_free(notin);
	g_slist_free(broken);
	return err;
}

int
meta2_filter_action_generate_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	gint64 size = 0;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *size_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CONTENTLENGTH);
	const char *policy_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);
	const char *spare_type = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_SPARE);
	gboolean append = (NULL != meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_APPEND));

	TRACE_FILTER();
	if (NULL != size_str)
		size = g_ascii_strtoll(size_str, NULL, 10);

	// Spare beans request
	if (spare_type != NULL) {
		reply->subject("%s|%s|%s", oio_url_get(url, OIOURL_WHOLE),
				oio_url_get(url, OIOURL_HEXID), spare_type);
		if (strcmp(spare_type, M2V2_SPARE_BY_BLACKLIST) == 0) {
			e = _spare_with_blacklist(m2b, ctx, obc, url, policy_str);
		} else if (strcmp(spare_type, M2V2_SPARE_BY_STGPOL) == 0) {
			e = meta2_backend_get_spare_chunks(m2b, url, policy_str, &(obc->l));
		} else {
			e = BADREQ("Unknown type of spare request: %s", spare_type);
		}
		if (e != NULL) {
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}
	// Standard beans request
	else {
		e = meta2_backend_generate_beans(m2b, url, size, policy_str, append,
				_bean_list_cb, &obc->l);
		if (NULL != e) {
			GRID_DEBUG("Failed to return alias for url: %s",
					oio_url_get(url, OIOURL_WHOLE));
			_on_bean_ctx_clean(obc);
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_touch_content(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply UNUSED)
{
    struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
    struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GSList *beans = NULL;
	GError *err = meta2_backend_get_alias(
			m2b, url, M2V2_FLAG_ALLPROPS|M2V2_FLAG_HEADERS,
			_bean_list_cb, &beans);
    if (!err) {
		_m2b_notify_beans(m2b, url, beans, "content.new");
		_bean_cleanl2(beans);
		return FILTER_OK;
	}

	_bean_cleanl2(beans);
    meta2_filter_ctx_set_error(ctx, err);
    return FILTER_KO;
}
