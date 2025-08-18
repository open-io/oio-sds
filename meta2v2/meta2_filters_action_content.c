/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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
#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#define _MAX_BEANS_BY_EVENT 16

static void
_load_url_from_alias(struct oio_url_s *url, struct bean_ALIASES_s *alias)
{
	if (alias == NULL)
		return;

	GString *path = ALIASES_get_alias(alias);
	oio_url_set(url, OIOURL_PATH, path->str);
	gint64 version = ALIASES_get_version(alias);
	gchar *str_version = g_strdup_printf("%"G_GINT64_FORMAT, version);
	oio_url_set(url, OIOURL_VERSION, str_version);
	g_free(str_version);
	GByteArray *content_id = ALIASES_get_content(alias);
	GString *hex_content_id = metautils_gba_to_hexgstr(NULL, content_id);
	oio_url_set(url, OIOURL_CONTENTID, hex_content_id->str);
	g_string_free(hex_content_id, TRUE);
}


void
_m2b_notify_beans(struct oio_events_queue_s *notifier, struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks)
{
	_m2b_notify_beans2(notifier, url, beans, name, send_chunks, NULL);
}

void
meta2_json_encode_async_repli(GString *gstr, struct async_repli_s *repli)
{
	if (!repli->dests) {
		GRID_DEBUG("no async repli in event (dests are missing)");
		return;
	}
	g_string_append_static(gstr, ",\"repli\":{\"destinations\":");
	oio_str_gstring_append_json_quote(gstr, repli->dests);

	if (repli->replicator_id) {
		g_string_append_static(gstr, ",\"replicator_id\":");
		oio_str_gstring_append_json_quote(gstr, repli->replicator_id);
	}
	if (repli->role_project_id) {
		// Here, the project_id coming from the role is converted
		// to the project_id of the source (it makes more sense for the
		// event reader).
		g_string_append_static(gstr, ",\"src_project_id\":");
		oio_str_gstring_append_json_quote(gstr, repli->role_project_id);
	}
	for (GSList *l0=repli->props; l0; l0=l0->next) {
		if (!l0->data) {
			continue;
		}
		if (&descr_struct_PROPERTIES == DESCR(l0->data)) {
			struct bean_PROPERTIES_s *prop = l0->data;
			GByteArray *val = PROPERTIES_get_value(prop);
			// Need both key and value to exist
			if (!PROPERTIES_get_key(prop)->str || !(gchar*)val->data) {
				continue;
			}
			g_string_append_static(gstr, ",");
			oio_str_gstring_append_json_quote(gstr, PROPERTIES_get_key(prop)->str);
			g_string_append_static(gstr, ":\"");
			oio_str_gstring_append_json_blob(gstr, (gchar*)val->data, val->len);
			g_string_append_static(gstr, "\"");
		}
	}
	g_string_append_static(gstr, "}");
}

void
_m2b_notify_beans2(struct oio_events_queue_s *notifier, struct oio_url_s *url,
		GSList *beans, const char *name, gboolean send_chunks,
		struct async_repli_s *repli)
{
	if (!notifier)
		return;

	guint n_events = 1;
	guint cur_event = 0;
	struct oio_url_s *url2 = NULL;
	struct m2v2_sorted_content_s *sorted = NULL;
	// Need the alias to build a complete object URL
	struct bean_ALIASES_s *alias = NULL;

	void forward(GSList *list_of_beans, gboolean send_repli) {
		gchar tmp[256];
		g_snprintf (tmp, sizeof(tmp), "%s.%s", META2_EVENTS_PREFIX, name);

		GString *gs = oio_event__create_with_id(tmp,
				url2, oio_ext_get_reqid());
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair_int(gs, "part", cur_event++);
		g_string_append_c(gs, ',');
		oio_str_gstring_append_json_pair_int(gs, "parts", n_events);
		g_string_append_static (gs, ",\"data\":[");
		meta2_json_dump_all_xbeans (gs, list_of_beans);
		g_string_append_static (gs, "]");

		if (repli && send_repli) {
			meta2_json_encode_async_repli(gs, repli);
		}
		g_string_append_static (gs, "}");
		oio_events_queue__send (notifier, NULL, g_string_free (gs, FALSE));
	}

	if (url == NULL) {
		url2 = oio_url_empty();
	} else {
		url2 = oio_url_dup(url);
	}

	m2v2_sort_content(beans, &sorted);

	alias = g_slist_nth_data(sorted->aliases, 0);

	if (g_slist_length(sorted->aliases) > 1) {
		struct bean_ALIASES_s *alias2 = g_slist_nth_data(sorted->aliases, 1);
		GRID_WARN(
			"Several aliases in the same event:"
			" selected=%s:%" G_GUINT64_FORMAT
			" other=%s:%" G_GUINT64_FORMAT,
			ALIASES_get_alias(alias)->str, ALIASES_get_version(alias),
			ALIASES_get_alias(alias2)->str, ALIASES_get_version(alias2));
	}
	_load_url_from_alias(url2, alias);
	GError *err = m2v2_sorted_content_extend_chunk_urls(sorted, url2);
	if (err != NULL) {
		GRID_WARN(
				"Next event may contain incomplete chunk URLs: %s (reqid=%s)",
				err->message, oio_ext_get_reqid());
		g_clear_error(&err);
	}

	GSList *non_chunks = NULL;
	if (sorted->header)
		non_chunks = g_slist_prepend(non_chunks, sorted->header);
	if (alias)
		non_chunks = g_slist_prepend(non_chunks, alias);
	if (sorted->properties)
		non_chunks = g_slist_concat(non_chunks, g_slist_copy(sorted->properties));

	gboolean send_repli = TRUE;
	if (!send_chunks) {
		forward(non_chunks, send_repli);
		send_repli = FALSE;
	} else {
		forward(beans, send_repli);
		send_repli = FALSE;
	}

	m2v2_sorted_content_free(sorted);
	g_slist_free(non_chunks);
	oio_url_clean(url2);
}

struct async_repli_s *
_async_repli_init(struct gridd_filter_ctx_s *ctx)
{
	struct async_repli_s *repli = g_slice_new0(struct async_repli_s);

	repli->dests = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_REPLI_DESTS);
	repli->replicator_id = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_REPLI_ID);
	repli->role_project_id = meta2_filter_ctx_get_param(
			ctx, NAME_MSGKEY_REPLI_PROJECT_ID);
	repli->props = NULL;

	return repli;
}

void
_async_repli_clean(struct async_repli_s *repli)
{
	if (!repli)
		return;

	if (repli->props) {
		_bean_cleanl2(repli->props);
		repli->props = NULL;
	}
	g_slice_free(struct async_repli_s, repli);
}

GError*
_m2b_extract_repli_properties(struct gridd_filter_ctx_s *ctx, GSList **out)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	guint32 flags = 0;
	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (fstr) {
		flags = atoi(fstr);
	}

	void
	_bean_repli_cb(gpointer plist, gpointer bean)
	{
		EXTRA_ASSERT(plist != NULL);
		EXTRA_ASSERT(bean != NULL);

		if (&descr_struct_PROPERTIES == DESCR(bean)) {
			struct bean_PROPERTIES_s *prop = bean;
			gchar *expected_prop = "x-object-sysmeta-s3api-acl";
			if (strcmp(expected_prop, PROPERTIES_get_key(prop)->str) != 0) {
				_bean_clean(bean);
				return;
			}
			*((GSList**)plist) = g_slist_prepend (*((GSList**)plist), bean);
		} else {
			_bean_clean(bean);
		}
	}

	return meta2_backend_get_properties(m2b, url, flags, _bean_repli_cb, out);
}

int
meta2_filter_action_check_content(struct gridd_filter_ctx_s * ctx,
		struct gridd_reply_ctx_s *reply) {
	(void) reply;
	GError *err = NULL;
	int rc = FILTER_OK;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	gboolean is_update = FALSE;
	const char *update = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE);
	if (update != NULL)
		is_update=TRUE;

	void _send_event(gchar *event, gpointer udata UNUSED) {
		meta2_filter_ctx_defer_event(ctx, event);
	}
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	err = meta2_backend_check_content(m2b, url, &beans, _send_event, is_update);
	meta2_filter_ctx_set_input_udata2(ctx, beans,
			(GDestroyNotify)_bean_cleanl2, FALSE);
	if (err) {
		if (err->code != CODE_CONTENT_UNCOMPLETE) {
			meta2_filter_ctx_set_error(ctx, err);
			rc = FILTER_KO;
		} else {
			g_error_free(err);
		}
	}
	return rc;
}

static int
meta2_filter_send_deferred_events(struct gridd_filter_ctx_s *ctx,
		struct oio_events_queue_s *notifier)
{
	TRACE_FILTER();

	GSList *events = meta2_filter_ctx_get_deferred_events(ctx);
	if (events) {
		for (GSList *l = events; l != NULL; l = l->next) {
			EXTRA_ASSERT(l->data != NULL);
			oio_events_queue__send(notifier, NULL, l->data);
			l->data = NULL;  // will be freed by the event queue
		}
	}

	return FILTER_OK;
}
int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	GError *e = NULL;
	gint rc = FILTER_OK;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	// FIXME: this context is useless: we do not answer beans anymore
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	GSList *added = NULL, *deleted = NULL;

	GRID_DEBUG("Putting %d beans in [%s]%s%s%s%s", g_slist_length(beans),
			oio_url_get(url, OIOURL_WHOLE),
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)?
			" (overwrite)":"",
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE)?
			" (update)":"",
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CHANGE_POLICY)?
			" (policy change)":"",
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_RESTORE_DRAINED)?
			" (restore drained)":"");

	if (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)) {
		e = meta2_backend_force_alias(m2b, url, beans,
				_bean_list_cb, &deleted, _bean_list_cb, &added);
	} else if (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_UPDATE)) {
		reply->subject("action:update");
		e = meta2_backend_update_content(m2b, url, beans,
				_bean_list_cb, &deleted, _bean_list_cb, &added);
	} else if (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CHANGE_POLICY)) {
		reply->subject("action:policy change");
		e = meta2_backend_change_alias_policy(m2b, url, beans,
				_bean_list_cb, &deleted, _bean_list_cb, &added);
	} else if (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_RESTORE_DRAINED)) {
		reply->subject("action:restore drained");
		e = meta2_backend_restore_drained(m2b, url, beans,
				_bean_list_cb, &deleted, _bean_list_cb, &added);
	} else {
		e = meta2_backend_put_alias(m2b, url, beans, _bean_list_cb, &deleted,
				_bean_list_cb, &added);
	}

	if (NULL != e) {
		GRID_DEBUG("Fail to put alias (%s)", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		rc = FILTER_KO;
	} else {
		for (GSList *l=deleted; l; l=l->next) {
			_m2b_notify_beans(m2b->notifier_content_deleted, url, l->data,
					"content.deleted", TRUE);
		}
		struct async_repli_s *repli = _async_repli_init(ctx);
		_m2b_notify_beans2(m2b->notifier_content_created, url, added, "content.new",
				FALSE, repli);
		_async_repli_clean(repli);
		meta2_filter_send_deferred_events(ctx, m2b->notifier_content_created);
		_on_bean_ctx_send_list(obc);
		rc = FILTER_OK;
	}

	_bean_cleanl2(added);
	g_slist_free_full(deleted, (GDestroyNotify)_bean_cleanl2);
	_on_bean_ctx_clean(obc);

	return rc;
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

	_m2b_notify_beans(m2b->notifier_content_appended, url, obc->l, "content.append", FALSE);
	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);

	meta2_filter_send_deferred_events(ctx, m2b->notifier_content_appended);
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

	gboolean content_found = FALSE;
	gboolean chunks_found = FALSE;
	gboolean is_deleted = FALSE;
	for (GSList *l = obc->l; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			GString *method = CONTENTS_HEADERS_get_chunk_method(l->data);
			content_found = TRUE;
			if (!strcmp(method->str, CHUNK_METHOD_DRAINED)) {
				meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_CONTENT_DRAINED,
						"The content is drained"));
				goto cleanup;
			}
		} else if (DESCR(l->data) == &descr_struct_ALIASES && ALIASES_get_deleted(l->data)) {
			is_deleted = TRUE;
		} else if (DESCR(l->data) == &descr_struct_CHUNKS) {
			chunks_found = TRUE;
		}
	}

	if (!is_deleted && (!content_found || !chunks_found)) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_CORRUPT_DATABASE,
				"content or chunks are missing"));
		goto cleanup;
	}

	const gchar *root_hexid = oio_url_get(url, OIOURL_ROOT_HEXID);
	if (root_hexid != NULL) {
		reply->add_header(NAME_MSGKEY_ROOT_HEXID,
				metautils_gba_from_string(root_hexid));
	}
	_on_bean_ctx_send_list(obc);
	rc = FILTER_OK;

cleanup:
	_on_bean_ctx_clean(obc);
	return rc;
}

int
meta2_filter_action_drain_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	e = meta2_backend_drain_content(m2b, url, _bean_list_cb, &obc->l);
	if (e != NULL) {
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_m2b_notify_beans(m2b->notifier_content_drained, url, obc->l, "content.drained", TRUE);
	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
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
	gboolean dryrun = BOOL(meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_DRYRUN));
	gboolean slo_manifest = BOOL(meta2_filter_ctx_get_param(
			ctx, NAME_MSGKEY_SLO_MANIFEST));
	gboolean delete_marker_created = FALSE;

	const gchar *user_agent = oio_ext_get_user_agent();
	gboolean from_lifecycle = g_strcmp0(user_agent, LIFECYCLE_USER_AGENT) == 0;
	gboolean create_delete_marker = BOOL(meta2_filter_ctx_get_param(
		ctx, NAME_MSGKEY_DELETE_MARKER));

	void
	_property_cb(gpointer plist UNUSED, gpointer bean)
	{
		EXTRA_ASSERT(plist != NULL);
		EXTRA_ASSERT(bean != NULL);
		if (DESCR(bean) == &descr_struct_PROPERTIES) {
			if (from_lifecycle || g_strcmp0(PROPERTIES_get_key(bean)->str, "ttime") == 0) {
				_bean_list_cb(&obc->l, bean);
				return;
			}
		}
		_bean_clean(bean);
	}

	m2_onbean_cb props_cb = NULL;
	if (!create_delete_marker) {
		props_cb = _property_cb;
	}

	TRACE_FILTER();
	e = meta2_backend_delete_alias(m2b, url,
		BOOL(meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_BYPASS_GOVERNANCE)),
		create_delete_marker,
		dryrun, slo_manifest, _bean_list_cb, &obc->l, props_cb, &obc->l,
		&delete_marker_created);
	if (NULL != e) {
		GRID_DEBUG("Fail to delete alias for url: %s", oio_url_get(url, OIOURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	// do not notify if dryrun is activated
	if (!dryrun) {
		if (delete_marker_created) {
			struct async_repli_s *repli = _async_repli_init(ctx);
			_m2b_notify_beans2(m2b->notifier_content_created, url, obc->l,
					"content.new", FALSE, repli);
			_async_repli_clean(repli);
		} else {
			_m2b_notify_beans(m2b->notifier_content_deleted, url, obc->l,
					"content.deleted", TRUE);
		}
	}
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
		_m2b_notify_beans(m2b->notifier_content_deleted, url, deleted, "content.deleted", TRUE);
	if (added)
		_m2b_notify_beans(m2b->notifier_content_created, url, added, "content.new", FALSE);

	_bean_cleanl2(added);
	_bean_cleanl2(deleted);
	return FILTER_OK;
}

int
meta2_filter_action_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	GError *e = NULL;
	GSList *modified = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	guint32 flags = 0;
	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (fstr != NULL)
		flags = atoi(fstr);

	if (!oio_url_has(url, OIOURL_PATH)) {
		e = BADREQ("Missing content path");
	} else {
		e = meta2_backend_set_properties(m2b, url, BOOL(flags&M2V2_FLAG_FLUSH),
				beans, &modified);
	}

	if (e) {
		GRID_DEBUG("Failed to set properties on [%s]: (%d) %s",
				oio_url_get(url, OIOURL_WHOLE), e->code, e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	struct async_repli_s *repli = _async_repli_init(ctx);
	// Only extract properties if dests are found
	if (repli->dests) {
		e = _m2b_extract_repli_properties(ctx, &repli->props);
		if (e) {
			_bean_cleanl2(modified);
			_async_repli_clean(repli);
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}

	_m2b_notify_beans2(m2b->notifier_content_updated, url, modified,
			"content.update", FALSE, repli);
	_bean_cleanl2(modified);
	_async_repli_clean(repli);
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
		struct gridd_reply_ctx_s *reply UNUSED)
{
	GError *e = NULL;
	GSList *deleted = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();

	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);

	gchar **namev = NULL;
	e = STRV_decode_buffer(buf, len, &namev);
	if (!e) {
		e = meta2_backend_del_properties(m2b, url, namev, &deleted);
	}
	g_strfreev(namev);

	if (e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	struct async_repli_s *repli = _async_repli_init(ctx);

	/* Notify only if we changed something. */
	gint prop_count = g_slist_length(deleted) - 1;  // Do not count alias
	if (prop_count > 0) {
		// Only extract properties if dests are found
		if (repli->dests) {
			e = _m2b_extract_repli_properties(ctx, &repli->props);
			if (e) {
				_async_repli_clean(repli);
				meta2_filter_ctx_set_error(ctx, e);
				g_slist_free_full(deleted, _bean_clean);
				return FILTER_KO;
			}
		}

		_m2b_notify_beans2(m2b->notifier_content_updated, url, deleted,
				"content.update", FALSE, repli);
	}
	g_slist_free_full(deleted, _bean_clean);
	_async_repli_clean(repli);

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
		_m2b_notify_beans(m2b->notifier_content_created, url, beans, "content.new", FALSE);
		_bean_cleanl2(beans);
		return FILTER_OK;
	}

	_bean_cleanl2(beans);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_purge_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	gint64 *pmaxvers = NULL;
	GSList *beans_list_list = NULL;

	const char *maxvers_str = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_MAXVERS);
	gint64 maxvers;
	if (oio_str_is_number(maxvers_str, &maxvers)) {
		pmaxvers = &maxvers;
	}

	// Here we are abusing _bean_list_cb with a list of lists of beans
	GError *err = meta2_backend_purge_alias(m2b, url, pmaxvers,
			_bean_list_cb, &beans_list_list);

	for (GSList *l = beans_list_list; l; l = l->next) {
		_m2b_notify_beans(m2b->notifier_content_deleted, url, l->data, "content.deleted", TRUE);
		_bean_cleanl2(l->data);
	}
	g_slist_free(beans_list_list);

	if (!err)
		return FILTER_OK;
	GRID_DEBUG("Object purge failed (%d): %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_request_policy_transition(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	TRACE_FILTER();
	GError *err = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *transitioned = NULL;
	gboolean skip_data_move = FALSE;
	gboolean force_event_emit = FALSE;

	const gchar* policy = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CHANGE_POLICY);
	const gchar* skip_data_move_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_SKIP_DATA_MOVE);
	const gchar* force_event_emit_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FORCE_EVENT_EMIT);
	if (skip_data_move_str != NULL) {
		skip_data_move = TRUE;
	}
	if (force_event_emit_str != NULL) {
		force_event_emit = TRUE;
	}
	err = meta2_backend_request_policy_transition(m2b, url, policy, skip_data_move, force_event_emit);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	_bean_cleanl2(transitioned);

	return FILTER_OK;
}
