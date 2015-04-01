/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqlite_utils.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>

#include <glib.h>

static void
_get_cb(gpointer udata, gpointer bean)
{
	struct on_bean_ctx_s *ctx = (struct on_bean_ctx_s*) udata;
	if(ctx && ctx->l && g_slist_length(ctx->l) >= 32) {
		_on_bean_ctx_send_list(ctx, FALSE);
	}
	ctx->l = g_slist_prepend(ctx->l, bean);
}

static int
_create_container(struct gridd_filter_ctx_s *ctx)
{
	struct m2v2_create_params_s params;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GError *err = NULL;
	int retry = 2;

	params.storage_policy = meta2_filter_ctx_get_param(ctx, M2_KEY_STORAGE_POLICY);
	params.version_policy = meta2_filter_ctx_get_param(ctx, M2_KEY_VERSION_POLICY);
	params.local = (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LOCAL) != NULL);

retry:
	err = meta2_backend_create_container(m2b, url, &params);
	if (err != NULL && err->code == CODE_REDIRECT && retry-- > 0 &&
			!g_strcmp0(err->message, meta2_backend_get_local_addr(m2b))) {
		GRID_WARN("Redirecting on myself!?! Retrying request immediately");
		g_clear_error(&err);
		hc_decache_reference_service(m2b->resolver, url, META2_TYPE_NAME);
		goto retry;
	}

	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_create_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	return _create_container(ctx);
}

int
meta2_filter_action_create_container_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	return _create_container(ctx);
}

int
meta2_filter_action_has_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (!url) {
		GRID_WARN("BUG : Checking container's presence : URL not set");
		return FILTER_OK;
	}

	GError *e = meta2_backend_has_container(m2b, url);
	if(NULL != e) {
		if (e->code == CODE_UNAVAILABLE)
			GRID_DEBUG("Container %s exists but could not open it: %s",
					hc_url_get(url, HCURL_WHOLE), e->message);
		else
			GRID_DEBUG("No such container (%s)", hc_url_get(url, HCURL_WHOLE));
		if (e->code == CODE_CONTAINER_NOTFOUND) {
			hc_decache_reference_service(m2b->resolver, url, META2_TYPE_NAME);
		}
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}
	return FILTER_OK;
}

int
meta2_filter_action_delete_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	guint32 flags = 0;

	flags |= meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FORCE) ? M2V2_DESTROY_FORCE : 0;
	flags |= meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLUSH) ? M2V2_DESTROY_FLUSH : 0;
	flags |= meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_PURGE) ? M2V2_DESTROY_PURGE : 0;
	flags |= meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LOCAL) ? M2V2_DESTROY_LOCAL : 0;

	GError *err = meta2_backend_destroy_container(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx),
			flags);

	(void) reply;

	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_purge_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	// M2V2_MODE_DRYRUN, ...
    guint32 flags = 0;
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
    const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
    if (NULL != fstr)
        flags = (guint32) g_ascii_strtoull(fstr, NULL, 10);

	GError *err = meta2_backend_purge_container(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx), flags, _get_cb, obc);

	if (NULL != err) {
		GRID_DEBUG("Container purge failed (%d): %s", err->code, err->message);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_deduplicate_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GString *status_message = NULL;

	// M2V2_MODE_DRYRUN, ...
	guint32 flags = 0;
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	if (NULL != fstr)
		flags = (guint32) g_ascii_strtoull(fstr, NULL, 10);
	
	GError *err = meta2_backend_deduplicate_contents(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx),
			flags,
			&status_message);
	(void) reply;

	if (!err) {
		if (status_message != NULL)
			reply->add_body(metautils_gba_from_string(status_message->str));
		return FILTER_OK;
	} else {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
}

#define S3_RESPONSE_HEADER(FieldName, Var) do { \
	if (NULL != (Var)) \
		reply->add_header((FieldName), metautils_gba_from_string(Var)); \
} while (0)

static int
_list_S3(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct list_params_s *lp)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	gboolean truncated = FALSE;
	char *next_marker = NULL;

	// XXX the underlying meta2_backend_list_aliases() function MUST
	// return headers before the associated alias.
	gint64 max = lp->maxkeys;
	void s3_list_cb(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (max > 0) {
			if (DESCR(bean) == &descr_struct_ALIASES) {
				_get_cb(obc, bean);
				if (0 == --max)
					next_marker = g_strdup(ALIASES_get_alias(bean)->str);
			} else {
				_get_cb(obc, bean);
			}
		} else {
			if (DESCR(bean) == &descr_struct_ALIASES)
				truncated = TRUE;
			_bean_clean(bean);
		}
	}

	GRID_DEBUG("LP H:%d A:%d D:%d prefix:%s marker:%s end:%s max:%"G_GINT64_FORMAT,
			lp->flag_headers, lp->flag_allversion, lp->flag_nodeleted,
			lp->prefix, lp->marker_start, lp->marker_end, lp->maxkeys);

	if (lp->maxkeys > 0) lp->maxkeys ++;
	e = meta2_backend_list_aliases(m2b, url, lp, lp->maxkeys>0 ? s3_list_cb : _get_cb, obc);

	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	S3_RESPONSE_HEADER(M2_KEY_PREFIX, lp->prefix);
	S3_RESPONSE_HEADER(M2_KEY_MARKER, lp->marker_start);
	S3_RESPONSE_HEADER(M2_KEY_MARKER_END, lp->marker_end);
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTMARKER, next_marker);
	if (lp->maxkeys > 0) {
		gchar tmp[64];	
		g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, lp->maxkeys - 1);
		reply->add_header(M2_KEY_MAX_KEYS, metautils_gba_from_string(tmp));
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	g_free0(next_marker);
	return FILTER_OK;
}

int
meta2_filter_action_list_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));

	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	if (NULL != fstr) {
		guint32 flags = atoi(fstr);
		lp.flag_headers = BOOL(flags & M2V2_FLAG_HEADERS);
		lp.flag_nodeleted = BOOL(flags & M2V2_FLAG_NODELETED);
		lp.flag_allversion = BOOL(flags & M2V2_FLAG_ALLVERSION);
	}

	lp.prefix = meta2_filter_ctx_get_param(ctx, M2_KEY_PREFIX);
	lp.marker_start = meta2_filter_ctx_get_param(ctx, M2_KEY_MARKER);
	lp.marker_end = meta2_filter_ctx_get_param(ctx, M2_KEY_MARKER_END);
	const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, M2_KEY_MAX_KEYS);
	if (NULL != maxkeys_str)
		lp.maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);

	return _list_S3(ctx, reply, &lp);
}

// TODO delete this ugly v1 feature
static int
_reply_path_info_list(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, GSList *pil)
{
	GError *e = NULL;
	guint nb = 32;
	GSList *cursor = NULL, *next = NULL;

	/*split the list into sublists of bounded size */
	for (cursor = pil; cursor; cursor = next) {

		// compute a sublist
		GSList *newList = NULL;
		next = g_slist_nth(cursor, nb + 1);
		for (; cursor && cursor != next; cursor = cursor->next)
			newList = g_slist_prepend(newList, cursor->data);

		// serialize
		GByteArray *gba = path_info_marshall_gba(newList, &e);
		if (newList)
			g_slist_free(newList);
		if (!gba) {
			GRID_DEBUG("Failed to encode path info sequence");
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
		reply->add_body(gba);
		reply->send_reply(CODE_PARTIAL_CONTENT, "Partial content");
	}

	reply->send_reply(CODE_FINAL_OK, "OK");
	return FILTER_OK;
}

static GSList*
_pack_path_info_list(GSList *aliases, GSList *headers)
{
	GSList *l = NULL;
	GSList *pil = NULL;

	for ( ; aliases; aliases = aliases->next) {
		if (!aliases->data)
			continue;

		for (l = headers; l; l = l->next) {
			if (!l->data)
				continue;

			GByteArray *ch_id = CONTENTS_HEADERS_get_id(l->data);
			GByteArray *al_id = ALIASES_get_content_id(aliases->data);

			// FVE: metautils_gba_cmp is safer but slower
			// TODO FIXME make the difference with metautils_gba_cmp close to 0
			if (!memcmp(ch_id->data, al_id->data, al_id->len)) {
				struct path_info_s *pi = g_malloc0(sizeof(path_info_t));
				g_strlcpy(pi->path, ALIASES_get_alias(aliases->data)->str, sizeof(pi->path));
				pi->user_metadata = g_byte_array_new();
				pi->hasSize = TRUE;
				pi->size = CONTENTS_HEADERS_get_size(l->data);
				pi->system_metadata = metautils_gba_from_string(ALIASES_get_mdsys(aliases->data)->str);
				pil = g_slist_prepend(pil, pi);
			}
		}
	}

	return pil;
}

int
meta2_filter_action_list_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *pil = NULL;
	GSList *aliases = NULL;
	GSList *headers = NULL;
	int status = FILTER_KO;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		if(DESCR(bean) == &descr_struct_ALIASES) {
			aliases = g_slist_prepend(aliases, bean);
		} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
			headers = g_slist_prepend(headers, bean);
		} else
			_bean_clean(bean);
	}

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flag_nodeleted = lp.flag_headers = ~0;
	lp.prefix = meta2_filter_ctx_get_param(ctx, M2_KEY_PREFIX);
	lp.marker_start = meta2_filter_ctx_get_param(ctx, M2_KEY_MARKER);
	lp.marker_end = meta2_filter_ctx_get_param(ctx, M2_KEY_MARKER_END);
	const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, M2_KEY_MAX_KEYS);
	if(NULL != maxkeys_str)
		lp.maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);

	e = meta2_backend_list_aliases(m2b, url, &lp, _cb, NULL);
	if (!e) {
		pil = _pack_path_info_list(aliases, headers);
		status = _reply_path_info_list(ctx, reply, pil);
	} else {
		meta2_filter_ctx_set_error(ctx, e);
		status = FILTER_KO;
	}

	_bean_cleanl2(aliases);
	_bean_cleanl2(headers);

	g_slist_free_full(pil, (GDestroyNotify)path_info_clean);

	return status;
}

int
meta2_filter_action_raw_list_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;

	void cb(gpointer u, gpointer bean) {
		GString *path = ALIASES_get_alias(bean);
		*((GSList**)u) = g_slist_prepend(*((GSList**)u), g_strdup(path->str));
	}

	(void) reply;
	TRACE_FILTER();
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	struct list_params_s lp;
	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.flag_nodeleted = ~0;

	GSList *result = NULL;
	err = meta2_backend_list_aliases(m2b, url, &lp, cb, &result);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	reply->add_body(strings_marshall_gba(result, NULL));
	g_slist_foreach(result, g_free1, NULL);
	g_slist_free(result);
	return FILTER_OK;
}

int
meta2_filter_action_getall_admin_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;
	GSList *result = NULL;

	(void) reply;
	TRACE_FILTER();
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean cb(gpointer u, const gchar *k, const guint8 *v, gsize vlen) {
		GSList **pl = u;
		gchar *s = g_strdup_printf("%s=%.*s", k, (int)vlen, (gchar*)v);
		*pl = g_slist_prepend(*pl, s);
		return TRUE;
	}

	int rc = FILTER_KO;
	GError *err = meta2_backend_get_container_properties(m2b, url,
			M2V2_FLAG_ALLPROPS, &result, cb);

	if (NULL != err)
		meta2_filter_ctx_set_error(ctx, err);
	else {
		reply->add_body(strings_marshall_gba(result, NULL));
		reply->send_reply(CODE_FINAL_OK, "OK");
		rc = FILTER_OK;
	}

	if (result) {
		g_slist_foreach(result, g_free1, NULL);
		g_slist_free(result);
	}
	return rc;
}

int
meta2_filter_action_setone_admin_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;

	(void) reply;
	TRACE_FILTER();
	err = NULL;
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	GByteArray *key = NULL, *value = NULL;

	err = message_extract_header_gba(reply->request, M2V1_KEY_ADMIN_KEY, TRUE, &key);
	if (!err)
		err = message_extract_header_gba(reply->request, M2V1_KEY_ADMIN_VALUE, TRUE, &value);
	if (!err) {
		GSList l = {.data=NULL, .next=NULL};
		struct meta2_property_s m2p;

		l.data = &m2p;
		m2p.name = g_strndup((gchar*)(key->data), key->len);
		m2p.version = 0;
		m2p.value = value;
		err = meta2_backend_set_container_properties(m2b, url,
				M2V2_FLAG_NOFORMATCHECK, &l);
	}

	if (key)
		g_byte_array_free(key, TRUE);
	if (value)
		g_byte_array_free(value, TRUE);

	if (NULL != err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	reply->send_reply(CODE_FINAL_OK, "OK");
	return FILTER_OK;
}

int
meta2_filter_action_insert_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);

	GError *err = meta2_backend_insert_beans(m2b, url, beans);
	if (!err)
		return FILTER_OK;

	GRID_DEBUG("Failed to insert beans : (%d) %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_delete_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);

	GError *err = meta2_backend_delete_beans(m2b, url, beans);
	if (!err)
		return FILTER_OK;

	GRID_DEBUG("Failed to delete beans : (%d) %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_update_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList **chunk_lists = meta2_filter_ctx_get_input_udata(ctx);

	GError *err = meta2_backend_update_beans(m2b, url,
			chunk_lists[0], chunk_lists[1]);
	if (!err)
		return FILTER_OK;

	GRID_DEBUG("Failed to update beans : (%d) %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

/* -------------- SNAPSHOT UTILITIES ----------------- */

int
meta2_filter_action_take_snapshot(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *err = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const gchar *snap_name = hc_url_get(url, HCURL_SNAPSHOT);

	err = meta2_backend_take_snapshot(m2b, url, snap_name);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_list_snapshots(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	err = meta2_backend_list_snapshots(m2b, url, _get_cb, obc);
	if (err != NULL) {
		GRID_DEBUG("Failed to list snapshots for %s",
			hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_delete_snapshot(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *err = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const gchar *snap_name = hc_url_get(url, HCURL_SNAPSHOT);

	err = meta2_backend_delete_snapshot(m2b, url, snap_name);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	return FILTER_OK;
}

int
meta2_filter_action_restore_snapshot(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *err = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const gchar *snap_name = hc_url_get(url, HCURL_SNAPSHOT);
	gboolean hard_restore = meta2_filter_ctx_get_param(ctx,
			M2_KEY_SNAPSHOT_HARDRESTORE) != NULL;

	err = meta2_backend_restore_snapshot(m2b, url, snap_name, hard_restore);
	if (err != NULL) {
		GRID_DEBUG("Failed to %srestore snapshot '%s' of %s",
			hard_restore? "(hard)" : "", snap_name,
			hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	return FILTER_OK;
}

