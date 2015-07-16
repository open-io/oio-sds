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

int
meta2_filter_action_create_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct m2v2_create_params_s params = {NULL,NULL,NULL,0};
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GError *err = NULL;
	int retry = 2;

	params.storage_policy = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);
	params.version_policy = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_VERPOLICY);
	params.local = (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LOCAL) != NULL);

	gchar **headers = metautils_message_get_field_names (reply->request);
	GPtrArray *tmp = g_ptr_array_new ();
	for (gchar **p=headers; *p ;++p) {
		if (!g_str_has_prefix(*p, NAME_MSGKEY_PREFIX_PROPERTY))
			continue;
		g_ptr_array_add (tmp, g_strdup((*p) + sizeof(NAME_MSGKEY_PREFIX_PROPERTY) - 1));
		g_ptr_array_add (tmp, metautils_message_extract_string_copy (reply->request, *p));
	}
	params.properties = (gchar**) metautils_gpa_to_array (tmp, TRUE);

retry:
	err = meta2_backend_create_container(m2b, url, &params);
	if (err != NULL && err->code == CODE_REDIRECT && retry-- > 0 &&
			!g_strcmp0(err->message, meta2_backend_get_local_addr(m2b))) {
		GRID_WARN("Redirecting on myself!?! Retrying request immediately");
		g_clear_error(&err);
		hc_decache_reference_service(m2b->resolver, url, NAME_SRVTYPE_META2);
		goto retry;
	}

	g_strfreev (params.properties);
	params.properties = NULL;

	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
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
		meta2_filter_ctx_set_error (ctx, NEWERROR(CODE_BAD_REQUEST, "No URL"));
		return FILTER_KO;
	}

	GError *e = meta2_backend_has_container(m2b, url);
	if (NULL != e) {
		GRID_DEBUG("Container test error for [%s] : (%d) %s",
					hc_url_get(url, HCURL_WHOLE), e->code, e->message);
		if (e->code == CODE_CONTAINER_NOTFOUND)
			hc_decache_reference_service(m2b->resolver, url, NAME_SRVTYPE_META2);
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
    const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
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
	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
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
		struct list_params_s *lp, GSList *headers)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	gboolean truncated = FALSE;
	char *next_marker = NULL;
	gchar **properties = NULL;

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

	if (lp->maxkeys > 0)
		lp->maxkeys ++;
	e = meta2_backend_list_aliases(m2b, url, lp, headers,
			(lp->maxkeys>0 ? s3_list_cb : _get_cb), obc, &properties);

	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		if (properties) g_strfreev (properties);
		return FILTER_KO;
	}

	S3_RESPONSE_HEADER(NAME_MSGKEY_PREFIX, lp->prefix);
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER, lp->marker_start);
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER_END, lp->marker_end);
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTMARKER, next_marker);
	if (lp->maxkeys > 0) {
		gchar tmp[64];	
		g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, lp->maxkeys - 1);
		reply->add_header(NAME_MSGKEY_MAX_KEYS, metautils_gba_from_string(tmp));
	}
	if (properties) {
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			if (!g_str_has_prefix (*p, SQLX_ADMIN_PREFIX_USER)
					&& !g_str_has_prefix (*p, SQLX_ADMIN_PREFIX_SYS))
				continue;
			gchar *k = g_strconcat (NAME_MSGKEY_PREFIX_PROPERTY, *p, NULL);
			reply->add_header(k, metautils_gba_from_string(*(p+1)));
			g_free (k);
		}
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	g_free0(next_marker);
	if (properties) g_strfreev (properties);
	return FILTER_OK;
}

static void
_load_list_params (struct list_params_s *lp, struct gridd_filter_ctx_s *ctx)
{
	memset(lp, '\0', sizeof(struct list_params_s));

	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr) {
		guint32 flags = atoi(fstr);
		lp->flag_headers = BOOL(flags & M2V2_FLAG_HEADERS);
		lp->flag_nodeleted = BOOL(flags & M2V2_FLAG_NODELETED);
		lp->flag_allversion = BOOL(flags & M2V2_FLAG_ALLVERSION);
	}

	lp->prefix = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_PREFIX);
	lp->marker_start = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MARKER);
	lp->marker_end = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MARKER_END);
	const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MAX_KEYS);
	if (NULL != maxkeys_str)
		lp->maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);
}

int
meta2_filter_action_list_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct list_params_s lp;
	_load_list_params (&lp, ctx);
	return _list_S3(ctx, reply, &lp, NULL);
}

int
meta2_filter_action_list_by_chunk_id(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *headers = NULL;
	GError *err = NULL;
	gchar *c = NULL;
	int rc = FILTER_KO;

	struct list_params_s lp;
	_load_list_params (&lp, ctx);

	// Get the chunk id
	c = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_KEY);
	if (!c)
		err = NEWERROR(CODE_BAD_REQUEST, "Missing content id at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err) {
		struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
		struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
		err = meta2_backend_content_from_chunkid (m2b, url, c, _bean_list_cb, &headers);
	}
	if (!err && !headers)
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No header linked");

	// Perform the list on it
	if (!err)
		rc = _list_S3(ctx, reply, &lp, headers);
	else
		meta2_filter_ctx_set_error(ctx, err);

	_bean_cleanl2 (headers);
	g_free0 (c);
	return rc;
}

int
meta2_filter_action_list_by_header_hash(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *headers = NULL;
	GError *err = NULL;
	GBytes *h = NULL;
	int rc = FILTER_KO;

	struct list_params_s lp;
	_load_list_params (&lp, ctx);

	// Get the header hash (binary form)
	gsize hlen = 0;
	void *hbuf = metautils_message_get_field (reply->request, NAME_MSGKEY_KEY, &hlen);
	if (hbuf && hlen)
		h = g_bytes_new_static (hbuf, hlen);
	if (!h)
		err = NEWERROR(CODE_BAD_REQUEST, "Missing content hash at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err) {
		struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
		struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
		err = meta2_backend_content_from_contenthash (m2b, url, h, _bean_list_cb, &headers);
	}
	if (!err && !headers)
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No header linked");

	// Perform the list on it
	if (!err)
		rc = _list_S3(ctx, reply, &lp, headers);
	else
		meta2_filter_ctx_set_error(ctx, err);

	_bean_cleanl2 (headers);
	if (h) g_bytes_unref (h);
	return rc;
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

