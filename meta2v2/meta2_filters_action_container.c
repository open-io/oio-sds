/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

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

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2_variables.h>

#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqlite_utils.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <resolver/hc_resolver.h>

int
meta2_filter_action_create_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct m2v2_create_params_s params = {NULL,NULL,NULL,NULL,0};
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GError *err = NULL;
	int retry = 2;

	params.storage_policy = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);
	params.version_policy = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_VERPOLICY);
	params.local = (meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LOCAL) != NULL);
	params.peers = meta2_filter_ctx_get_param(ctx, SQLX_ADMIN_PEERS);

	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);
	err = KV_decode_buffer(buf, len, &params.properties);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	while (!err) {
		if (!(err = meta2_backend_create_container(m2b, url, &params)))
			break;
		if (err != NULL && err->code == CODE_REDIRECT && retry-- > 0 &&
			!g_strcmp0(err->message, meta2_backend_get_local_addr(m2b))) {
			GRID_WARN(
					"Redirecting on myself!?! Retrying request immediately");
			g_clear_error(&err);
			hc_decache_reference_service(m2b->resolver, url,
										 NAME_SRVTYPE_META2);
		}
	}

	g_strfreev(params.properties);
	params.properties = NULL;
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_empty_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);

	GError *e = meta2_backend_container_isempty(m2b, url);
	if (NULL != e) {
		if (e->code == CODE_CONTAINER_NOTFOUND)
			hc_decache_reference_service(m2b->resolver, url, NAME_SRVTYPE_META2);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

#define getflag(F,R,N) do { \
	if (metautils_message_extract_flag (R, NAME_MSGKEY_##N, 0)) \
		F |= M2V2_DESTROY_##N; \
} while (0)

int
meta2_filter_action_delete_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	guint32 flags = 0;
	getflag (flags,reply->request, FORCE);
	getflag (flags,reply->request, EVENT);

	GError *err = meta2_backend_destroy_container(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx),
			flags);
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_purge_container(struct gridd_filter_ctx_s *ctx,
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

	GError *err = meta2_backend_purge_container(m2b, url, pmaxvers,
			_bean_list_cb, &beans_list_list);

	for (GSList *l = beans_list_list; l; l = l->next) {
		_m2b_notify_beans(m2b->notifier_content_deleted, url, l->data, "content.deleted", TRUE);
		_bean_cleanl2(l->data);
	}
	g_slist_free(beans_list_list);

	if (!err)
		return FILTER_OK;
	GRID_DEBUG("Container purge failed (%d): %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_flush_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *beans_list_list = NULL;
	gboolean truncated = FALSE;

	GError *err = meta2_backend_flush_container(meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx), _bean_list_cb, &beans_list_list,
			&truncated);

	for (GSList *l=beans_list_list; l; l=l->next) {
		_m2b_notify_beans(m2b->notifier_content_deleted, url, l->data, "content.deleted", TRUE);
		_bean_cleanl2(l->data);
	}
	g_slist_free(beans_list_list);

	if (!err) {
		reply->add_header(NAME_MSGKEY_TRUNCATED,
				metautils_gba_from_string(truncated ? "true" : "false"));
		return FILTER_OK;
	}
	GRID_DEBUG("Container flush failed (%d): %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

#define S3_RESPONSE_HEADER(FieldName, Var) do { \
	if (NULL != (Var)) \
		reply->add_header((FieldName), metautils_gba_from_string(Var)); \
} while (0)

int
meta2_filter_action_drain_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *limit_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LIMIT);
	gint64 limit;
	/* If no limit found in the context, take the default one in the conf.
	 * Otherwise, take the lowest one. */
	if (!oio_str_is_number(limit_str, &limit) || limit <= 0 ||
			limit > meta2_drain_limit) {
		limit = meta2_drain_limit;
	}

	GSList *beans_list_list = NULL;
	gboolean truncated = FALSE;

	GError *err = meta2_backend_drain_container(m2b, url, limit, _bean_list_cb,
			&beans_list_list, &truncated);

	if (err != NULL) {
		GRID_DEBUG("Container drain failed (%d): %s", err->code, err->message);
		meta2_filter_ctx_set_error(ctx, err);
		g_slist_free(beans_list_list);
		return FILTER_KO;
	}

	for (GSList *bean = beans_list_list; bean; bean = bean->next) {
		_m2b_notify_beans(m2b->notifier_content_deleted, url, bean->data,
				"content.drained", TRUE);
		_bean_cleanl2(bean->data);
	}
	g_slist_free(beans_list_list);

	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");

	return FILTER_OK;
}

static int
_list_S3(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct list_params_s *lp, GSList *headers)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	gboolean truncated = FALSE;
	char *next_marker = NULL;
	char *next_version_marker = NULL;
	gchar **properties = NULL;

	if (lp->maxkeys <= 0)
		lp->maxkeys = meta2_batch_maxlen;

	GRID_DEBUG("LP H:%d A:%d D:%d prefix:%s delimiter:%s marker:%s "
			"mpu_marker_only:%d version_marker:%s end:%s max:%"G_GINT64_FORMAT,
			lp->flag_headers, lp->flag_allversion, lp->flag_nodeleted,
			lp->prefix, lp->delimiter, lp->marker_start,
			lp->flag_mpu_marker_only,
			lp->version_marker, lp->marker_end, lp->maxkeys);

	// XXX the underlying meta2_backend_list_aliases() function MUST
	// return headers before the associated alias.
	gint64 max = lp->maxkeys;
	void s3_list_cb(gpointer ignored, gpointer bean) {
		(void) ignored;
		if (max > 0) {
			if (DESCR(bean) == &descr_struct_ALIASES) {
				_bean_list_cb(&obc->l, bean);
				if (--max == 0) {
					next_marker = g_strdup(ALIASES_get_alias(bean)->str);
					if (lp->flag_allversion) {
						next_version_marker = g_strdup_printf(
								"%"G_GINT64_FORMAT, ALIASES_get_version(bean));
					}
				}
			} else {
				_bean_list_cb(&obc->l, bean);
			}
		} else {
			if (DESCR(bean) == &descr_struct_ALIASES)
				truncated = TRUE;
			_bean_clean(bean);
		}
	}
	void s3_list_end_cb(struct sqlx_sqlite3_s *sq3) {
		if (!oio_ext_is_shard_redirection()) {
			// Not a request for a shard
			return;
		} else if (!sqlx_admin_has(sq3, M2V2_ADMIN_SHARDING_ROOT)) {
			// Should never happen
			GRID_WARN("Failed to find root information");
			return;
		}

		if (truncated) {
			// Already truncated
			return;
		}

		gchar *shard_upper = NULL;
		GError *err = m2db_get_sharding_upper(sq3, &shard_upper);
		if (err) {
			GRID_WARN("Failed to get shard upper: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			goto end;
		}
		if (!*shard_upper) {
			// Last shard
			goto end;
		}

		if (lp->prefix
				// The prefix is before the last object of this shard
				&& g_strcmp0(lp->prefix, shard_upper) <= 0
				// The last object of this shard desn't start with the prefix
				&& !g_str_has_prefix(shard_upper, lp->prefix)) {
			goto end;
		}
		if (lp->marker_end
				// The marker end is before the last object of this shard
				&& g_strcmp0(lp->marker_end, shard_upper) <= 0) {
			goto end;
		}

		// In all other cases, the list is truncated
		truncated = TRUE;
		g_free(next_marker);
		next_marker = shard_upper;
		shard_upper = NULL;
		g_free(next_version_marker);
		next_version_marker = NULL;

end:
		g_free(shard_upper);
	}

	lp->maxkeys ++;
	e = meta2_backend_list_aliases(m2b, url, lp, headers, s3_list_cb, NULL,
			s3_list_end_cb, &properties);
	obc->l = g_slist_reverse(obc->l);

	if (!e || e->code == CODE_REDIRECT_SHARD) {
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
	}

	if (e) {
		GRID_DEBUG("Fail to return alias for url: %s", oio_url_get(url, OIOURL_WHOLE));
		_on_bean_ctx_clean(obc);
		g_free(next_marker);
		g_free(next_version_marker);
		if (properties)
			g_strfreev(properties);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	S3_RESPONSE_HEADER(NAME_MSGKEY_PREFIX, lp->prefix);
	if (lp->delimiter) {
		S3_RESPONSE_HEADER(NAME_MSGKEY_DELIMITER, lp->delimiter);
	}
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER, lp->marker_start);
	S3_RESPONSE_HEADER(NAME_MSGKEY_VERSIONMARKER, lp->version_marker);
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER_END, lp->marker_end);
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTMARKER, next_marker);
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTVERSIONMARKER, next_version_marker);

	gchar tmp[64];
	g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, lp->maxkeys - 1);
	reply->add_header(NAME_MSGKEY_MAX_KEYS, metautils_gba_from_string(tmp));

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	g_free(next_marker);
	g_free(next_version_marker);
	if (properties)
		g_strfreev (properties);
	return FILTER_OK;
}

static void
_load_list_params(struct list_params_s *lp, struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	memset(lp, '\0', sizeof(struct list_params_s));

	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr) {
		guint32 flags = atoi(fstr);
		lp->flag_headers = BOOL(flags & M2V2_FLAG_HEADERS);
		lp->flag_nodeleted = BOOL(flags & M2V2_FLAG_NODELETED);
		lp->flag_allversion = BOOL(flags & M2V2_FLAG_ALLVERSION);
		lp->flag_properties = BOOL(flags & M2V2_FLAG_ALLPROPS);
		lp->flag_local = BOOL(flags & M2V2_FLAG_LOCAL);
		lp->flag_mpu_marker_only = BOOL(flags & M2V2_FLAG_MPUMARKER_ONLY);
		// Beware of the negation of the flag
		lp->flag_recursion = ! BOOL(flags & M2V2_FLAG_NORECURSION);
	}

	lp->prefix = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_PREFIX);
	const gchar *delimiter_str = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_DELIMITER);
	lp->delimiter = delimiter_str;
	lp->marker_start = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MARKER);
	if (lp->flag_allversion && lp->marker_start) {
		lp->version_marker = meta2_filter_ctx_get_param(ctx,
				NAME_MSGKEY_VERSIONMARKER);
	} else {
		lp->version_marker = NULL;
	}
	lp->marker_end = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MARKER_END);
	const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MAX_KEYS);
	if (NULL != maxkeys_str)
		lp->maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);
	gchar *marker_start = string_to_ltsv_value(lp->marker_start);
	gchar *marker_end = string_to_ltsv_value(lp->marker_end);
	gchar *prefix = string_to_ltsv_value(lp->prefix);
	gchar *delimiter = string_to_ltsv_value(lp->delimiter);
	reply->subject("max:%"G_GINT64_FORMAT"\tmarker:%s\tversion_marker:%s\t"
			"end:%s\tprefix:%s\tdelimiter:%s", lp->maxkeys, marker_start,
			lp->version_marker, marker_end, prefix, delimiter);
	g_free(marker_start);
	g_free(marker_end);
	g_free(prefix);
	g_free(delimiter);
}

int
meta2_filter_action_list_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct list_params_s lp;
	_load_list_params(&lp, ctx, reply);
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
	_load_list_params(&lp, ctx, reply);

	// Get the chunk id
	c = metautils_message_extract_string_copy (reply->request, NAME_MSGKEY_KEY);
	if (!c)
		err = NEWERROR(CODE_BAD_REQUEST, "Missing content id at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err) {
		struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
		struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
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
	_load_list_params(&lp, ctx, reply);

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
		struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
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
meta2_filter_action_list_by_header_id(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *headers = NULL;
	GError *err = NULL;
	GBytes *h = NULL;
	int rc = FILTER_KO;

	struct list_params_s lp;
	_load_list_params(&lp, ctx, reply);

	// Get the header ID (binary form)
	gsize hlen = 0;
	void *hbuf = metautils_message_get_field (reply->request, NAME_MSGKEY_KEY, &hlen);
	if (hbuf && hlen)
		h = g_bytes_new_static (hbuf, hlen);
	if (!h)
		err = NEWERROR(CODE_BAD_REQUEST, "Missing content hash at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err) {
		struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
		struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
		err = meta2_backend_content_from_contentid (m2b, url, h, _bean_list_cb, &headers);
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
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	const gboolean frozen = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FROZEN, FALSE);
	const gboolean force = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FORCE, FALSE);

	GError *err = meta2_backend_insert_beans(m2b, url, beans, frozen, force);
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
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
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
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList **chunk_lists = meta2_filter_ctx_get_input_udata(ctx);
	const gboolean frozen = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FROZEN, FALSE);

	GError *err = meta2_backend_update_beans(m2b, url,
			chunk_lists[0], chunk_lists[1], frozen);
	if (!err)
		return FILTER_OK;

	GRID_DEBUG("Failed to update beans : (%d) %s", err->code, err->message);
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_touch_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean recompute = FALSE;
	metautils_message_extract_boolean(reply->request,
			NAME_MSGKEY_RECOMPUTE, FALSE, &recompute);

	GError *err = meta2_backend_notify_container_state(m2b, url, recompute);
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

/* Sharding ----------------------------------------------------------------- */

int
meta2_filter_action_find_shards(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	gchar **properties = NULL;

	const char *strategy = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_SHARDING_STRATEGY);
	if (!strategy) {
		err = BADREQ("Missing strategy");
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	gsize length = 0;
	void *strategy_params = metautils_message_get_BODY(reply->request, &length);
	json_object *jstrategy_params = NULL;
	if (strategy_params) {
		err = JSON_parse_buffer(strategy_params, length, &jstrategy_params);
		if (!err && !json_object_is_type(jstrategy_params, json_type_object)) {
			err = BADREQ("Expected JSON object for strategy parameters");
		}

		if (err) {
			_on_bean_ctx_clean(obc);
			if (jstrategy_params) {
				json_object_put(jstrategy_params);
			}
			meta2_filter_ctx_set_error(ctx, err);
			return FILTER_KO;
		}
	}

	GRID_DEBUG("FSP strategy:%s", strategy);

	if (g_strcmp0(strategy, "shard-with-partition") == 0) {
		err = meta2_backend_find_shards_with_partition(m2b, url,
				jstrategy_params, _bean_list_cb, &(obc->l), &properties);
	} else if (g_strcmp0(strategy, "shard-with-size") == 0) {
		err = meta2_backend_find_shards_with_size(m2b, url,
				jstrategy_params, _bean_list_cb, &(obc->l), &properties);
	} else {
		err = BADREQ("Unknown strategy");
	}
	obc->l = g_slist_reverse(obc->l);

	if (err) {
		GRID_DEBUG("Fail to find shards for url: %s",
				oio_url_get(url, OIOURL_WHOLE));
		_on_bean_ctx_clean(obc);
		if (properties)
			g_strfreev(properties);
		if (jstrategy_params)
			json_object_put(jstrategy_params);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (properties) {
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			if (!g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_USER)
					&& !g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_SYS))
				continue;
			gchar *k = g_strconcat(NAME_MSGKEY_PREFIX_PROPERTY, *p, NULL);
			reply->add_header(k, metautils_gba_from_string(*(p+1)));
			g_free(k);
		}
	}

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	if (properties)
		g_strfreev(properties);
	if (jstrategy_params)
		json_object_put(jstrategy_params);
	return FILTER_OK;
}

int
meta2_filter_action_prepare_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const char *action = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_SHARDING_ACTION);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	gchar **properties = NULL;

	if (g_strcmp0(action, "merge") == 0) {
		err = meta2_backend_prepare_shrinking(m2b, url, &properties);
	} else {
		err = meta2_backend_prepare_sharding(m2b, url, beans, &properties);
	}
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (properties) {
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			if (!g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_USER)
					&& !g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_SYS))
				continue;
			gchar *k = g_strconcat(NAME_MSGKEY_PREFIX_PROPERTY, *p, NULL);
			reply->add_header(k, metautils_gba_from_string(*(p+1)));
			g_free(k);
		}
		g_strfreev(properties);
	}
	return FILTER_OK;
}

int
meta2_filter_action_merge_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	gboolean truncated = FALSE;

	err = meta2_backend_merge_sharding(m2b, url, beans, &truncated);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	return FILTER_OK;
}

int
meta2_filter_action_update_shard(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);
	gchar **queries = NULL;
	err = STRV_decode_buffer(buf, len, &queries);
	if (!err) {
		err = meta2_backend_update_shard(m2b, url, queries);
	}

	g_strfreev(queries);
	if (!err) {
		return FILTER_OK;
	}
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_lock_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GError *err = meta2_backend_lock_sharding(m2b, url);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	return FILTER_OK;
}

int
meta2_filter_action_replace_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);

	err = meta2_backend_replace_sharding(m2b, url, beans);
	if (!err) {
		return FILTER_OK;
	}
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_clean_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gboolean truncated = FALSE;
	GError *err = NULL;
	GSList *beans = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean local = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_LOCAL) != NULL;
	reply->subject("op_type:%s", local? "local" : "replicated");
	if (local) {
		// Manipulate the database locally (without replication)
		// to clean it up once
		beans = meta2_filter_ctx_get_input_udata(ctx);
		err = meta2_backend_clean_locally_sharding(m2b, url, beans, &truncated);
	} else {
		gboolean urgent = meta2_filter_ctx_get_param(
				ctx, NAME_MSGKEY_URGENT) != NULL;
		err = meta2_backend_clean_sharding(m2b, url, urgent, &truncated);
	}
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	reply->subject("truncated:%s", truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	return FILTER_OK;
}

int
meta2_filter_action_show_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	struct list_params_s lp = {0};
	gboolean truncated = FALSE;
	gchar *next_marker = NULL;
	gchar **properties = NULL;

	_load_list_params(&lp, ctx, reply);
	if (lp.maxkeys <= 0)
		lp.maxkeys = meta2_batch_maxlen;

	GRID_DEBUG("LP H:%d A:%d D:%d prefix:%s marker:%s end:%s max:%"G_GINT64_FORMAT,
			lp.flag_headers, lp.flag_allversion, lp.flag_nodeleted,
			lp.prefix, lp.marker_start, lp.marker_end, lp.maxkeys);

	gint64 max = lp.maxkeys;
	void s3_list_cb(gpointer u UNUSED, gpointer bean) {
		if (max > 0) {
			if (DESCR(bean) == &descr_struct_SHARD_RANGE) {
				_bean_list_cb(&obc->l, bean);
				if (0 == --max)
					next_marker = g_strdup(SHARD_RANGE_get_upper(bean)->str);
			} else {
				_bean_clean(bean);
			}
		} else {
			if (DESCR(bean) == &descr_struct_SHARD_RANGE)
				truncated = TRUE;
			_bean_clean(bean);
		}
	}

	lp.maxkeys++;
	err = meta2_backend_show_sharding(m2b, url, &lp, s3_list_cb, NULL,
			&properties);
	obc->l = g_slist_reverse(obc->l);

	if (err) {
		GRID_DEBUG("Fail to return shard ranges for url: %s",
				oio_url_get(url, OIOURL_WHOLE));
		_on_bean_ctx_clean(obc);
		g_free(next_marker);
		if (properties)
			g_strfreev(properties);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTMARKER, next_marker);

	if (properties) {
		for (gchar **p=properties; *p && *(p+1) ;p+=2) {
			if (!g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_USER)
					&& !g_str_has_prefix(*p, SQLX_ADMIN_PREFIX_SYS))
				continue;
			gchar *k = g_strconcat(NAME_MSGKEY_PREFIX_PROPERTY, *p, NULL);
			reply->add_header(k, metautils_gba_from_string(*(p+1)));
			g_free(k);
		}
	}

	_on_bean_ctx_send_list(obc);
	_on_bean_ctx_clean(obc);
	g_free(next_marker);
	if (properties)
		g_strfreev(properties);
	return FILTER_OK;
}

int
meta2_filter_action_abort_sharding(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply UNUSED)
{
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GError *err = meta2_backend_abort_sharding(m2b, url);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	return FILTER_OK;
}
