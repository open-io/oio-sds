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

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2_variables.h>

#include <cluster/lib/gridcluster.h>
#include <sqliterepo/sqlite_utils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/election.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <meta2v2/meta2_macros.h>
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
	if (!oio_url_has_fq_container(ctx->base.url)) {
		_reply_no_body(ctx, reply, BADREQ("Need a fully qualified container name"));
		return FILTER_KO;
	}

	int retry = 2;
	GError *err = NULL;
	gchar stgpol[LIMIT_LENGTH_STGPOLICY] = "", verpol[32] = "";

	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_STGPOLICY, stgpol, sizeof(stgpol));

	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_VERPOLICY, verpol, sizeof(verpol));

	if (err)
		return _reply_no_body(ctx, reply, err);

	struct m2v2_create_params_s params = {0};
	params.storage_policy = oio_str_is_set(stgpol) ? stgpol : NULL;
	params.version_policy = oio_str_is_set(verpol) ? verpol : NULL;

	gsize len = 0;
	void *buf = metautils_message_get_BODY(reply->request, &len);
	err = KV_decode_buffer(buf, len, &params.properties);

	if (!err) {
		while (!err) {
			err = meta2_backend_create_container(ctx->backend, &ctx->base, &params);
			if (!err)
				break;
			if (err->code == CODE_REDIRECT && retry-- > 0 &&
					!g_strcmp0(err->message, meta2_backend_get_local_addr(ctx->backend))) {
				GRID_WARN(
						"Redirecting on myself!?! Retrying request immediately");
				g_clear_error(&err);
				hc_decache_reference_service(ctx->backend->resolver, ctx->base.url,
						NAME_SRVTYPE_META2);
			}
		}

		g_strfreev(params.properties);
		params.properties = NULL;
	}

	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_empty_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_container_isempty(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_has_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_has_container(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_delete_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct m2v2_destroy_params_s params = {0};
	params.flag_force = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FORCE, FALSE);
	params.flag_flush = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FLUSH, FALSE);
	params.flag_event = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_EVENT, FALSE);

	GError *err = meta2_backend_destroy_container(ctx->backend, &ctx->base, &params);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_purge_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_purge_container(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_flush_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_flush_container(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_dedup_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_dedup_contents(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
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
	gboolean truncated = FALSE;
	char *next_marker = NULL;
	gchar **properties = NULL;
	GSList *beans = NULL;

	if (lp->maxkeys <= 0)
		lp->maxkeys = meta2_batch_maxlen;

	GRID_DEBUG("LP H:%d A:%d D:%d prefix:%s marker:%s end:%s max:%"G_GINT64_FORMAT,
			lp->flags.headers, lp->flags.allversion, lp->flags.nodeleted,
			lp->prefix, lp->marker_start, lp->marker_end, lp->maxkeys);

	// The underlying meta2_backend_list_aliases() function MUST return
	// headers before the associated alias.
	gint64 max = lp->maxkeys;
	void s3_list_cb(gpointer ignored UNUSED, gpointer bean) {
		if (max > 0) {
			beans = g_slist_prepend(beans, bean);
			if (DESCR(bean) == &descr_struct_ALIASES && 0 == --max)
				next_marker = g_strdup(ALIASES_get_alias(bean)->str);
		} else {
			if (DESCR(bean) == &descr_struct_ALIASES)
				truncated = TRUE;
			_bean_clean(bean);
		}
	}

	lp->maxkeys ++;
	e = meta2_backend_list_aliases(ctx->backend, &ctx->base,
			lp, headers, s3_list_cb, NULL, &properties);

	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", oio_url_get(ctx->base.url, OIOURL_WHOLE));
		if (properties) g_strfreev (properties);
		return FILTER_KO;
	}

	S3_RESPONSE_HEADER(NAME_MSGKEY_PREFIX, lp->prefix);
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER, lp->marker_start);
	S3_RESPONSE_HEADER(NAME_MSGKEY_MARKER_END, lp->marker_end);
	S3_RESPONSE_HEADER(NAME_MSGKEY_TRUNCATED, truncated ? "true" : "false");
	S3_RESPONSE_HEADER(NAME_MSGKEY_NEXTMARKER, next_marker);

	gchar tmp[64];
	g_snprintf(tmp, sizeof(tmp), "%"G_GINT64_FORMAT, lp->maxkeys - 1);
	reply->add_header(NAME_MSGKEY_MAX_KEYS, metautils_gba_from_string(tmp));

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

	g_free0(next_marker);
	if (properties) g_strfreev (properties);
	return _reply_beans_and_clean(reply, beans);
}

struct list_params_inline_s
{
	gint64 maxkeys;
	struct list_flags_s flags;
	gchar prefix[LIMIT_LENGTH_CONTENTPATH];
	gchar marker_start[LIMIT_LENGTH_CONTENTPATH];
	gchar marker_end[LIMIT_LENGTH_CONTENTPATH];
};


static GError *
_load_list_params (struct gridd_reply_ctx_s *reply,
		struct list_params_inline_s *lp)
{
	guint32 flags = 0;
	metautils_message_extract_flags32(reply->request, NAME_MSGKEY_FLAGS, &flags);

	lp->flags.headers = BOOL(flags & M2V2_FLAG_HEADERS);
	lp->flags.nodeleted = BOOL(flags & M2V2_FLAG_NODELETED);
	lp->flags.allversion = BOOL(flags & M2V2_FLAG_ALLVERSION);
	lp->flags.properties = BOOL(flags & M2V2_FLAG_ALLPROPS);

	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_PREFIX, lp->prefix, sizeof(lp->prefix));
	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_MARKER, lp->marker_start, sizeof(lp->marker_start));
	metautils_message_extract_string_noerror(reply->request,
			NAME_MSGKEY_MARKER_END, lp->marker_end, sizeof(lp->marker_end));

	lp->maxkeys = meta2_batch_maxlen;

	gchar strmax[32];
	const gboolean rc = metautils_message_extract_string_noerror(
			reply->request, NAME_MSGKEY_MAX_KEYS, strmax, sizeof(strmax));
	if (rc && (!oio_str_is_number(strmax, &lp->maxkeys) || lp->maxkeys < 1))
		return BADREQ("Invalid max number of items");
	return NULL;
}

static void
list_param_map(struct list_params_s *lp,
		const struct list_params_inline_s *lpi)
{
	lp->maxkeys = lpi->maxkeys;
	lp->flags = lpi->flags;
	lp->prefix = oio_str_is_set(lpi->prefix) ? lpi->prefix : NULL;
	lp->marker_start = oio_str_is_set(lpi->marker_start) ? lpi->marker_start : NULL;
	lp->marker_end = oio_str_is_set(lpi->marker_end) ? lpi->marker_end : NULL;
}

int
meta2_filter_action_list_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct list_params_inline_s lpi = {0};
	struct list_params_s lp = {0};
	GError *err = _load_list_params (reply, &lpi);
	if (err)
		return _reply_no_body(ctx, reply, err);
	list_param_map(&lp, &lpi);

	return _list_S3(ctx, reply, &lp, NULL);
}

int
meta2_filter_action_list_by_chunk_id(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gchar c[LIMIT_LENGTH_CONTENTPATH];
	struct list_params_inline_s lpi = {0};
	struct list_params_s lp = {0};
	GError *err = _load_list_params (reply, &lpi);
	if (err)
		return _reply_no_body(ctx, reply, err);
	list_param_map(&lp, &lpi);

	GSList *headers = NULL;

	// Get the chunk id
	if (!metautils_message_extract_string_noerror (reply->request,
				NAME_MSGKEY_KEY, c, sizeof(c)))
		err = BADREQ("Missing content id at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err)
		err = meta2_backend_content_from_chunkid (ctx->backend, &ctx->base,
				c, _bean_list_cb, &headers);
	if (!err && !headers)
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No header linked");

	// Perform the list on it
	int rc = FILTER_KO;
	if (err)
		rc = _reply_no_body(ctx, reply, err);
	else
		rc = _list_S3(ctx, reply, &lp, headers);

	_bean_cleanl2 (headers);
	return rc;
}

int
meta2_filter_action_list_by_header_hash(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct list_params_inline_s lpi = {0};
	struct list_params_s lp = {0};
	GError *err = _load_list_params (reply, &lpi);
	if (err)
		return _reply_no_body(ctx, reply, err);
	list_param_map(&lp, &lpi);

	GSList *headers = NULL;
	GBytes *h = NULL;

	// Get the header hash (binary form)
	gsize hlen = 0;
	void *hbuf = metautils_message_get_field (reply->request, NAME_MSGKEY_KEY, &hlen);
	if (hbuf && hlen)
		h = g_bytes_new_static (hbuf, hlen);
	if (!h)
		err = BADREQ("Missing content hash at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err)
		err = meta2_backend_content_from_contenthash (ctx->backend, &ctx->base,
				h, _bean_list_cb, &headers);

	if (!err && !headers)
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No header linked");

	// Perform the list on it
	int rc = FILTER_KO;
	if (err)
		rc = _reply_no_body(ctx, reply, err);
	else
		rc = _list_S3(ctx, reply, &lp, headers);

	_bean_cleanl2 (headers);
	if (h) g_bytes_unref (h);
	return rc;
}

int
meta2_filter_action_list_by_header_id(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct list_params_inline_s lpi = {0};
	struct list_params_s lp = {0};
	GError *err = _load_list_params (reply, &lpi);
	if (err)
		return _reply_no_body(ctx, reply, err);
	list_param_map(&lp, &lpi);

	GSList *headers = NULL;
	GBytes *h = NULL;

	// Get the header ID (binary form)
	gsize hlen = 0;
	void *hbuf = metautils_message_get_field (reply->request, NAME_MSGKEY_KEY, &hlen);
	if (hbuf && hlen)
		h = g_bytes_new_static (hbuf, hlen);
	if (!h)
		err = BADREQ("Missing content hash at [%s]", NAME_MSGKEY_KEY);

	// Use it to locate the headers
	if (!err)
		err = meta2_backend_content_from_contentid (ctx->backend, &ctx->base,
				h, _bean_list_cb, &headers);

	if (!err && !headers)
		err = NEWERROR(CODE_CONTENT_NOTFOUND, "No header linked");

	int rc = FILTER_KO;
	if (err)
		rc = _reply_no_body(ctx, reply, err);
	else
		rc = _list_S3(ctx, reply, &lp, headers);

	_bean_cleanl2 (headers);
	if (h) g_bytes_unref (h);

	return rc;
}

int
meta2_filter_action_insert_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans = NULL;
	GError *err = metautils_message_extract_body_encoded (reply->request,
			FALSE, &beans, bean_sequence_decoder);
	if (!err) {
		const gboolean force = metautils_message_extract_flag(
				reply->request, NAME_MSGKEY_FORCE, FALSE);
		err = meta2_backend_insert_beans(ctx->backend, &ctx->base, beans, force);
	}

	_bean_cleanl2(beans);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_delete_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *beans = NULL;
	GError *err = metautils_message_extract_body_encoded (reply->request,
			FALSE, &beans, bean_sequence_decoder);
	if (!err)
		err = meta2_backend_delete_beans(ctx->backend, &ctx->base, beans);
	_bean_cleanl2(beans);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_update_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	GSList *old_chunks = NULL, *new_chunks = NULL;

	gboolean frozen;
	metautils_message_extract_boolean(reply->request, NAME_MSGKEY_FROZEN,
			FALSE, &frozen);

	if (!err)
		err = metautils_message_extract_header_encoded(reply->request,
				NAME_MSGKEY_NEW, TRUE, &new_chunks, bean_sequence_decoder);
	if (!err)
		err = metautils_message_extract_header_encoded(reply->request,
				NAME_MSGKEY_OLD, TRUE, &old_chunks, bean_sequence_decoder);
	if (!err)
		err = meta2_backend_update_beans(ctx->backend, &ctx->base,
				new_chunks, old_chunks, frozen);

	_bean_cleanl2(old_chunks);
	_bean_cleanl2(new_chunks);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_link(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	GBytes *id = NULL;

	const char *hexid = oio_url_get(ctx->base.url, OIOURL_CONTENTID);
	if (!hexid)
		err = BADREQ("Missing content ID");
	else if (!oio_str_ishexa1(hexid))
		err = BADREQ("Invalid content ID");
	else {
		id = g_byte_array_free_to_bytes (metautils_gba_from_hexstring(hexid));
		err = meta2_backend_link_content (ctx->backend, &ctx->base, id);
		g_bytes_unref (id);
	}

	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_touch_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = meta2_backend_notify_container_state(ctx->backend, &ctx->base);
	return _reply_no_body(ctx, reply, err);
}

int
meta2_filter_action_exit_election(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	if (oio_url_has(ctx->base.url, OIOURL_HEXID)) {
		struct sqlx_name_s n = {
			.base = oio_url_get(ctx->base.url,OIOURL_HEXID),
			.type = NAME_SRVTYPE_META2,
			.ns = ctx->backend->ns_name
		};
		err = sqlx_repository_exit_election(ctx->backend->repo, &n);
		hc_decache_reference_service(
				ctx->backend->resolver, ctx->base.url, NAME_SRVTYPE_META2);
	} else {
		election_manager_exit_all(
				sqlx_repository_get_elections_manager(ctx->backend->repo),
				5 * G_TIME_SPAN_MINUTE, FALSE);
	}

	return _reply_no_body(ctx, reply, err);
}

