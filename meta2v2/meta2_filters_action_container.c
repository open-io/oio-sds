#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
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
	params.local = (meta2_filter_ctx_get_param(ctx, "LOCAL") != NULL);

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

	flags |= meta2_filter_ctx_get_param(ctx, "FORCE") ? M2V2_DESTROY_FORCE : 0;
	flags |= meta2_filter_ctx_get_param(ctx, "FLUSH") ? M2V2_DESTROY_FLUSH : 0;
	flags |= meta2_filter_ctx_get_param(ctx, "PURGE") ? M2V2_DESTROY_PURGE : 0;
	flags |= meta2_filter_ctx_get_param(ctx, "LOCAL") ? M2V2_DESTROY_LOCAL : 0;

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

static int
_list_NORMAL(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct list_params_s *lp)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	if (hc_url_has(url, HCURL_SNAPSHOT)) {
		lp->snapshot_name = hc_url_get(url, HCURL_SNAPSHOT);
	} else if (hc_url_has(url, HCURL_VERSION)) {
		lp->snapshot_name = hc_url_get(url, HCURL_VERSION);
	}

	e = meta2_backend_list_aliases(m2b, url, lp, _get_cb, obc);
	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s",
				hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

#define S3_RESPONSE_HEADER(FieldName, Var) do { \
	if (NULL != (Var)) { \
		reply->add_header((FieldName), \
				g_byte_array_append(g_byte_array_new(), \
					(guint8*)(Var), \
					strlen((char*)(Var)))); \
	} \
} while (0)


static int
_list_S3(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct list_params_s *lp)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	GSList *common_prefixes = NULL;
	gint64 max = 0;
	gboolean truncated = FALSE;
	char *next_marker = NULL;

	GRID_DEBUG("S3 LISTING");
	lp->type = S3;
	lp->flags = lp->flags | M2V2_FLAG_HEADERS;
	lp->params.s3.prefix = meta2_filter_ctx_get_param(ctx,
			M2_KEY_PREFIX);
	lp->params.s3.marker = meta2_filter_ctx_get_param(ctx,
			M2_KEY_MARKER);
	lp->params.s3.delimiter = meta2_filter_ctx_get_param(ctx,
			M2_KEY_DELIMITER);
	const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, M2_KEY_MAX_KEYS);
	if(NULL != maxkeys_str)
		lp->params.s3.maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);
	lp->params.s3.maxkeys = (lp->params.s3.maxkeys > 0) ?
		lp->params.s3.maxkeys + 1 : 1001;

	max = lp->params.s3.maxkeys - 1;

	gboolean _is_directory(gpointer alias)
	{
		char *mtype = strstr(ALIASES_get_mdsys(alias)->str, "mime-type=");
		if (!mtype)
			return FALSE;
		return !g_ascii_strncasecmp("application/x-directory", mtype + 10, 23);
	}

	char * _get_real_name(gpointer alias)
	{
		return _is_directory(alias) ?
			g_strconcat(ALIASES_get_alias(alias)->str, "/", NULL)
			: g_strdup(ALIASES_get_alias(alias)->str);
	}

	void add_prefix(char *prefix)
	{
		/* check presence */
		for (GSList *l = common_prefixes; l && l->data; l = l->next) {
			if (0 == g_ascii_strcasecmp((char *)l->data, prefix)) {
				g_free(prefix);
				return;
			}
		}
		common_prefixes = g_slist_prepend(common_prefixes, prefix);
	}

	void check_alias(gpointer alias)
	{
		char *alias_name = _get_real_name(alias);
		/* add to beans list or common prefix */
		char * r = NULL;
		if (lp->params.s3.delimiter)
			r = g_strstr_len((!lp->params.s3.prefix) ?
					alias_name : alias_name + strlen(lp->params.s3.prefix),
					-1, lp->params.s3.delimiter);
		if (r) {
			GRID_DEBUG("Found common prefix : %.*s",
					((int)( r - alias_name)) + 1,
					alias_name);
			add_prefix(g_strndup(alias_name,
						r + 1 - alias_name));
		} else  {
			_get_cb(obc, alias);
		}

		g_free(alias_name);
	}

	void s3_list_cb(gpointer ignored, gpointer bean)
	{
		(void) ignored;
		if(max > 0) {
			if(DESCR(bean) == &descr_struct_ALIASES) {
				check_alias(bean);
				max--;
				if(0 == max)
					next_marker = g_strdup(ALIASES_get_alias(bean)->str);
			} else {
				_get_cb(obc, bean);
			}
			return;
		}
		if(DESCR(bean) == &descr_struct_ALIASES) {
			truncated = TRUE;
		}
		_bean_clean(bean);
	}

	void send_result()
	{
		if (NULL != common_prefixes) {
			char **array = (char **)metautils_list_to_array(common_prefixes);
			reply->add_header("COMMON_PREFIXES", metautils_encode_lines(array));
			g_strfreev(array);
		}

		S3_RESPONSE_HEADER(M2_KEY_PREFIX, lp->params.s3.prefix);
		S3_RESPONSE_HEADER(M2_KEY_MARKER, lp->params.s3.marker);
		S3_RESPONSE_HEADER(M2_KEY_DELIMITER, lp->params.s3.delimiter);
		S3_RESPONSE_HEADER(M2_KEY_MAX_KEYS, (maxkeys_str) ? maxkeys_str : "1000");
		S3_RESPONSE_HEADER("TRUNCATED", truncated ? "true" : "false");
		S3_RESPONSE_HEADER("NEXT_MARKER", next_marker);

		_on_bean_ctx_send_list(obc, TRUE);
	}

	GRID_DEBUG("prefix = %s | marker = %s | delimiter = %s | max-keys = %"G_GINT64_FORMAT,
			lp->params.s3.prefix, lp->params.s3.marker, lp->params.s3.delimiter,
			lp->params.s3.maxkeys);

	e = meta2_backend_list_aliases(m2b, url, lp, s3_list_cb, NULL);
	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s",
				hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	send_result();

	g_free(next_marker);

	g_slist_free(common_prefixes);

	return FILTER_OK;
}

int
meta2_filter_action_list_contents(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();

	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	const char *type = meta2_filter_ctx_get_param(ctx, M2_KEY_LISTING_TYPE);
	struct list_params_s lp;

	memset(&lp, '\0', sizeof(struct list_params_s));
	lp.type = DEFAULT;

	if (NULL != fstr) {
		//lp.flags = (guint32) g_ascii_strtoull(fstr, NULL, 10);
        lp.flags = atoi(fstr);
        lp.flags = g_ntohl(lp.flags);
	}
	if(type && !g_ascii_strcasecmp(type, S3_LISTING_TYPE)) {
		return _list_S3(ctx, reply, &lp);
	} else if (type && !g_ascii_strcasecmp(type, REDC_LISTING_TYPE)) {
			lp.type = REDC;
			lp.params.redc.metadata_pattern = meta2_filter_ctx_get_param(ctx,
					M2_KEY_METADATA_PATTERN);
			lp.params.redc.name_pattern = meta2_filter_ctx_get_param(ctx,
					M2_KEY_NAME_PATTERN);
	}
	return _list_NORMAL(ctx, reply, &lp);
}

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
		reply->send_reply(206, "Partial content");
	}

	reply->send_reply(200, "OK");
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
	lp.flags = M2V2_FLAG_NODELETED | M2V2_FLAG_HEADERS;
	const char * ltype = meta2_filter_ctx_get_param(ctx, M2_KEY_LISTING_TYPE);
	if (GRID_TRACE_ENABLED()) {
		GRID_TRACE("Listing type: %s", ltype);
		GRID_TRACE("Prefix: %s", meta2_filter_ctx_get_param(ctx, M2_KEY_PREFIX));
	}
	if (NULL != ltype && !g_ascii_strcasecmp(ltype, S3_LISTING_TYPE)) {
		lp.type = S3;
		lp.params.s3.prefix = meta2_filter_ctx_get_param(ctx,
				M2_KEY_PREFIX);
		lp.params.s3.marker = meta2_filter_ctx_get_param(ctx,
				M2_KEY_MARKER);
		lp.params.s3.delimiter = meta2_filter_ctx_get_param(ctx,
				M2_KEY_DELIMITER);
		const char *maxkeys_str = meta2_filter_ctx_get_param(ctx, M2_KEY_MAX_KEYS);
		if(NULL != maxkeys_str)
			lp.params.s3.maxkeys = g_ascii_strtoll(maxkeys_str, NULL, 10);
	} else {
		lp.type = DEFAULT;
		lp.params.redc.metadata_pattern =
			meta2_filter_ctx_get_param(ctx, M2_KEY_METADATA_PATTERN);
		lp.params.redc.name_pattern =
			meta2_filter_ctx_get_param(ctx, M2_KEY_NAME_PATTERN);
	}

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
meta2_filter_action_open_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;

	(void) reply;
	TRACE_FILTER();
	err = meta2_backend_open_container(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx));
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_close_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;

	(void) reply;
	TRACE_FILTER();
	err = meta2_backend_close_container(
			meta2_filter_ctx_get_backend(ctx),
			meta2_filter_ctx_get_url(ctx));
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, err);
	return FILTER_KO;
}

int
meta2_filter_action_get_flags(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 status = 0;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();

	e = meta2_backend_get_container_status(m2b, url, &status);
	if (NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	gchar msg[64];
	g_snprintf(msg, sizeof(msg), "FLAG [%08X]", status);
	reply->add_body(g_byte_array_append(g_byte_array_new(), (guint8*)&status, 4));
	reply->send_reply(200, msg);
	return FILTER_OK;
}

int
meta2_filter_action_set_flags(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	static guint32 model_enabled = 0;
	static guint32 model_frozen = -1;
	static guint32 model_disbaled = -2;

	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	guint32 flags = 0, status = CONTAINER_STATUS_ENABLED;

	TRACE_FILTER();
	(void) reply;

	do {
		GByteArray *body = meta2_filter_ctx_get_input_udata(ctx);
		flags = *((guint32*) body->data);
		if (!memcmp(body->data, &model_enabled, 4))
			status = CONTAINER_STATUS_ENABLED;
		else if (!memcmp(body->data, &model_frozen, 4))
			status = CONTAINER_STATUS_FROZEN;
		else if (!memcmp(body->data, &model_disbaled, 4))
			status = CONTAINER_STATUS_DISABLED;
		else {
			e = g_error_new(GQ(), 400, "Bad flags [%08X]", status);
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	} while (0);

	e = meta2_backend_set_container_status(m2b, url, NULL, status);
	if (NULL != e) {
		GRID_DEBUG("Status change failure %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	gchar msg[64];
	g_snprintf(msg, sizeof(msg), "FLAG set to [%08X/%08X]", flags, status);
	reply->send_reply(200, msg);
	return FILTER_OK;
}

int
meta2_filter_action_enable(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();
	(void) reply;

	e = meta2_backend_set_container_status(m2b, url, NULL, CONTAINER_STATUS_ENABLED);
	if (NULL != e) {
		GRID_DEBUG("Status change failure %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_disable(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 flags = CONTAINER_STATUS_ENABLED;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();
	(void) reply;

	e = meta2_backend_set_container_status(m2b, url, &flags, CONTAINER_STATUS_DISABLED);
	if (NULL != e) {
		GRID_DEBUG("Status change failure %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_freeze(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 flags = CONTAINER_STATUS_ENABLED;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();
	(void) reply;

	e = meta2_backend_set_container_status(m2b, url, &flags, CONTAINER_STATUS_FROZEN);
	if (NULL != e) {
		GRID_DEBUG("Status change failure %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_disable_frozen(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 flags = CONTAINER_STATUS_FROZEN;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	TRACE_FILTER();
	(void) reply;

	e = meta2_backend_set_container_status(m2b, url, &flags, CONTAINER_STATUS_DISABLED);
	if (NULL != e) {
		GRID_DEBUG("Status change failure %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

/* ----------- CONTAINER PROPERTIES ------------------ */
int
meta2_filter_action_set_container_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const gchar *k, *v;
	struct meta2_property_s m2p;

	(void) reply;
	TRACE_FILTER();
	GSList l = {.data=&m2p, .next=NULL};
	k = meta2_filter_ctx_get_param(ctx, "K");
	v = meta2_filter_ctx_get_param(ctx, "V");
	m2p.name = g_strdup(k);
	m2p.version = 0;
	m2p.value = metautils_gba_from_string(v);
	e = meta2_backend_set_container_properties(m2b, url, 0, &l);
	g_free(m2p.name);
	g_byte_array_free(m2p.value, TRUE);

	if (!e)
		return FILTER_OK;

	GRID_DEBUG("Fail to set [%s]=[%s] for %s", k, v,
			hc_url_get(url, HCURL_WHOLE));
	meta2_filter_ctx_set_error(ctx, e);
	return FILTER_KO;
}

int
meta2_filter_action_remove_container_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	const gchar *k;

	(void) reply;
	TRACE_FILTER();
	if (!(k = meta2_filter_ctx_get_param(ctx, "K")) || !*k) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(400, "Empty property key"));
		return FILTER_KO;
	}

	struct meta2_property_s m2p;
	m2p.name = g_strdup(k);
	m2p.version = 0;
	m2p.value = NULL;
	GSList l = {.data=&m2p, .next=NULL};
	e = meta2_backend_set_container_properties(m2b, url, 0, &l);
	g_free(m2p.name);

	if (!e)
		return FILTER_OK;

	GRID_DEBUG("Fail to delete property [%s] for %s", k,
			hc_url_get(url, HCURL_WHOLE));
	meta2_filter_ctx_set_error(ctx, e);
	return FILTER_KO;
}

int
meta2_filter_action_get_container_prop_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	const gchar *k0;
	gchar *v0 = NULL;
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;

	(void) reply;
	TRACE_FILTER();
	k0 = meta2_filter_ctx_get_param(ctx, "K");
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean _cb(gpointer u, const gchar *k, const guint8 *v, gsize vlen) {
		(void) u;
		if (k && !g_ascii_strcasecmp(k, k0)) {
			if (v0)
				g_free(v0);
			v0 = g_strndup((gchar*)v, vlen);
			return FALSE;
		}
		return TRUE;
	}
	err = meta2_backend_get_container_properties(m2b, url, 0, NULL, _cb);

	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (v0) {
		reply->add_header("field_2", metautils_gba_from_string(v0));
		reply->send_reply(200, "OK");
		g_free(v0);
		return FILTER_OK;
	}
	else {
		err = NEWERROR(CODE_CONTAINER_PROP_NOTFOUND, "No such property");
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
}

int
meta2_filter_action_list_usr_container_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	int rc;
	GError *err;
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;
	GSList *result = NULL;

	(void) reply;
	TRACE_FILTER();
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean _cb(gpointer u, const gchar *k, const guint8 *v, gsize vlen) {
		(void) u;
		if (!g_str_has_prefix(k, M2V2_PROP_PREFIX_USER))
			return TRUE;
		struct meta2_property_s *m2p = g_malloc0(sizeof(*m2p));
		m2p->name = g_strdup(k);
		m2p->version = 0;
		m2p->value = g_byte_array_append(g_byte_array_new(), v, vlen);
		result = g_slist_prepend(result, m2p);
		return TRUE;
	}

	err = meta2_backend_get_container_properties(m2b, url, 0, NULL, _cb);

	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		rc = FILTER_KO;
	}
	else {
		reply->add_body(meta2_property_marshall_gba(result, NULL));
		reply->send_reply(200, "OK");
		rc = FILTER_OK;
	}

	g_slist_free_full(result, g_free);
	return rc;
}

int
meta2_filter_action_list_all_container_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	int rc;
	GError *err;
	struct hc_url_s *url;
	struct meta2_backend_s *m2b;
	GSList *result = NULL;

	(void) reply;
	TRACE_FILTER();
	url = meta2_filter_ctx_get_url(ctx);
	m2b = meta2_filter_ctx_get_backend(ctx);

	gboolean _cb(gpointer u, const gchar *k, const guint8 *v, gsize vlen) {
		(void) u;
		if (!g_str_has_prefix(k, "version:")) {
			gchar *s = g_strdup_printf("%s=%.*s", k, (int)vlen, (gchar*)v);
			result = g_slist_prepend(result, s);
		}
		return FALSE;
	}

	err = meta2_backend_get_container_properties(m2b, url,
			M2V2_FLAG_ALLPROPS, NULL, _cb);

	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		rc = FILTER_KO;
	}
	else {
		reply->add_body(strings_marshall_gba(result, NULL));
		reply->send_reply(200, "OK");
		rc = FILTER_OK;
	}

	g_slist_free_full(result, (GDestroyNotify)g_free);
	return rc;
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
	lp.flags = M2V2_FLAG_NODELETED;
	lp.type = DEFAULT;
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
		reply->send_reply(200, "OK");
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

	err = message_extract_header_gba(reply->request, "ADMIN_KEY", TRUE, &key);
	if (!err)
		err = message_extract_header_gba(reply->request, "ADMIN_VALUE", TRUE, &value);
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

	reply->send_reply(200, "OK");
	return FILTER_OK;
}

/* -------------- RESTORE UTILITIES ----------------- */

struct restorev1_ctx_s {
	struct gridd_reply_ctx_s *reply;
	gboolean error;
	guint32 count_content;
	guint32 count_event;
	guint32 count_property;
	guint32 count_admin;
};

static gboolean
restorev1_content_cb(gpointer u, const meta2_raw_content_v2_t *p)
{
	gchar str[32];
	struct restorev1_ctx_s *ctx = u;

	g_assert(ctx != NULL);
	GRID_TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p)
		ctx->count_content ++;

	if ((!p && ctx->count_content) || ctx->count_content >= 50) {
		g_snprintf(str, sizeof(str), "%"G_GUINT32_FORMAT" contents", ctx->count_content);
		ctx->reply->send_reply(201, str);
		ctx->count_content = 0;
	}

	return TRUE;
}

static gboolean
restorev1_admin_cb(gpointer u, const key_value_pair_t *p)
{
	gchar str[32];
	struct restorev1_ctx_s *ctx = u;

	g_assert(ctx != NULL);
	TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p)
		ctx->count_admin ++;
	if ((!p && ctx->count_admin) || ctx->count_admin >= 50) {
		g_snprintf(str, sizeof(str), "%"G_GUINT32_FORMAT" admin", ctx->count_admin);
		ctx->reply->send_reply(201, str);
		ctx->count_admin = 0;
	}

	return TRUE;
}

static gboolean
restorev1_event_cb(gpointer u, const container_event_t *p)
{
	gchar str[64];
	struct restorev1_ctx_s *ctx = u;

	g_assert(ctx != NULL);
	TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p)
		ctx->count_event ++;
	if ((!p && ctx->count_event) || ctx->count_event >= 50) {
		g_snprintf(str, sizeof(str), "%"G_GUINT32_FORMAT" events", ctx->count_event);
		ctx->reply->send_reply(201, str);
		ctx->count_event = 0;
	}

	return TRUE;
}

static gboolean
restorev1_property_cb(gpointer u, const meta2_property_t *p)
{
	gchar str[64];
	struct restorev1_ctx_s *ctx = u;

	g_assert(ctx != NULL);
	TRACE("%s(%p,%p)", __FUNCTION__, u, p);

	if (p)
		ctx->count_property ++;
	if ((!p && ctx->count_property) || ctx->count_property >= 50) {
		g_snprintf(str, sizeof(str), "%"G_GUINT32_FORMAT" properties", ctx->count_property);
		ctx->reply->send_reply(201, str);
		ctx->count_property = 0;
	}

	return TRUE;
}

static struct meta2_restorev1_hooks_s notify_hooks =
{
	restorev1_content_cb,
	restorev1_admin_cb,
	restorev1_property_cb,
	restorev1_event_cb
};


int
meta2_filter_action_restore_container(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct restorev1_ctx_s notify_ctx;
	container_id_t peer_cid;
	const char *peer_cid_str = NULL;
	addr_info_t *peer_addr = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	memset(&notify_ctx, 0x00, sizeof(struct restorev1_ctx_s));
	memset(peer_cid, 0x00, sizeof(container_id_t));

	peer_addr = (addr_info_t *)meta2_filter_ctx_get_input_udata(ctx);
	peer_cid_str = meta2_filter_ctx_get_param(ctx, "SRC_CID");
	container_id_hex2bin(peer_cid_str, strlen(peer_cid_str), &peer_cid, &e);

	notify_ctx.reply = reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	e = meta2_backend_restore_container_from_peer(m2b, url, peer_cid, peer_addr,
			&notify_ctx, &notify_hooks);
	if(NULL != e) {
		GRID_DEBUG("Restore container failed : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
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
meta2_filter_action_substitute_chunks(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	int rc = FILTER_OK;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	// See meta2_filter_extract_header_chunk_beans()
	GSList **chunk_lists = meta2_filter_ctx_get_input_udata(ctx);
	gboolean restrict_to_alias = meta2_filter_ctx_get_param(ctx,
			"RESTRICT_TO_ALIAS") != NULL;

	GError *err = meta2_backend_substitute_chunks(m2b, url, restrict_to_alias,
			chunk_lists[0], chunk_lists[1]);

	if (err) {
		GRID_DEBUG("Failed to substitute chunks: %s", err->message);
		meta2_filter_ctx_set_error(ctx, err);
		rc = FILTER_KO;
	}

	return rc;
}

/* -------------- SNAPSHOT UTILITIES ----------------- */

int meta2_filter_action_take_snapshot(struct gridd_filter_ctx_s *ctx,
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

int meta2_filter_action_list_snapshots(struct gridd_filter_ctx_s *ctx,
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

int meta2_filter_action_delete_snapshot(struct gridd_filter_ctx_s *ctx,
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

int meta2_filter_action_restore_snapshot(struct gridd_filter_ctx_s *ctx,
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

