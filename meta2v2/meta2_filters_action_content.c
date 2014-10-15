#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <attr/xattr.h>
#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/events/gridcluster_events.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

enum content_action_e
{
	PUT=1,
	APPEND,
	DELETE,
};

struct content_info_s
{
	enum content_action_e action;
	GSList *beans;
};

struct all_vers_cb_args {
	const gchar *contentid;
	gconstpointer udata_in;
	gpointer udata_out;
};

// Defines a callback to be called for all versions of a given content.
typedef GError* (*all_vers_cb) (struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		struct all_vers_cb_args *cbargs);

static void _content_info_clean(gpointer p)
{
	if(!p)
		return;

	struct content_info_s *ci = (struct content_info_s *)p;

	if(NULL != ci->beans)
		_bean_cleanl2(ci->beans);

	g_free(ci);
}

static struct content_info_s *
_get_content_info(GSList *beans, enum content_action_e action)
{
	struct content_info_s *ci = g_malloc0(sizeof(struct content_info_s));
	ci->action = action;
	ci->beans = beans;
	return ci;
}

static void
_get_cb(gpointer udata, gpointer bean)
{
	struct on_bean_ctx_s *ctx = (struct on_bean_ctx_s*) udata;
	if (GRID_TRACE_ENABLED()) {
		GString *str = _bean_debug(NULL, bean);
		GRID_TRACE("Bean got: %s", str->str);
		g_string_free(str, TRUE);
	}
	if (ctx && ctx->l && g_slist_length(ctx->l) >= 32) {
		_on_bean_ctx_send_list(ctx, FALSE);
	}
	ctx->l = g_slist_prepend(ctx->l, bean);
}

static int
_reply_chunk_info_list(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		GSList *cil, const char *mdsys)
{
	GSList *list_of_lists = NULL, *cursor = NULL;
	GError *e = NULL;
	list_of_lists = gslist_split(cil, 32);
	for (cursor = list_of_lists; cursor; cursor = cursor->next) {
		GSList *l = cursor->data;
		GByteArray *body = chunk_info_marshall_gba(l, &e);
		if (!body) {
			GRID_DEBUG("Failed to marshall chunk info list");
			meta2_filter_ctx_set_error(ctx, e);
			gslist_chunks_destroy(list_of_lists, NULL);
			return FILTER_KO;
		}
		reply->add_body(body);
		reply->send_reply(206, "Partial content");
	}
	if (NULL != mdsys) {
		reply->add_header("METADATA_SYS", g_byte_array_append(g_byte_array_new(),
				(const guint8*)mdsys, strlen(mdsys)));
	}
	reply->send_reply(200, "OK");

	gslist_chunks_destroy(list_of_lists, NULL);

	return FILTER_OK;
}

int
meta2_filter_action_retrieve_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *beans = NULL;
	GSList *result = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	char *mdsys = NULL;

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		beans = g_slist_prepend(beans, bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if(!beans) {
		GRID_DEBUG("No beans returned by get_alias for: %s",
				hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_CONTENT_NOTFOUND,
				"Content not found (deleted) (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	result = chunk_info_list_from_m2v2_beans(beans, &mdsys);
	_bean_cleanl2(beans);

	_reply_chunk_info_list(ctx, reply, result, mdsys);

	if(NULL != mdsys)
		g_free(mdsys);

	g_slist_foreach(result, chunk_info_gclean, NULL);
	g_slist_free(result);

	return FILTER_OK;
}

static int
_reply_raw_content(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct meta2_raw_content_s *c, int code, char *m)
{
	GByteArray *enc = NULL;
	GError *e = NULL;

	/*encode the content */
	enc = meta2_maintenance_marshall_content(c, &e);
	if (!enc) {
		GRID_DEBUG("Failed to marshall raw content");
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}
	reply->add_body(enc);
	reply->send_reply(code, m);
	return FILTER_OK;
}

static int
_reply_chunked_raw_content(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		struct meta2_raw_content_s *rc)
{
	GSList *original_chunks, *list_of_lists, *cursor;
	original_chunks = rc->raw_chunks;
	list_of_lists = gslist_split(rc->raw_chunks, 32);
	for (cursor = list_of_lists; cursor; cursor = g_slist_next(cursor)) {

		if (!cursor->data) {
			GRID_WARN("NULL chunks sublist");
			continue;
		}
		rc->raw_chunks = (GSList *) cursor->data;
		if (g_slist_next(cursor)) {
			if(FILTER_KO == _reply_raw_content(ctx, reply, rc, 206, "partial content")) {
				rc->raw_chunks = original_chunks;
				gslist_chunks_destroy(list_of_lists, NULL);
				return FILTER_KO;
			}
		} else {
			if(FILTER_KO ==  _reply_raw_content(ctx, reply, rc, 200, "OK")) {
				rc->raw_chunks = original_chunks;
				gslist_chunks_destroy(list_of_lists, NULL);
				return FILTER_KO;
			}
		}
	}

	rc->raw_chunks = original_chunks;
	gslist_chunks_destroy(list_of_lists, NULL);
	return FILTER_OK;
}

int
meta2_filter_action_raw_chunks_get_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *beans = NULL;
	struct meta2_raw_content_s *rc = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	int status = FILTER_OK;

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		if (DESCR(bean) == &descr_struct_PROPERTIES && PROPERTIES_get_deleted(bean)) {
			/* we don't want deleted props */
			_bean_clean(bean);
		} else {
		beans = g_slist_prepend(beans, bean);
		}
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED | M2V2_FLAG_ALLPROPS, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}
	if(!beans) {
		GRID_DEBUG("No beans returned by get_alias for: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_CONTENT_NOTFOUND,
				"Content not found (deleted) (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	GRID_DEBUG("Raw chunk get returns %d beans", g_slist_length(beans));

	rc = raw_content_from_m2v2_beans(hc_url_get_id(url), beans);
	_bean_cleanl2(beans);

	if (!rc) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if(g_slist_length(rc->raw_chunks) > 0) {
		GSList *l = NULL;
		for(l = rc->raw_chunks; l && l->data; l = l->next) {
			meta2_raw_chunk_t *c = (meta2_raw_chunk_t*) l->data;
			char buf[512];
			memset(buf, '\0', 512);
			chunk_id_to_string(&(c->id), buf, 512);
			memset(buf, '\0', 512);
			buffer2str(c->hash, sizeof(c->hash), buf, 512);
		}
	}

	/******************/

	if (!rc->raw_chunks) {
		status = _reply_raw_content(ctx, reply, rc, 200, "OK");
	} else {
		status = _reply_chunked_raw_content(ctx, reply, rc);
	}

	meta2_raw_content_clean(rc);

	return status;
}

static int
_put_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);

	GRID_DEBUG("Putting %d beans", g_slist_length(beans));

	if(NULL != meta2_filter_ctx_get_param(ctx, M2_KEY_OVERWRITE)) {
		e = meta2_backend_force_alias(m2b, url, beans);
		if(!e)
			reply->send_reply(200, "OK");
	} else {
		struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
		e = meta2_backend_put_alias(m2b, url, beans, _get_cb, obc);
		if(!e) {
			_on_bean_ctx_send_list(obc, TRUE);
		}
		_on_bean_ctx_clean(obc);
	}

	if(NULL != e) {
		GRID_DEBUG("Fail to put alias (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

static int
_copy_alias(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		const char *source)
{
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GRID_DEBUG("Copying %s from %s", hc_url_get(url, HCURL_WHOLE), source);

	e = meta2_backend_copy_alias(m2b, url, source);
	if (NULL != e) {
		GRID_DEBUG("Fail to copy alias (%s) to (%s)", source, hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	} else {
		// For notification purposes, we need to load all the beans
		struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
		e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NOPROPS, _get_cb, obc);
		if (!e) {
			_on_bean_ctx_send_list(obc, TRUE);
		}
		_on_bean_ctx_clean(obc);
	}

	return FILTER_OK;
}

int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	const char *copy_source = meta2_filter_ctx_get_param(ctx, M2_KEY_COPY_SOURCE);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if(NULL != copy_source) {
		reply->subject("%s|%s|COPY(%s)", hc_url_get(url, HCURL_WHOLE),
				hc_url_get(url, HCURL_HEXID), copy_source);
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
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	GRID_DEBUG("Appending %d beans", g_slist_length(beans));

	e = meta2_backend_append_to_alias(m2b, url, beans, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Fail to append to alias (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
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
	gint64 limit = -1; // negative means unlimited
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	const gchar *chunk_id = meta2_filter_ctx_get_param(ctx, M2_KEY_CHUNK_ID);
	const gchar *limit_str = meta2_filter_ctx_get_param(ctx, M2_KEY_MAX_KEYS);
	GSList *urls = NULL;

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
		flags = g_ntohl(flags);
	}
	if (limit_str != NULL && limit_str[0] != '\0') {
		limit = atoll(limit_str);
	}

	if (chunk_id == NULL) {
		urls = g_slist_prepend(urls, hc_url_init(hc_url_get(url, HCURL_WHOLE)));
	} else {
		// Search aliases referencing a specific chunk and build URLs
		GRID_DEBUG("Searching aliases referencing chunk %s", chunk_id);
		e = meta2_backend_get_content_urls_from_chunk_id(m2b, url, chunk_id,
				limit, &urls);
		if (e != NULL) {
			GRID_ERROR("Failed getting aliases from chunk id: %s", e->message);
			meta2_filter_ctx_set_error(ctx, e);
			goto cleanup;
		}

		if (urls == NULL) {
			e = NEWERROR(404,
					"Did not find any matching alias for chunk %s",
					chunk_id);
			GRID_DEBUG(e->message);
			meta2_filter_ctx_set_error(ctx, e);
			goto cleanup;
		}
		if (GRID_TRACE_ENABLED()) {
			for (GSList *cursor = urls; cursor; cursor = cursor->next) {
				GRID_TRACE("Found alias: %s",
						hc_url_get(cursor->data, HCURL_WHOLE));
			}
		}
	}

	for (GSList *cursor = urls; cursor != NULL; cursor = cursor->next) {
		struct hc_url_s *url2 = cursor->data;
		e = meta2_backend_get_alias(m2b, url2, flags, _get_cb, obc);
		if (NULL != e) {
			GRID_DEBUG("Fail to return alias for url: %s",
					hc_url_get(url2, HCURL_WHOLE));
			meta2_filter_ctx_set_error(ctx, e);
			goto cleanup;
		}
	}

	_on_bean_ctx_send_list(obc, TRUE);
	rc = FILTER_OK;

cleanup:
	g_slist_free_full(urls, (GDestroyNotify)hc_url_clean);
	_on_bean_ctx_clean(obc);
	return rc;
}

int
meta2_filter_action_delete_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	guint32 flags = 0;
	gboolean sync_del = FALSE;
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	if (fstr != NULL) {
		flags = (guint32)atoi(fstr);
	}
	sync_del = BOOL(flags & M2V2_FLAG_SYNCDEL);

	TRACE_FILTER();
	e = meta2_backend_delete_alias(m2b, url, sync_del, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Fail to delete alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	// This is required for Kafka notifications to work
	_on_bean_ctx_send_list(obc, FALSE);

	//generate notification before send reply, 
	//besause a destroy container should executes 
	//   before realy generated events was created on disk
	//   and no chunk on it ! no purge by polix!
	meta2_filter_action_notify_content_DELETE_v2(ctx, reply, obc);

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_remove_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;

	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	TRACE_FILTER();

	/* store in transient */
	e = m2b_transient_put(m2b, hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), _get_content_info(NULL, DELETE),
			(GDestroyNotify)_content_info_clean);
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

static int
_validate_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = NULL;

	struct content_info_s *ci = (struct content_info_s *) m2b_transient_get(
			m2b, hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID), &e);
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if (!ci) {
		GRID_DEBUG("Cannot validate properties, cannot find informations in m2b_transient about it!");
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST, "Cannot find any information"
				" about properties to validate (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	GString *tmp = NULL;
	GSList *l = NULL;
	for(l=ci->beans; l && l->data; l=l->next){
		tmp = _bean_debug(tmp, l->data);
	}
	g_string_free(tmp, TRUE);

	obc = _on_bean_ctx_init(ctx, reply);
	e = meta2_backend_set_properties(m2b, url, ci->beans, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Failed to set properties to (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	m2b_transient_del(m2b, hc_url_get(url, HCURL_WHOLE),hc_url_get(url, HCURL_HEXID));

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

static int
_cancel_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	GError *e = NULL;

	if (NULL != (e = meta2_backend_has_master_container(m2b, url))) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	e = m2b_transient_del(m2b, hc_url_get(url, HCURL_WHOLE),
			hc_url_get(url, HCURL_HEXID));
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	reply->send_reply(200, "OK");

	return FILTER_OK;
}

static int
_init_set_content_properties(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	GError *e = NULL;
	GSList *tostore = NULL, *l = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (NULL != (e = meta2_backend_has_master_container(m2b, url))) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED,
			NULL, NULL);
	if (NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	/* perform a copy of our beans, input data will be freed at end of the first call */
	for(l = beans; l && l->data; l = l->next) {
		tostore = g_slist_prepend(tostore, _bean_dup(l->data));
	}

	/* store in transient to commit later */
	e = m2b_transient_put(m2b, hc_url_get(url, HCURL_WHOLE),
			hc_url_get(url, HCURL_HEXID), _get_content_info(tostore, PUT),
			(GDestroyNotify) _content_info_clean);
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	reply->send_reply(200, "OK");
	return FILTER_OK;
}

static int
_set_content_properties(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	guint32 flags = 0;
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	GSList *props = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	if (fstr != NULL) {
		flags = (guint32)atoi(fstr);
	}

	if (hc_url_has(url, HCURL_PATH)) {
		e = meta2_backend_set_properties(m2b, url, beans, _get_cb, obc);
	} else {
		for (GSList *l = beans; l != NULL; l = l->next) {
			if (DESCR(l->data) == &descr_struct_PROPERTIES) {
				props = g_slist_prepend(props, bean_to_meta2_prop(l->data));
			}
		}
		e = meta2_backend_set_container_properties(m2b, url, flags, props);
		if (e == NULL) {
			for (GSList *l = beans; l != NULL; l = l->next) {
				if (DESCR(l->data) == &descr_struct_PROPERTIES) {
					obc->l = g_slist_prepend(obc->l, _bean_dup(l->data));
				}
			}
		}

		g_slist_free_full(props, (GDestroyNotify)meta2_property_clean);
	}

	if (NULL != e) {
		GRID_DEBUG("Failed to set properties to (%s)",
				hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

#define CONTENT_PROP_INIT	1
#define CONTENT_PROP_VALIDATE	2
#define CONTENT_PROP_CANCEL	3

int
meta2_filter_action_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	const char *fstr = meta2_filter_ctx_get_param(ctx, "ACTION");
	int action = 0;

	TRACE_FILTER();
	if (NULL != fstr) {
		action = atoi(fstr);
	}

	switch (action) {
		case CONTENT_PROP_INIT:
			GRID_DEBUG("ACTION init");
			return _init_set_content_properties(ctx, reply);
		case CONTENT_PROP_VALIDATE:
			GRID_DEBUG("ACTION validate");
			return _validate_set_content_properties(ctx, reply);
		case CONTENT_PROP_CANCEL:
			GRID_DEBUG("ACTION cancel ");
			return _cancel_set_content_properties(ctx, reply);
		default:
			GRID_DEBUG("ACTION classic");
			return _set_content_properties(ctx, reply);
	}
}

int
meta2_filter_action_get_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	guint32 flags = 0;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
		flags = g_htonl(flags);
	}

	gboolean _prop_to_bean(gpointer udata, const gchar *k, const guint8 *v, gsize vlen) {
		struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_key(prop, k);
		if (v != NULL)
			PROPERTIES_set2_value(prop, v, vlen);
		_get_cb(udata, prop);
		return FALSE;
	}

	if (hc_url_has(url, HCURL_PATH)) {
		e = meta2_backend_get_properties(m2b, url, flags, _get_cb, obc);
	} else {
		e = meta2_backend_get_container_properties(m2b, url, flags, obc, _prop_to_bean);
	}
	if (NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);

	return FILTER_OK;
}

int
meta2_filter_action_set_content_prop_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	GSList * props = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *prop_key = meta2_filter_ctx_get_param(ctx, "field_2");
	const char *prop_value = meta2_filter_ctx_get_param(ctx, "field_3");

	void _cb(gpointer udata, gpointer bean)
	{
		(void) udata;
		_bean_clean(bean);
	}

	TRACE_FILTER();

	struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
	PROPERTIES_set_alias_version(prop, 1L);
	PROPERTIES_set_key(prop, g_string_new(prop_key));
	PROPERTIES_set_value(prop, g_byte_array_append(g_byte_array_new(), (guint8*)g_strdup(prop_value), strlen(prop_value)));
	PROPERTIES_set_deleted(prop, FALSE);

	props = g_slist_prepend(props, prop);

	e = meta2_backend_set_properties(m2b, url, props, _cb, NULL);

	_bean_cleanl2(props);

	if(NULL != e) {
		GRID_DEBUG("Failed to set property key=[%s] value=[%s] to (%s)", prop_key, prop_value, hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_remove_content_prop_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;

	(void) reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *prop_key = meta2_filter_ctx_get_param(ctx, "field_2");
	GSList *props = NULL;

	TRACE_FILTER();

	struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
	PROPERTIES_set_alias_version(prop, 1L);
	PROPERTIES_set2_key(prop, prop_key);
	PROPERTIES_set2_value(prop, (guint8*)"", 1);
	PROPERTIES_set_deleted(prop, TRUE);

	props = g_slist_prepend(props, prop);

	e = meta2_backend_set_properties(m2b, url, props, NULL, NULL);

	_bean_cleanl2(props);

	if(NULL != e) {
		GRID_DEBUG("Failed to remove property key=[%s] from (%s)", prop_key, hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_modify_mdusr_v1(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *props = NULL;

	(void) reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *mdusr = meta2_filter_ctx_get_param(ctx, "V");

	struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
	PROPERTIES_set_alias_version(prop, 1L);
	PROPERTIES_set2_key(prop, MDUSR_PROPERTY_KEY);
	if(NULL != mdusr) {
		PROPERTIES_set2_value(prop, (guint8*)mdusr, strlen(mdusr));
		PROPERTIES_set_deleted(prop, FALSE);
	} else {
		PROPERTIES_set2_value(prop, (guint8*)" ", 1);
		PROPERTIES_set_deleted(prop, TRUE);
	}


	props = g_slist_prepend(props, prop);

	e = meta2_backend_set_properties(m2b, url, props, NULL, NULL);
	if(NULL != e) {
		GRID_DEBUG("Error while setting mdsys : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		_bean_cleanl2(props);
		return FILTER_KO;
	}

	_bean_cleanl2(props);

	return FILTER_OK;
}

int
meta2_filter_action_modify_mdsys_v1(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *beans = NULL;
	gpointer alias = NULL;
	gpointer header = NULL;

	(void) reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *mdsys = meta2_filter_ctx_get_param(ctx, "V");

	void _get_alias_header_cb(gpointer udata, gpointer bean) {
		(void) udata;
		if(DESCR(bean) == &descr_struct_ALIASES)
			alias = bean;
		else if(DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			header = bean;
		else if(DESCR(bean) == &descr_struct_CONTENTS)
			beans = g_slist_prepend(beans, bean);
		else if(DESCR(bean) == &descr_struct_CHUNKS)
			beans = g_slist_prepend(beans, bean);
		else
			_bean_clean(bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED,
			_get_alias_header_cb, NULL);
	if (NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	char *sp = storage_policy_from_mdsys_str(mdsys);
	ALIASES_set2_mdsys(alias, mdsys);
	if (NULL != sp) {
		const gchar *old_sp = CONTENTS_HEADERS_get_policy(header)->str;
		e = storage_policy_check_compat_by_name(&(m2b->ns_info), old_sp, sp);
		if (e == NULL)
			CONTENTS_HEADERS_set2_policy(header, sp);
		g_free(sp);
	}

	beans = g_slist_prepend(g_slist_prepend(beans, header), alias);
	if (e == NULL) {
		// skip checks only when changing stgpol
		e = meta2_backend_update_alias_header(m2b, url, beans, (sp != NULL));
	}
	_bean_cleanl2(beans);

	if (NULL != e) {
		GRID_DEBUG("Failed to update alias/headers: %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}


int
meta2_filter_action_get_content_prop_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	const char *prop_key = meta2_filter_ctx_get_param(ctx, "field_2");

	void _cb(gpointer udata, gpointer bean)
	{
		(void) udata;
		if(!PROPERTIES_get_deleted(bean)) {
			GByteArray *val = PROPERTIES_get_value(bean);
			char buf[val->len + 1];
			memset(buf, '\0', val->len + 1);
			memcpy(buf, val->data, val->len);
			reply->add_header("field_3", g_byte_array_append(g_byte_array_new(),
					val->data, val->len));
		}
		_bean_clean(bean);
	}

	TRACE_FILTER();

	e = meta2_backend_get_property(m2b, url, prop_key, M2V2_FLAG_NODELETED, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	reply->send_reply(200, "OK");
	return FILTER_OK;
}

int meta2_filter_action_list_all_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 flags = 0;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);
	const gchar *prop_key = meta2_filter_ctx_get_param(ctx, "field_2");
	GSList *beans = NULL;

	void _cb(gpointer udata, gpointer _bean)
	{
		(void) udata;
		struct bean_PROPERTIES_s *bean = _bean;
		GRID_TRACE("Getting a bean from database (legacy mode)");
		beans = g_slist_prepend(beans, bean);
	}

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
		flags = g_htonl(flags);
	}

	e = meta2_backend_get_property(m2b, url, prop_key, flags, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	reply->add_header("field_3", bean_sequence_marshall(beans));
	reply->send_reply(200, "OK");
	_bean_cleanl2(beans);

	return FILTER_OK;
}

static GError*
_spare_with_blacklist(struct meta2_backend_s *m2b,
		struct gridd_filter_ctx_s *ctx, struct on_bean_ctx_s *obc,
		struct hc_url_s *url, const gchar *polname)
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
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
	const char *size_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CONTENTLENGTH);
	const char *policy_str = meta2_filter_ctx_get_param(ctx, M2_KEY_STORAGE_POLICY);
	const char *mdsys = meta2_filter_ctx_get_param(ctx, M2V1_KEY_METADATA_SYS);
	const char *spare_type = meta2_filter_ctx_get_param(ctx, M2_KEY_SPARE);
	gboolean append = (NULL != meta2_filter_ctx_get_param(ctx, "APPEND"));

	TRACE_FILTER();
	if (NULL != size_str)
		size = g_ascii_strtoll(size_str, NULL, 10);

	// Spare beans request
	if (spare_type != NULL) {
		reply->subject("%s|%s|%s", hc_url_get(url, HCURL_WHOLE),
				hc_url_get(url, HCURL_HEXID), spare_type);
		if (strcmp(spare_type, M2V2_SPARE_BY_BLACKLIST) == 0) {
			e = _spare_with_blacklist(m2b, ctx, obc, url, policy_str);
		} else if (strcmp(spare_type, M2V2_SPARE_BY_STGPOL) == 0) {
			e = meta2_backend_get_spare_chunks(m2b, url, policy_str,
					&(obc->l), TRUE);
		} else {
			e = NEWERROR(CODE_BAD_REQUEST, "Unknown type of spare request: %s", spare_type);
		}
		if (e != NULL) {
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}
	// Standard beans request
	else {
		e = meta2_backend_generate_beans_v1(m2b, url, size, policy_str, append,
				mdsys, NULL, _get_cb, obc);
		if (NULL != e) {
			GRID_DEBUG("Failed to return alias for url: %s",
					hc_url_get(url, HCURL_WHOLE));
			_on_bean_ctx_clean(obc);
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

static int
_generate_chunks(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		gboolean append)
{
	GError *e = NULL;
	gint64 size = 0;
	GSList *beans = NULL, *cil = NULL;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *size_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CONTENTLENGTH);
	const char *mdsys = meta2_filter_ctx_get_param(ctx, M2V1_KEY_METADATA_SYS);
	const char *mdusr = meta2_filter_ctx_get_param(ctx, M2V1_KEY_METADATA_USR);

	char *out_mdsys = NULL;

	GRID_TRACE2("mdsys extracted from request : %s", mdsys);

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		beans = g_slist_prepend(beans, bean);
	}

	TRACE_FILTER();
	if (NULL != size_str)
		size = g_ascii_strtoll(size_str, NULL, 10);

	e = meta2_backend_generate_beans_v1(m2b, url, size, NULL, append, mdsys, NULL, _cb, NULL);
	if (NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	/* */
	if(NULL != mdusr && !append) {
		gpointer prop = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(prop, hc_url_get(url, HCURL_PATH));
		PROPERTIES_set_alias_version(prop, 1);
		PROPERTIES_set2_key(prop, MDUSR_PROPERTY_KEY);
		PROPERTIES_set2_value(prop, (const guint8*) mdusr, strlen(mdusr));
		PROPERTIES_set_deleted(prop, FALSE);
		beans = g_slist_prepend(beans, prop);
	}

	/* store in transient to commit later */
	e = m2b_transient_put(m2b, hc_url_get(url, HCURL_WHOLE),
			hc_url_get(url, HCURL_HEXID), _get_content_info(beans, (append
					? APPEND : PUT)), (GDestroyNotify) _content_info_clean);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	GRID_DEBUG("nb beans generated : %d", g_slist_length(beans));

	cil = chunk_info_list_from_m2v2_beans(beans, &out_mdsys);
	_reply_chunk_info_list(ctx, reply, cil, out_mdsys);

	g_slist_foreach(cil, chunk_info_gclean, NULL);
	g_slist_free(cil);

	if(NULL != out_mdsys)
		g_free(out_mdsys);

	return FILTER_OK;
}

int
meta2_filter_action_generate_append_chunks(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return _generate_chunks(ctx, reply, TRUE);
}

int
meta2_filter_action_generate_chunks(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return _generate_chunks(ctx, reply, FALSE);
}

static GSList*
_keep_chunks(GSList *in_place, GSList *tmp)
{
	GSList *result = NULL;
	GByteArray *cid = NULL;
	/* drop content / chunks in place, save content id */
	for(; in_place; in_place = in_place->next) {
		if(!in_place->data)
			continue;
		if( DESCR(in_place->data) == &descr_struct_CONTENTS ||
			DESCR(in_place->data) == &descr_struct_CHUNKS) {
			_bean_clean(in_place->data);
		} else {
			if(DESCR(in_place->data) == &descr_struct_ALIASES) {
				cid = ALIASES_get_content_id(in_place->data);
			}
			result = g_slist_prepend(result, in_place->data);
		}
	}

	g_slist_free(in_place);

	/* update contents with kept content id, add contents and chunks to the list */
	for(; tmp ; tmp = tmp->next) {
		if(!tmp->data)
			continue;
		if(DESCR(tmp->data) == &descr_struct_CONTENTS) {
			/* replace content id */
			CONTENTS_set2_content_id(tmp->data, cid->data, cid->len);
			result = g_slist_prepend(result, tmp->data);
		} else if (DESCR(tmp->data) == &descr_struct_CHUNKS) {
			result = g_slist_prepend(result, tmp->data);
		} else {
			_bean_clean(tmp->data);
		}
	}

	g_slist_free(tmp);

	return result;
}

int
meta2_filter_action_update_chunk_md5(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *err = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);

	if (NULL != (err = meta2_backend_has_master_container(m2b, url))) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	struct content_info_s *ci = (struct content_info_s *) m2b_transient_get(
			m2b, hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID),
			&err);

	if (!ci) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	GSList *cil = meta2_filter_ctx_get_input_udata(ctx);
	GSList *tmp = m2v2_beans_from_chunk_info_list(NULL,
			hc_url_get(url, HCURL_PATH), cil);

	/* keep contents & chunks (lists free'd inside) */
	ci->beans = _keep_chunks(ci->beans, tmp);

	return FILTER_OK;
}

static void
_update_url_version_from_content(struct meta2_raw_content_s *content,
		struct hc_url_s *url)
{
	if (content && content->version > 0) {
		gchar *tmp = g_strdup_printf("%"G_GINT64_FORMAT, content->version);
		hc_url_set(url, HCURL_VERSION, tmp);
		g_free(tmp);
	}
}

static GError*
_add_beans(struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		const gchar *cid,
		const gchar *pos_pfx)
{
	GError *err = NULL;
	GSList *beans;

	/* Map the raw content into beans */
	if (pos_pfx) {
		char* _make_subpos(guint32 pos, void *udata)
		{
			char *prefix = udata;
			return g_strdup_printf("%s%u", prefix, pos);
		}
		beans = m2v2_beans_from_raw_content_custom(cid, content,
				_make_subpos, (void*) pos_pfx);
	} else {
		beans = m2v2_beans_from_raw_content(cid, content);
	}

	/* force the alias beans to be saved */
	err = meta2_backend_force_alias(m2b, url, beans);
	_bean_cleanl2(beans);

	return err;
}

static GError*
_add_beans_cb(struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		struct all_vers_cb_args *cbargs)
{
	const gchar *cid = cbargs ? cbargs->contentid : NULL;
	const gchar *pos_pfx = cbargs ? cbargs->udata_in : NULL;
	return _add_beans(m2b, content, url, cid, pos_pfx);
}

static gboolean
_version_contains_chunk(struct meta2_raw_content_s *content,
		gpointer bean)
{
	if (bean && DESCR(bean) == &descr_struct_CHUNKS) {
		GString *id_from_bean = CHUNKS_get_id(bean);
		GSList *l = content->raw_chunks;
		struct meta2_raw_chunk_s *chunk;
		gchar strid[2048];
		for (; l; l = l->next) {
			chunk = l->data;
			memset(strid, 0, sizeof(strid));
			(void) chunk_id_to_string(&(chunk->id), strid, sizeof(strid));
			strid[STRLEN_CHUNKID - 1] = '\0';
			if (0 == g_strcmp0(strid, strrchr(id_from_bean->str, '/') + 1))
				return TRUE;
		}
	}
	return FALSE;
}

static GError*
_call_for_all_versions(struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		all_vers_cb cb,
		struct all_vers_cb_args *cbargs)
{
	GError *err = NULL;
	gint64 maxvers = 1;
	gboolean found_chunk = FALSE;

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		if (!found_chunk)
			found_chunk = _version_contains_chunk(content, bean);
		_bean_clean(bean);
	}

	err = meta2_backend_get_alias_version(m2b, url, 0, &maxvers);
	if (!err) {
		for (gint64 v = 1; v <= maxvers && !err; v++) {
			found_chunk = FALSE;
			content->version = v;
			_update_url_version_from_content(content, url);
			err = meta2_backend_get_alias(m2b, url, 0, _cb, NULL);
			if (!err) {
				// skip this version if it does not contain the given chunk
				if (found_chunk)
					err = cb(m2b, content, url, cbargs);
			} else if (err->code == CODE_CONTENT_NOTFOUND) {
				// skip this version if not found or deleted
				g_clear_error(&err);
			}
		}
	}

	return err;
}

static gboolean
_has_versioning(struct meta2_backend_s *m2b, struct hc_url_s *url)
{
	gint64 maxvers = 0;
	GError *err = meta2_backend_get_max_versions(m2b, url, &maxvers);
	if (err) {
		GRID_ERROR("Failed getting max versions for ref [%s]: %s",
				hc_url_get(url, HCURL_REFERENCE),
				err->message);
		g_clear_error(&err);
		return FALSE;
	}
	//  0 -> versioning disabled
	// -1 -> unlimited
	// >0 -> number of versions
	return maxvers != 0;
}

int
meta2_filter_action_add_raw_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct hc_url_s *url = hc_url_empty();
	struct meta2_backend_s *m2b;
	struct meta2_raw_content_s *content;
	const char *position_prefix = meta2_filter_ctx_get_param(ctx, "POSITION_PREFIX");

	(void) reply;
	TRACE_FILTER();
	m2b = meta2_filter_ctx_get_backend(ctx);
	content = meta2_filter_ctx_get_input_udata(ctx);

	gchar content_id[64];
	memset(content_id, 0, sizeof(content_id));
	SHA256_randomized_string(content_id, sizeof(content_id));

	char hexid[65];
	memset(hexid, '\0', 65);
	buffer2str(content->container_id, sizeof(container_id_t), hexid, 65);

	/* fill url */
	hc_url_set(url, HCURL_NS, m2b->ns_name);
	hc_url_set(url, HCURL_HEXID, hexid);
	hc_url_set(url, HCURL_PATH, content->path);

	if (_has_versioning(m2b, url)) {
		struct all_vers_cb_args cbargs = {
				.contentid = content_id,
				.udata_in = position_prefix,
				.udata_out = NULL
		};
		err = _call_for_all_versions(m2b, content, url, _add_beans_cb, &cbargs);
	} else {
		_update_url_version_from_content(content, url);
		err = _add_beans(m2b, content, url, content_id, position_prefix);
	}

	/* clean up tmp url */
	hc_url_clean(url);

	if (NULL != err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	return FILTER_OK;
}

static GSList*
_merge_beans(GSList *in_place, GSList *to_drop)
{
	gboolean _chunk_to_drop(GSList *l, gpointer chunk)
	{
		for(; l; l = l->next) {
			if(!l->data)
				continue;
			if(DESCR(l->data) == &descr_struct_CHUNKS) {
				if(0 == g_ascii_strcasecmp(CHUNKS_get_id(l->data)->str, CHUNKS_get_id(chunk)->str)) {
					return TRUE;
				}
			}
		}
		return FALSE;
	}

	gboolean _content_to_drop(GSList *l, gpointer content)
	{
		for(; l; l = l->next) {
			if(!l->data)
				continue;
			if(DESCR(l->data) == &descr_struct_CONTENTS) {
				if(0 == g_ascii_strcasecmp(CONTENTS_get_chunk_id(l->data)->str, CONTENTS_get_chunk_id(content)->str)) {
					return TRUE;
				}
			}
		}
		return FALSE;
	}

	GSList *result = NULL;
	for(; in_place; in_place = in_place->next) {
		if(!in_place->data)
			continue;
		if(DESCR(in_place->data) == &descr_struct_CONTENTS) {
			if(!_content_to_drop(to_drop, in_place->data)) {
				continue;
			}
		} else if (DESCR(in_place->data) == &descr_struct_CHUNKS) {
			if(!_chunk_to_drop(to_drop, in_place->data)) {
				continue;
			}
		}
		result = g_slist_prepend(result, _bean_dup(in_place->data));
	}

	return result;
}

static GError*
_delete_beans(struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url)
{
	GError *err = NULL;
	GSList *beans = NULL, *to_drop = NULL, *in_place = NULL;
	GString *content_id = NULL;

	void _cb(gpointer udata, gpointer bean) {
		(void) udata;
		in_place = g_slist_prepend(in_place, bean);
		if (content_id == NULL && DESCR(bean) == &descr_struct_ALIASES) {
			content_id = metautils_gba_to_hexgstr(NULL,
					ALIASES_get_content_id(bean));
		}
	}

	err = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _cb, NULL);
	if (NULL != err) {
		GRID_DEBUG("Failed to get alias : %s", err->message);
		goto exit;
	}

	to_drop = m2v2_beans_from_raw_content(content_id ? content_id->str : "1",
			content);

	/* remove chunks & contents */
	beans = _merge_beans(in_place, to_drop);

	err = meta2_backend_delete_chunks(m2b, url, beans);

exit:
	_bean_cleanl2(in_place);
	_bean_cleanl2(to_drop);
	_bean_cleanl2(beans);
	g_string_free(content_id, TRUE);

	return err;
}

static GError*
_delete_beans_cb(struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		struct all_vers_cb_args *cbargs)
{
	(void) cbargs;
	return _delete_beans(m2b, content, url);
}

	int
meta2_filter_action_remove_raw_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	GError *e = NULL;
	gchar strcid[STRLEN_CONTAINERID];
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct meta2_raw_content_s *content = meta2_filter_ctx_get_input_udata(ctx);
	container_id_to_string(content->container_id, strcid, sizeof(strcid));

	TRACE_FILTER();

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, m2b->ns_name);
	hc_url_set(url, HCURL_HEXID, strcid);
	hc_url_set(url, HCURL_PATH, content->path);

	if (_has_versioning(m2b, url)) {
		e = _call_for_all_versions(m2b, content, url, _delete_beans_cb, NULL);
	} else {
		_update_url_version_from_content(content, url);
		e = _delete_beans(m2b, content, url);
	}

	hc_url_clean(url);

	if (NULL != e) {
		GRID_DEBUG("Failed to force alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

	int
meta2_filter_action_content_commit_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;

	void _cb(gpointer udata, gpointer bean) {
		(void) udata;
		_bean_clean(bean);
	}

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct content_info_s *ci = (struct content_info_s *)m2b_transient_get(m2b, hc_url_get(url, HCURL_WHOLE),hc_url_get(url, HCURL_HEXID),&e);
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if(!ci) {
		GRID_DEBUG("Cannot commit content, cannot find informations in m2b_transient about it!");
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST, "Cannot find any information"
					" about content to commit (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	switch(ci->action) {
		case PUT:
			GRID_DEBUG("Performing put_alias on [%s]", hc_url_get(url, HCURL_WHOLE));
			e = meta2_backend_put_alias(m2b, url, ci->beans, _cb, NULL);
			break;
		case APPEND:
			GRID_DEBUG("Performing append_alias on [%s]", hc_url_get(url, HCURL_WHOLE));
			e = meta2_backend_append_to_alias(m2b, url, ci->beans, _cb, NULL);
			break;
		case DELETE:
			GRID_DEBUG("Performing delete_alias on [%s]", hc_url_get(url, HCURL_WHOLE));
			e = meta2_backend_delete_alias(m2b, url, FALSE, _cb, NULL);
			break;
	}

	m2b_transient_del(m2b, hc_url_get(url, HCURL_WHOLE),hc_url_get(url, HCURL_HEXID));

	if(NULL != e) {
		GRID_DEBUG("Content commit failed : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_content_rollback_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GError *e = NULL;

	if (NULL != (e = meta2_backend_has_master_container(m2b, url))) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	/* we don't take care of any error */
	e= m2b_transient_del(m2b, hc_url_get(url, HCURL_WHOLE),hc_url_get(url, HCURL_HEXID));
	if(NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

/* ------------ CONTENT SERVICES ------------------*/

	int
meta2_filter_action_add_service_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	GSList singleton, *l, *paths;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *srvtype = meta2_filter_ctx_get_param(ctx, "SRVTYPE");
	struct service_info_s *si = NULL;

	TRACE_FILTER();

	paths = meta2_filter_ctx_get_input_udata(ctx);

	err = meta2_backend_poll_service(m2b, srvtype, &si);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	gchar straddr[STRLEN_ADDRINFO];
	addr_info_to_string(&(si->addr), straddr, sizeof(straddr));

	gchar *k = g_strdup_printf("sys.srv.%s", srvtype);

	struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set_alias_version(prop, 1);
	PROPERTIES_set2_key(prop, k);
	PROPERTIES_set2_value(prop, (guint8*)straddr, strlen(straddr));
	PROPERTIES_set_deleted(prop, FALSE);

	for (l=paths; !err && l ;l=l->next) {
		GRID_TRACE("Binding [%s]=[%s] to [%s]", k, straddr, (gchar*)l->data);
		if (!l->data)
			continue;
		singleton.data = prop;
		singleton.next = NULL;
		hc_url_set(url, HCURL_PATH, (gchar*)(l->data));
		PROPERTIES_set2_alias(prop, (gchar*)(l->data));
		err = meta2_backend_set_properties(m2b, url, &singleton, NULL, NULL);
	}

	g_free(k);
	k = NULL;
	_bean_clean(prop);
	prop = NULL;

	if (err)
		meta2_filter_ctx_set_error(ctx, err);
	else {
		singleton.next = NULL;
		singleton.data = si;
		reply->add_body(service_info_marshall_gba(&singleton, NULL));
	}

	service_info_clean(si);
	si = NULL;

	return err ? FILTER_KO : FILTER_OK;
}

	int
meta2_filter_action_list_content_services(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct args_s {
		gchar *key;
		GSList *result;
	};

	void cb(gpointer u, gpointer bean) {
		struct args_s *pargs = u;
		if (!g_strcmp0(PROPERTIES_get_key(bean)->str, pargs->key)) {
			GByteArray *val = PROPERTIES_get_value(bean);
			if (val && val->len) {
				addr_info_t ai;
				g_byte_array_append(val, (guint8*)"", 1);
				if (l4_address_init_with_url(&ai, (gchar*)val->data, NULL)) {
					pargs->result = g_slist_prepend(pargs->result,
							g_memdup(&ai, sizeof(ai)));
				}
			}
		}
		_bean_clean(bean);
	}

	void cleanup(gpointer p) {
		if (!p)
			return;
		g_slist_foreach((GSList*)p, addr_info_gclean, NULL);
		g_slist_free((GSList*)p);
	}

	GError *err;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *srvtype = meta2_filter_ctx_get_param(ctx, "SRVTYPE");
	struct args_s args = {NULL, NULL};

	TRACE_FILTER();

	args.key = g_strdup_printf("sys.srv.%s", srvtype);
	err = meta2_backend_get_properties(m2b, url, M2V2_FLAG_NODELETED, cb, &args);
	g_free(args.key);
	args.key = NULL;

	if (err != NULL) {
		if (args.result) {
			cleanup(args.result);
			args.result = NULL;
		}
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	reply->add_body(addr_info_marshall_gba(args.result, NULL));
	reply->send_reply(200, "OK");
	cleanup(args.result);
	return FILTER_OK;
}

static GError *
_list_all_services(struct meta2_backend_s *m2b, struct hc_url_s *url,
		const gchar *srvtype, GSList **result)
{
	void cb(gpointer u, gpointer bean) {
		GSList **pl = u;
		GByteArray *val = PROPERTIES_get_value(bean);
		if (val && val->len) {
			addr_info_t ai;
			g_byte_array_append(val, (guint8*)"", 1);
			if (l4_address_init_with_url(&ai, (gchar*) val->data, NULL))
				*pl = g_slist_prepend(*pl, g_memdup(&ai, sizeof(ai)));
		}
		_bean_clean(bean);
	}

	TRACE_FILTER();
	gchar *k = g_strdup_printf("sys.srv.%s", srvtype);
	GError *err = meta2_backend_get_all_properties(m2b, url, k, 0, cb, result);
	g_free(k);

	return err;
}

int
meta2_filter_action_list_all_content_services(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *srvtype = meta2_filter_ctx_get_param(ctx, "SRVTYPE");

	TRACE_FILTER();
	GSList *result = NULL;
	int rc;

	if (NULL != (err = _list_all_services(m2b, url, srvtype, &result))) {
		meta2_filter_ctx_set_error(ctx, err);
		rc = FILTER_KO;
	}
	else {
		reply->add_body(addr_info_marshall_gba(result, NULL));
		reply->send_reply(200, "OK");
		rc = FILTER_OK;
	}

	g_slist_foreach(result, addr_info_gclean, NULL);
	g_slist_free(result);
	return rc;
}

int
meta2_filter_action_del_content_services(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *srvtype = meta2_filter_ctx_get_param(ctx, "SRVTYPE");
	GSList *paths = meta2_filter_ctx_get_input_udata(ctx);
	GSList *result = NULL;

	TRACE_FILTER();

	/* first delete the properties */
	gchar k[LIMIT_LENGTH_SRVTYPE + sizeof("sys.srv.%s")];
	g_snprintf(k, sizeof(k), "sys.srv.%s", srvtype);
	GSList *l;
	for (l=paths; l ;l=l->next) {
		if (!l->data)
			continue;
		hc_url_set(url, HCURL_PATH, (gchar*)l->data);
		err = meta2_backend_del_property(m2b, url, k);
		if (err != NULL) {
			meta2_filter_ctx_set_error(ctx, err);
			return FILTER_KO;
		}
	}

	/* Now list the properties and return them in a header */
	int rc;
	if (NULL != (err = _list_all_services(m2b, url, srvtype, &result))) {
		meta2_filter_ctx_set_error(ctx, err);
		rc = FILTER_KO;
	}
	else {
		reply->add_header("result", addr_info_marshall_gba(result, NULL));
		reply->add_body(strings_marshall_gba(paths, NULL));
		reply->send_reply(200, "OK");
		rc = FILTER_OK;
	}

	g_slist_foreach(result, addr_info_gclean, NULL);
	g_slist_free(result);
	return rc;
}

int
meta2_filter_action_flush_content_services(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const gchar *srvtype = meta2_filter_ctx_get_param(ctx, "SRVTYPE");
	GError *err = NULL;

	gchar *k = g_strdup_printf("sys.srv.%s", srvtype);
	err = meta2_backend_flush_property(m2b, url, k);
	g_free(k);

	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	else {
		reply->add_body(addr_info_marshall_gba(NULL, NULL));
		reply->send_reply(200, "0K");
		return FILTER_OK;
	}
}

int
meta2_filter_action_replicate_content_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_raw_content_v2_s *v2 = meta2_filter_ctx_get_input_udata(ctx);
	GSList *beans;

	g_assert(m2b != NULL);
	g_assert(url != NULL);
	g_assert(v2 != NULL);

	/* complete the URL portions */
	gchar hexid[STRLEN_CONTAINERID+1];
	container_id_to_string(v2->header.container_id, hexid, sizeof(hexid));
	hc_url_set(url, HCURL_HEXID, hexid);
	hc_url_set(url, HCURL_PATH, v2->header.path);

	beans = m2v2_beans_from_raw_content_v2(hc_url_get(url, HCURL_HEXID), v2);
	if (!beans) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(500, "Beans conversion error"));
		return FILTER_KO;
	}

	GError *err = meta2_backend_force_alias(m2b, url, beans);
	_bean_cleanl2(beans);

	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	else {
		reply->send_reply(200, "OK");
		return FILTER_OK;
	}
}

int
meta2_filter_action_statv2_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_raw_content_v2_s *v2 = NULL;
	GError *e = NULL;
	GSList *beans = NULL;

	void _cb(gpointer u, gpointer bean) {
		(void) u;
		beans = g_slist_prepend(beans, bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _cb, NULL);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if(!beans) {
		GRID_DEBUG("No beans returned by get_alias for: %s",
				hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_CONTENT_NOTFOUND,
				"Content not found (deleted) (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	v2 = raw_content_v2_from_m2v2_beans(hc_url_get_id(url), beans);
	_bean_cleanl2(beans);

	if (!v2) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(500, "Conversion failure"));
		return FILTER_KO;
	}

	GSList singleton = {NULL, NULL};
	singleton.data = v2;
	reply->add_body(meta2_raw_content_v2_marshall_gba(&singleton, NULL));
	reply->send_reply(200, "OK");
	meta2_raw_content_v2_clean(v2);

	return FILTER_OK;
}

static GError *
_spare_special(struct gridd_reply_ctx_s *reply, struct meta2_backend_s *m2b,
		struct hc_url_s *url, GSList **result, gboolean answer_beans)
{
		gint64 nb = 1;
		gint64 dist = 1;
		GError *e = NULL;
		char broken[1024];
		char notin[1024];
		memset(broken, '\0', 1024);
		memset(notin, '\0', 1024);
		if(NULL != (e = message_extract_strint64(reply->request, "COUNT", &nb)) || 0 == nb) {
			g_clear_error(&e);
			nb = 1;
		}
		if(NULL != (e = message_extract_strint64(reply->request, "DISTANCE", &dist)) || 0 == dist) {
			g_clear_error(&e);
			dist = 1;
		}
		if(NULL != (e = message_extract_string(reply->request, "BROKEN", broken, 1024))) {
			g_clear_error(&e);
			broken[0] = '\0';
		}
		if(NULL != (e = message_extract_string(reply->request, "NOT-IN", notin, 1024))) {
			g_clear_error(&e);
			notin[0] = '\0';
		}

		return meta2_backend_get_conditionned_spare_chunks(
				m2b, url, nb, dist, notin, broken, result, answer_beans);
}

int
meta2_filter_action_get_spare_chunks(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	/*
	 * CDE : This method returns spare chunks according to the following header rules:
	 *	Headers:
	 *		(PRIOR)
	 *			-------------------------------------------------------
	 *			StoragePolicy : STR (Take in account if present):
	 *
	 *			Returns X chunks requires to upload 1 META-chunks to a position
	 *			(e.g: 2 chunks for a data-security: DUP:nb-copy=2|distance=1
	 *			and 6 chunks for a data-security: RAIN:k=4|m=2|distance=1)
	 *			-------------------------------------------------------
	 *		OR
	 *			-------------------------------------------------------
	 *			Count : INT
	 *			Not-in : STR (location exclusion list, you're sure that
	 *					returned chunks cannot be on these RAW-X services)
	 *			Broken : STR (brokens RAW-X, you're sure that
	 *					returned chunks cannot be on these RAW-X services)
	 *			Distance : Wanted distance between service (distance will be applied
	 *					to Not-in list)
	 *			-------------------------------------------------------
	 */

	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *polname = meta2_filter_ctx_get_param(ctx, M2_KEY_STORAGE_POLICY);
	GSList *cil = NULL;

	if (NULL != polname) {
		e = meta2_backend_get_spare_chunks(m2b, url, polname, &cil, FALSE);
		if (e != NULL) {
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	} else {
		if (NULL != (e = _spare_special(reply, m2b, url, &cil, FALSE))) {
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
	}

	_reply_chunk_info_list(ctx, reply, cil, NULL);

	g_slist_foreach(cil, chunk_info_gclean, NULL);
	g_slist_free(cil);

	return FILTER_OK;
}

