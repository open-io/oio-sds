/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include <hc_url.h>

#include <glib.h>

#include <transport_gridd.h>

#include "../server/gridd_dispatcher_filters.h"
#include "../cluster/events/gridcluster_events.h"
#include "../cluster/lib/gridcluster.h"

#include "./meta2_macros.h"
#include "./meta2_filter_context.h"
#include "./meta2_filters.h"
#include "./meta2_backend_internals.h"
#include "./meta2_bean.h"
#include "./meta2v2_remote.h"
#include "./generic.h"
#include "./autogen.h"

#define TRACE_FILTER() GRID_TRACE2("%s", __FUNCTION__)

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
	GString *str= _bean_debug(NULL, bean);
	GRID_TRACE("Bean got : %s", str->str);
	g_string_free(str, TRUE);
	if(ctx && ctx->l && g_slist_length(ctx->l) >= 32) {
		_on_bean_ctx_send_list(ctx, FALSE);
	}
	ctx->l = g_slist_prepend(ctx->l, bean);
}

static int
_reply_chunk_info_list(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		GSList *cil, const char *mdsys)
{

	(void) mdsys;
	GSList *list_of_lists = NULL, *cursor = NULL;
	GError *e = NULL;
        list_of_lists = gslist_split(cil, 32);
        for (cursor = list_of_lists; cursor; cursor = cursor->next) {
                void *buf = NULL;
                gsize bufsize = 0;
                GSList *l = NULL;
                l = (GSList *) cursor->data;
		if (!chunk_info_marshall(l, &buf, &bufsize, &e)) {
			GRID_DEBUG("Failed to marshall chunk info list");
			meta2_filter_ctx_set_error(ctx, e);
			gslist_chunks_destroy(list_of_lists, NULL);
			return FILTER_KO;
		}
		GByteArray *body = g_byte_array_new();
		g_byte_array_append(body, buf, bufsize);
		reply->add_body(body);
		reply->send_reply(206, "Partial content");
        }
	/* TODO: mdsys */
	reply->send_reply(200, "OK");

        gslist_chunks_destroy(list_of_lists, NULL);

        return FILTER_OK;
}

int
meta2_filter_action_retrieve_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	auto void _cb(gpointer u, gpointer bean);
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
		GRID_DEBUG("No beans returned by get_alias for: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(420, "Content not found (deleted) (%s)",
				hc_url_get(url, HCURL_WHOLE)));
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
	auto void _cb(gpointer u, gpointer bean);
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

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}
	if(!beans) {
		GRID_DEBUG("No beans returned by get_alias for: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(420, "Content not found (deleted) (%s)",
				hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

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

int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);

	GRID_DEBUG("Putting %d beans", g_slist_length(beans));
	e = meta2_backend_put_alias(m2b, url, beans, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Fail to put alias (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
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
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
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
	GError *e = NULL;
	guint32 flags = 0;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
		flags = g_ntohl(flags);
	}

	e = meta2_backend_get_alias(m2b, url, flags, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_delete_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);

	TRACE_FILTER();
	e = meta2_backend_delete_alias(m2b, url, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Fail to delete alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

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
		GRID_DEBUG("Cannot validate properties, cannot found informations in m2b_transient about it!");
		meta2_filter_ctx_set_error(ctx, NEWERROR(400, "Cannot found any information"
				" about properties to validate (%s)", hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}

	GString *tmp = NULL;
	GSList *l = NULL;
	for(l=ci->beans; l && l->data; l=l->next){
		tmp = _bean_debug(tmp, l->data);
	}
	g_string_free(tmp, TRUE);

	obc = _on_bean_ctx_init(reply);
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
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
	e = meta2_backend_set_properties(m2b, url, beans, _get_cb, obc);
	if(NULL != e) {
		GRID_DEBUG("Failed to set properties to (%s)", hc_url_get(url, HCURL_WHOLE));
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
	int flags = 0;

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
	}

	switch(flags) {
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
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
	const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);

	TRACE_FILTER();
	if (NULL != fstr) {
		flags = atoi(fstr);
		flags = g_htonl(flags);
	}

	e = meta2_backend_get_properties(m2b, url, flags, _get_cb, obc);
	if(NULL != e) {
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
	auto void _cb(gpointer, gpointer);
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
	auto void _get_alias_header_cb(gpointer udata, gpointer bean);

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
		else
			_bean_clean(bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _get_alias_header_cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	} 

	char *sp = storage_policy_from_mdsys_str(mdsys);
	ALIASES_set2_mdsys(alias, mdsys);
	if(NULL != sp) {
		CONTENTS_HEADERS_set2_policy(header, sp);
		g_free(sp);
	}

	beans = g_slist_prepend(g_slist_prepend(beans, header), alias);
	e = meta2_backend_update_alias_header(m2b, url, beans);
	_bean_cleanl2(beans);

	if(NULL != e) {
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

	auto void _cb(gpointer, gpointer);

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
/*        (void) reply;
        GError *e = NULL;
        guint32 flags = 0;
        struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
        struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
        struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
        const char *fstr = meta2_filter_ctx_get_param(ctx, M2_KEY_GET_FLAGS);

        TRACE_FILTER();
        if (NULL != fstr) {
                flags = atoi(fstr);
                flags = g_htonl(flags);
        }

        e = meta2_backend_get_properties(m2b, url, flags, _get_cb, obc);
        if(NULL != e) {
                GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
                _on_bean_ctx_clean(obc);
                meta2_filter_ctx_set_error(ctx, e);
                return FILTER_KO;
        }



        _on_bean_ctx_send_list(obc, TRUE);
        _on_bean_ctx_clean(obc);

        return FILTER_OK;
*/



	auto void _cb(gpointer, gpointer);
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

	//e = meta2_backend_get_properties(m2b, url, flags, _cb, NULL);
	e = meta2_backend_get_property(m2b, url, prop_key, flags, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to return alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

/*
	GSList* l = NULL;
        GSList* prop_beans = NULL;
	for(l=beans; l ; l = l->next) {
                if (!l->data)
                        continue;
                if (DESCR(l->data) == &descr_struct_PROPERTIES)
                        prop_beans = g_slist_prepend(prop_beans, l->data);
        }
*/
/*{
	("GLA: List all beans/properties");
	GSList* m = NULL;
	for (m=beans; m ;m=m->next) {
		GString *s = _bean_debug(NULL, m->data);
		GRID_INFO("GLA: Properties %s", s->str);
		g_string_free(s, TRUE);
	}
}*/

        //reply->add_body(bean_sequence_marshall(beans));


	reply->add_header("field_3", bean_sequence_marshall(beans));
	reply->send_reply(200, "OK");
	_bean_cleanl2(beans);

	return FILTER_OK;
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
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(reply);
	const char *size_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CONTENTLENGTH);
	const char *policy_str = meta2_filter_ctx_get_param(ctx, M2_KEY_STORAGE_POLICY);
	gboolean append = (NULL != meta2_filter_ctx_get_param(ctx, "APPEND"));

	TRACE_FILTER();
	if (NULL != size_str)
		size = g_ascii_strtoll(size_str, NULL, 10);

	e = meta2_backend_generate_beans(m2b, url, size, policy_str, append, _get_cb, obc);
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

	static int
_generate_chunks(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		gboolean append)
{
	GError *e = NULL;
	gint64 size = 0;
	GSList *beans = NULL, *cil = NULL, *list_of_lists = NULL, *cursor = NULL;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *size_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_CONTENTLENGTH);
	const char *mdsys = meta2_filter_ctx_get_param(ctx, M2V1_KEY_METADATA_SYS);
	const char *mdusr = meta2_filter_ctx_get_param(ctx, M2V1_KEY_METADATA_USR);

	char *out_mdsys = NULL;

	GRID_TRACE2("mdsys extracted from request : %s", mdsys);

	auto void _cb(gpointer u, gpointer bean);

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

	list_of_lists = gslist_split(cil, 32);

	for (cursor = list_of_lists; cursor && cursor->data; cursor = cursor->next) {
		void *buf = NULL;
		gsize bufsize = 0;
		GSList *l = NULL;
		l = (GSList *) cursor->data;
		if (!chunk_info_marshall(l, &buf, &bufsize, &e)) {
			GRID_DEBUG("Failed to marshall chunk info list");
			meta2_filter_ctx_set_error(ctx, e);
			return FILTER_KO;
		}
		GByteArray *gba = g_byte_array_new();
		g_byte_array_append(gba, buf, bufsize);
		reply->add_body(gba);
		reply->send_reply(206, "Partial content");
		if(NULL != buf) {
			g_free(buf);
		}
	}

	/* TODO : send mdsys */

	reply->send_reply(200, "OK");

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

	static void
_search_and_replace_md5(gpointer chunk, GSList *in_place)
{
	for(; in_place ; in_place=in_place->next) {
		if(!in_place->data)
			continue;
		GString *str = _bean_debug(NULL, in_place->data);
		g_string_free(str, TRUE);
		if(DESCR(in_place->data) == &descr_struct_CHUNKS) {
			if(0 == g_ascii_strcasecmp(CHUNKS_get_id(in_place->data)->str, CHUNKS_get_id(chunk)->str)) { 
				GByteArray *gba = CHUNKS_get_hash(chunk);
				CHUNKS_set2_hash(in_place->data, gba->data, gba->len);
				/* our chunk, change its md5 */
				break;
			}
		}
	}

}

static void
_update_in_place_chunk_md5(GSList *in_place, GSList *tmp)
{
	for(; tmp ; tmp = tmp->next) {
		if(!tmp->data)
			continue;
		GString *str = _bean_debug(NULL, tmp->data);
		g_string_free(str, TRUE);
		if(DESCR(tmp->data) == &descr_struct_CHUNKS) {
			_search_and_replace_md5(tmp->data, in_place);
		}
	}
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
	GSList *tmp = m2v2_beans_from_chunk_info_list("1",
			hc_url_get(url, HCURL_PATH), cil);
	_update_in_place_chunk_md5(ci->beans, tmp);
	_bean_cleanl2(tmp);
	return FILTER_OK;
}

	int
meta2_filter_action_add_raw_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	struct hc_url_s *url = hc_url_empty();
	struct meta2_backend_s *m2b;
	struct meta2_raw_content_s *content;

	(void) reply;
	TRACE_FILTER();
	m2b = meta2_filter_ctx_get_backend(ctx);
	content = meta2_filter_ctx_get_input_udata(ctx);

	/* Map the raw content into beans */
	gchar content_id[64];
	memset(content_id, 0, sizeof(content_id));
	SHA256_randomized_string(content_id, sizeof(content_id));

	GSList *beans = m2v2_beans_from_raw_content(content_id, content);
	char hexid[65];
	memset(hexid, '\0', 65);
	buffer2str(content->container_id, sizeof(container_id_t), hexid, 65);

	/* fill url */
	hc_url_set(url, HCURL_NS, m2b->ns_name);
	hc_url_set(url, HCURL_HEXID, hexid);
	hc_url_set(url, HCURL_PATH, content->path);

	/* force the alias beans to be saved */
	err = meta2_backend_force_alias(m2b, url, beans);
	_bean_cleanl2(beans);

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
	auto gboolean _chunk_to_drop(GSList *l, gpointer chunk);
	auto gboolean _content_to_drop(GSList *l, gpointer content);

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

	int
meta2_filter_action_remove_raw_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	auto void _cb(gpointer udata, gpointer bean);

	GError *e = NULL;
	gchar strcid[STRLEN_CONTAINERID];
	GSList *in_place = NULL;
	GSList *beans = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct meta2_raw_content_s *content = meta2_filter_ctx_get_input_udata(ctx);
	container_id_to_string(content->container_id, strcid, sizeof(strcid));

	TRACE_FILTER();

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, m2b->ns_name);
	hc_url_set(url, HCURL_HEXID, strcid);
	hc_url_set(url, HCURL_PATH, content->path);

	void _cb(gpointer udata, gpointer bean) {
		(void) udata;
		in_place = g_slist_prepend(in_place, bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	} 

	GSList *to_drop = m2v2_beans_from_raw_content("1", content);
	/* remove chunks & contents */
	beans = _merge_beans(in_place, to_drop); 

	e = meta2_backend_delete_chunks(m2b, url, beans);
	hc_url_clean(url);
	_bean_cleanl2(in_place);
	_bean_cleanl2(to_drop);
	_bean_cleanl2(beans);

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

	auto void _cb(gpointer udata, gpointer bean);

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
		GRID_DEBUG("Cannot commit content, cannot found informations in m2b_transient about it!");
		meta2_filter_ctx_set_error(ctx, NEWERROR(400, "Cannot found any information"
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
			e = meta2_backend_delete_alias(m2b, url, _cb, NULL);
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

	auto void cb(gpointer u, gpointer bean);
	auto void cleanup(gpointer p);

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
	auto void cb(gpointer u, gpointer bean);

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

	beans = m2v2_beans_from_raw_content_v2(hc_url_get_id(url), v2);
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

	auto void _cb(gpointer u, gpointer bean);

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
		GRID_DEBUG("No beans returned by get_alias for: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, NEWERROR(420, "Content not found (deleted) (%s)",
				hc_url_get(url, HCURL_WHOLE)));
		return FILTER_KO;
	}



/*{
	GRID_INFO("List all beans/properties");
	GSList* m = NULL;

        for (m=beans; m ;m=m->next) {
                GString *s = _bean_debug(NULL, m->data);
                GRID_INFO("Properties %s", s->str);
                g_string_free(s, TRUE);
        }
} */

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

