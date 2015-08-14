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
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <core/hc_url_ext.h>

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

struct all_vers_cb_args
{
	const gchar *contentid;
	gconstpointer udata_in;
	gpointer udata_out;
};

// Defines a callback to be called for all versions of a given content.
typedef GError* (*all_vers_cb) (struct meta2_backend_s *m2b,
		struct meta2_raw_content_s *content,
		struct hc_url_s *url,
		struct all_vers_cb_args *cbargs);

static void
_notify_beans (struct meta2_backend_s *m2b, struct hc_url_s *url,
		GSList *beans, const char *name)
{
	void sep (GString *gs) {
		if (gs->len > 1 && !strchr(",[{", gs->str[gs->len-1]))
			g_string_append_c (gs, ',');
	}
	void append_int64 (GString *gs, const char *k, gint64 v) {
		sep (gs);
		g_string_append_printf (gs, "\"%s\":%"G_GINT64_FORMAT, k, v);
	}
	void append_const (GString *gs, const char *k, const char *v) {
		sep (gs);
		if (v)
			g_string_append_printf (gs, "\"%s\":\"%s\"", k, v);
		else
			g_string_append_printf (gs, "\"%s\":null", k);
	}
	void append (GString *gs, const char *k, gchar *v) {
		append_const (gs, k, v);
		g_free0 (v);
	}

	if (!m2b->notify.hook)
		return;

	GString *gs = g_string_new ("{");
	g_string_append_printf (gs, "\"event\":\"%s.%s\"", NAME_SRVTYPE_META2, name);
	append_int64 (gs, "when", g_get_real_time());
	g_string_append (gs, ",\"url\":{");
	hc_url_to_json (gs, url);
	g_string_append (gs, "},\"data\":[");
	meta2_json_dump_all_xbeans (gs, beans);
	g_string_append (gs, "]}");
	m2b->notify.hook (m2b->notify.udata, g_string_free (gs, FALSE));
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
		reply->send_reply(CODE_PARTIAL_CONTENT, "Partial content");
	}
	if (NULL != mdsys) {
		reply->add_header(NAME_MSGKEY_MDSYS, g_byte_array_append(g_byte_array_new(),
				(const guint8*)mdsys, strlen(mdsys)));
	}
	reply->send_reply(CODE_FINAL_OK, "OK");

	gslist_chunks_destroy(list_of_lists, NULL);

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
			if(FILTER_KO == _reply_raw_content(ctx, reply, rc,
					CODE_PARTIAL_CONTENT, "partial content")) {
				rc->raw_chunks = original_chunks;
				gslist_chunks_destroy(list_of_lists, NULL);
				return FILTER_KO;
			}
		} else {
			if(FILTER_KO ==  _reply_raw_content(ctx, reply, rc, CODE_FINAL_OK, "OK")) {
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
		beans = g_slist_prepend(beans, bean);
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

	if (!rc->raw_chunks) {
		status = _reply_raw_content(ctx, reply, rc, CODE_FINAL_OK, "OK");
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
	gint rc = FILTER_OK;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	GSList *added = NULL, *deleted = NULL;

	GRID_DEBUG("Putting %d beans in [%s]%s", g_slist_length(beans),
			hc_url_get(url, HCURL_WHOLE),
			meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)?
			" (overwrite)":"");

	if (NULL != meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_OVERWRITE)) {
		e = meta2_backend_force_alias(m2b, url, beans, &deleted, &added);
	} else {
		e = meta2_backend_put_alias(m2b, url, beans, &deleted, &added);
	}

	if (NULL != e) {
		GRID_DEBUG("Fail to put alias (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		rc = FILTER_KO;
	} else {
		_notify_beans (m2b, url, added, "content.new");
		if (deleted)
			_notify_beans (m2b, url, deleted, "content.deleted");
		_on_bean_ctx_send_list(obc, TRUE);
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
		e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NOPROPS,
				_bean_list_cb, &obc->l);
		if (!e)
			_on_bean_ctx_send_list(obc, TRUE);
		_on_bean_ctx_clean(obc);
	}

	return FILTER_OK;
}

int
meta2_filter_action_put_content(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	const char *copy_source = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_COPY);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (NULL != copy_source) {
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

	e = meta2_backend_append_to_alias(m2b, url, beans, _bean_list_cb, &obc->l);
	if(NULL != e) {
		GRID_DEBUG("Fail to append to alias (%s)", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_notify_beans (m2b, url, obc->l, "content.append");
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
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	TRACE_FILTER();

	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr)
		flags = atoi(fstr);

	e = meta2_backend_get_alias(m2b, url, flags, _bean_list_cb, &obc->l);
	if (NULL != e) {
		GRID_DEBUG("Fail to return alias for url: %s", hc_url_get(
					url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		goto cleanup;
	}

	_on_bean_ctx_send_list(obc, TRUE);
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
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	TRACE_FILTER();
	e = meta2_backend_delete_alias(m2b, url, _bean_list_cb, &obc->l);
	if (NULL != e) {
		GRID_DEBUG("Fail to delete alias for url: %s", hc_url_get(url, HCURL_WHOLE));
		meta2_filter_ctx_set_error(ctx, e);
		_on_bean_ctx_clean(obc);
		return FILTER_KO;
	}

	_notify_beans(m2b, url, obc->l, "content.deleted");
	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_set_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GSList *beans = meta2_filter_ctx_get_input_udata(ctx);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	guint32 flags = 0;
	const char *fstr = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_FLAGS);
	if (NULL != fstr)
		flags = atoi(fstr);
	
	if (!hc_url_has(url, HCURL_PATH))
		e = NEWERROR(CODE_BAD_REQUEST, "Missing content path");
	else
		e = meta2_backend_set_properties(m2b, url, BOOL(flags&M2V2_FLAG_FLUSH),
				beans, _bean_list_cb, &obc->l);

	if (NULL != e) {
		GRID_DEBUG("Failed to set properties to [%s] : (%d) %s",
				hc_url_get(url, HCURL_WHOLE), e->code, e->message);
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_get_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);

	TRACE_FILTER();

	e = meta2_backend_get_properties(m2b, url, _bean_list_cb, &obc->l);
	if (NULL != e) {
		_on_bean_ctx_clean(obc);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	_on_bean_ctx_send_list(obc, TRUE);
	_on_bean_ctx_clean(obc);
	return FILTER_OK;
}

int
meta2_filter_action_del_content_properties(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	GError *e = NULL;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	GSList *namel = meta2_filter_ctx_get_input_udata(ctx);

	TRACE_FILTER();

	gchar **namev = (gchar**) metautils_list_to_array (namel);
	e = meta2_backend_del_properties(m2b, url, namev);
	g_strfreev(namev);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

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
	const char *mdsys = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_VALUE);

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
		e = storage_policy_check_compat_by_name(&(m2b->backend.ns_info),
				old_sp, sp);
		if (e == NULL)
			CONTENTS_HEADERS_set2_policy(header, sp);
		g_free(sp);
	}

	beans = g_slist_prepend(g_slist_prepend(beans, header), alias);
	if (e == NULL) {
		// skip checks only when changing stgpol
		e = meta2_backend_update_alias_header(m2b, url, beans);
	}
	_bean_cleanl2(beans);

	if (NULL != e) {
		GRID_DEBUG("Failed to update alias/headers: %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

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
	const char *policy_str = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);
	const char *mdsys = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MDSYS);
	const char *spare_type = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_SPARE);
	gboolean append = (NULL != meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_APPEND));

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
				mdsys, NULL, _bean_list_cb, &obc->l);
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
	const char *mdsys = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_MDSYS);

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
	GSList *beans = NULL, *added = NULL, *deleted = NULL;

	/* Map the raw content into beans */
	if (pos_pfx) {
		char* _make_subpos(guint32 pos, void *udata) {
			char *prefix = udata;
			return g_strdup_printf("%s%u", prefix, pos);
		}
		beans = m2v2_beans_from_raw_content_custom(cid, content,
				_make_subpos, (void*) pos_pfx);
	} else {
		beans = m2v2_beans_from_raw_content(cid, content);
	}

	/* force the alias beans to be saved */
	err = meta2_backend_force_alias(m2b, url, beans, &deleted, &added);
	_notify_beans (m2b, url, added, "content.new");
	if (deleted)
		_notify_beans (m2b, url, deleted, "content.del");
	_bean_cleanl2(added);
	_bean_cleanl2(deleted);
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
			(void) chunk_id_to_string(&(chunk->id), strid, sizeof(strid));
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

	err = meta2_backend_get_alias_version(m2b, url, &maxvers);
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
				hc_url_get(url, HCURL_WHOLE), err->message);
		g_clear_error(&err);
		return FALSE;
	}
	//  0 -> versioning disabled
	// -1 -> unlimited
	// >0 -> number of versions
	return maxvers != 0;
}

static int
_update_beans(struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply,
		all_vers_cb cb, struct all_vers_cb_args *cbargs)
{
	GError *err = NULL;
	gchar strcid[STRLEN_CONTAINERID];
	struct hc_url_s *url = hc_url_empty();
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct meta2_raw_content_s *content = meta2_filter_ctx_get_input_udata(ctx);
	container_id_to_string(content->container_id, strcid, sizeof(strcid));

	/* fill url */
	hc_url_set(url, HCURL_NS, m2b->backend.ns_name);
	hc_url_set(url, HCURL_HEXID, strcid);
	hc_url_set(url, HCURL_PATH, content->path);
	hc_url_clean(meta2_filter_ctx_get_url(ctx));
	meta2_filter_ctx_set_url(ctx, url);

	if (_has_versioning(m2b, url)) {
		err = _call_for_all_versions(m2b, content, url, cb, cbargs);
	} else {
		_update_url_version_from_content(content, url);
		err = cb(m2b, content, url, cbargs);
	}

	if (!err) {
		struct on_bean_ctx_s *obc = _on_bean_ctx_init(ctx, reply);
		err = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED,
				_bean_list_cb, &obc->l);
		_on_bean_ctx_append_udata_list(obc);
		_on_bean_ctx_clean(obc);
	}

	if (NULL != err) {
		GRID_DEBUG("Failed to update beans: %s", err->message);
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_action_add_raw_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	const char *position_prefix = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_POSITIONPREFIX);
	gchar content_id[64];
	memset(content_id, 0, sizeof(content_id));
	SHA256_randomized_string(content_id, sizeof(content_id));

	struct all_vers_cb_args cbargs = {
			.contentid = content_id,
			.udata_in = position_prefix,
			.udata_out = NULL
	};

	return _update_beans(ctx, reply, _add_beans_cb, &cbargs);
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
	TRACE_FILTER();
	return _update_beans(ctx, reply, _delete_beans_cb, NULL);
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
		if(NULL != (e = metautils_message_extract_strint64(reply->request, NAME_MSGKEY_COUNT, &nb)) || 0 == nb) {
			g_clear_error(&e);
			nb = 1;
		}
		if(NULL != (e = metautils_message_extract_strint64(reply->request, NAME_MSGKEY_DISTANCE, &dist)) || 0 == dist) {
			g_clear_error(&e);
			dist = 1;
		}
		if(NULL != (e = metautils_message_extract_string(reply->request, NAME_MSGKEY_BROKEN, broken, 1024))) {
			g_clear_error(&e);
			broken[0] = '\0';
		}
		if(NULL != (e = metautils_message_extract_string(reply->request, NAME_MSGKEY_NOTIN, notin, 1024))) {
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
	const char *polname = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);
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

