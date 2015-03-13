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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

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

#define EXTRACT_STRING2(FieldName,VarName,Opt) do { \
	e = message_extract_string(reply->request, FieldName, buf, sizeof(buf)); \
	if(NULL != e) { \
		if(!Opt) { \
			meta2_filter_ctx_set_error(ctx, e); \
			return FILTER_KO; \
		} else { \
			g_clear_error(&e); \
			return FILTER_OK; \
		} \
	} \
	meta2_filter_ctx_add_param(ctx, VarName, buf); \
} while (0)

#define EXTRACT_STRING(Name, Opt) EXTRACT_STRING2(Name,Name,Opt)

#define EXTRACT_OPT(Name) do { \
	memset(buf, 0, sizeof(buf)); \
	e = message_extract_string(reply->request, Name, buf, sizeof(buf)); \
	if (NULL != e) { \
		g_clear_error(&e); \
	} else { \
		meta2_filter_ctx_add_param(ctx, Name, buf); \
	} \
} while (0)

#define EXTRACT_HEADER_BEANS(FieldName,Variable) do {\
	GError *err = message_extract_header_encoded(reply->request, FieldName, TRUE, &Variable, bean_sequence_decoder);\
	if (err) { \
		meta2_filter_ctx_set_error(ctx, err);\
		return FILTER_KO;\
	} \
} while(0)

int
meta2_filter_extract_header_ns(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	gchar ns[LIMIT_LENGTH_NSNAME];
	struct hc_url_s *url;

	TRACE_FILTER();
	err = message_extract_string(reply->request, NAME_MSGKEY_NAMESPACE,
			ns, sizeof(ns));
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}
	hc_url_set(url, HCURL_NS, ns);
	return FILTER_OK;
}

int
meta2_filter_extract_header_url(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	struct hc_url_s *url = NULL;
	char buf[LIMIT_LENGTH_HCURL];
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];
	const gchar *container, *path;

	TRACE_FILTER();
	e = message_extract_string(reply->request, M2_KEY_URL, buf, sizeof(buf));
	if(NULL != e) {
		GRID_DEBUG("Failed to get url field from input message");
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	GRID_DEBUG("URL from header: %s", buf);

	if(!(url = hc_url_init(buf))) {
		GRID_DEBUG("Failed to init url from message field (%s)", buf);
		e = NEWERROR(CODE_BAD_REQUEST, "Bad HC url format [%s]", buf);
	} else if (strlen(hc_url_get(url, HCURL_NS)) > LIMIT_LENGTH_NSNAME) {
		e = NEWERROR(CODE_BAD_REQUEST, "namespace name is too long");
	}

	container = hc_url_get(url, HCURL_REFERENCE);
	path = hc_url_get(url, HCURL_PATH);
	if (container && strlen(container) > LIMIT_LENGTH_CONTAINERNAME) {
		e = NEWERROR(CODE_BAD_REQUEST, "container name is too long");
	} else if (path && strlen(path) > LIMIT_LENGTH_CONTENTPATH) {
		e = NEWERROR(CODE_BAD_REQUEST, "content path is too long");
	}

	if (e != NULL) {
		meta2_filter_ctx_set_error(ctx, e);
		hc_url_clean(url);
		return FILTER_KO;
	}

	e = message_extract_cid(reply->request, "CONTAINER_ID", &cid);
	if (NULL != e) {
		g_clear_error(&e);
		if (metautils_str_ishexa(container, STRLEN_CONTAINERID-1)) {
			GRID_DEBUG("Refname in url looks like container id, "
					"and no container id specified in header");
			g_strlcpy(strcid, container, sizeof(strcid));
			hc_url_set(url, HCURL_HEXID, strcid);
		} else {
			GRID_DEBUG("No container id, continue with the base url");
		}
		GRID_DEBUG("Initialized url = %s", hc_url_get(url, HCURL_WHOLE));
	} else {
		container_id_to_string(cid, strcid, sizeof(strcid));
		if (0 != g_ascii_strcasecmp(strcid, hc_url_get(url, HCURL_HEXID))) {
			GRID_DEBUG("Container hexid != url hexid, replace it");
			hc_url_set(url, HCURL_HEXID, strcid);
		}
	}

	GRID_DEBUG("Initialized url = %s", hc_url_get(url, HCURL_WHOLE));
	meta2_filter_ctx_set_url(ctx, url);

	return FILTER_OK;
}

int
meta2_filter_extract_header_copy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[512];

	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_COPY_SOURCE, TRUE);
	if(NULL != meta2_filter_ctx_get_param(ctx, M2_KEY_COPY_SOURCE)) {
		meta2_filter_ctx_add_param(ctx, "BODY_OPT", "OK");
	}
	return FILTER_OK;
}

int
meta2_filter_extract_header_vns(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[128];

	TRACE_FILTER();
	EXTRACT_STRING(M2V1_KEY_VIRTUAL_NAMESPACE, TRUE);
	return FILTER_OK;
}

static int
_meta2_filter_extract_cname(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, const gchar *fname)
{
	GError *e;
	gchar buf[1024];
	struct hc_url_s *url;

	EXTRACT_STRING(fname, 1);

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}

	hc_url_set(url, HCURL_REFERENCE, buf);

	return FILTER_OK;
}

int
meta2_filter_extract_header_cname(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_cname(ctx, reply, NAME_MSGKEY_CONTAINERNAME);
}

static int
_meta2_filter_extract_path(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, const gchar *fname)
{
	GError *e;
	gchar buf[1024];
	struct hc_url_s *url;

	EXTRACT_STRING(fname, 1);

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}

	hc_url_set(url, HCURL_PATH, buf);

	return FILTER_OK;
}

int
meta2_filter_extract_header_path_f2(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_path(ctx, reply, "field_2");
}

int
meta2_filter_extract_header_path_f1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_path(ctx, reply, "field_1");
}

static int
_meta2_filter_extract_cid(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, const gchar *fname)
{
	GError *err;
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];
	struct hc_url_s *url;

	err = message_extract_cid(reply->request, fname, &cid);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}
	container_id_to_string(cid, strcid, sizeof(strcid));
	hc_url_set(url, HCURL_HEXID, strcid);
	return FILTER_OK;
}

int
meta2_filter_extract_header_cid(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_cid(ctx, reply, NAME_MSGKEY_CONTAINERID);
}

int
meta2_filter_extract_header_cid_f0(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_cid(ctx, reply, "field_0");
}

int meta2_filter_extract_header_optional_cid(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	GError *err;
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];
	struct hc_url_s *url;

	err = message_extract_cid(reply->request, NAME_MSGKEY_CONTAINERID, &cid);
	if (err != NULL) {
		g_clear_error(&err);
		return FILTER_OK;
	}

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}
	container_id_to_string(cid, strcid, sizeof(strcid));
	hc_url_set(url, HCURL_HEXID, strcid);
	return FILTER_OK;
}

static int
_meta2_filter_extract_srvtype(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, const gchar *f)
{
	gchar srvtype[LIMIT_LENGTH_SRVTYPE];
	GError *err;

	memset(srvtype, 0, sizeof(srvtype));
	err = message_extract_string(reply->request, f, srvtype, sizeof(srvtype));
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	meta2_filter_ctx_add_param(ctx, "SRVTYPE", srvtype);
	return FILTER_OK;
}

int
meta2_filter_extract_header_srvtype_f1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_srvtype(ctx, reply, "field_1");
}

int
meta2_filter_extract_header_propname_f2(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[128];

	TRACE_FILTER();
	EXTRACT_STRING("field_2", FALSE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_propvalue_f3(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[128];

	TRACE_FILTER();
	EXTRACT_STRING("field_3", FALSE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_ref(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[128];

	TRACE_FILTER();
	EXTRACT_STRING(M2V1_KEY_CONTAINER_NAME, FALSE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_path(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[128];

	TRACE_FILTER();
	EXTRACT_STRING(M2V1_KEY_PATH, FALSE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_storage_policy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[65];

	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_STORAGE_POLICY, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_mdsys(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[1024];

	TRACE_FILTER();
	EXTRACT_STRING(M2V1_KEY_METADATA_SYS, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_mdusr(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[8192];

	TRACE_FILTER();
	EXTRACT_STRING(M2V1_KEY_METADATA_USER, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_version_policy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[65];

	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_VERSION_POLICY, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_body_strlist(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	void cleanup(gpointer p) {
		if (!p)
			return;
		g_slist_foreach((GSList*)p, g_free1, NULL);
		g_slist_free((GSList*)p);
	}
	GError *err;
	GSList *names = NULL;

	err = message_extract_body_encoded(reply->request, TRUE, &names, strings_unmarshall);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, names, cleanup);
	return FILTER_OK;
}

int
meta2_filter_extract_body_rawcontentv2(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	void cleanup(gpointer p) {
		if (!p)
			return;
		g_slist_foreach((GSList*)p, meta2_raw_content_v2_gclean, NULL);
		g_slist_free((GSList*)p);
	}
	GSList *result = NULL;
	GError *err;

	err = message_extract_body_encoded(reply->request, TRUE, &result,
		meta2_raw_content_v2_unmarshall);

	if (!err) {
		if (!result) {
			meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST, "No content"));
			return FILTER_KO;
		}
		else {
			meta2_filter_ctx_set_input_udata(ctx, result->data,
					(GDestroyNotify) meta2_raw_content_v2_clean);
			result->data = NULL;
			cleanup(result);
			return FILTER_OK;
		}
	}

	cleanup(result);
	return FILTER_KO;
}

int
meta2_filter_extract_body_rawcontentv1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	void *b = NULL;
	gsize blen = 0;
	struct hc_url_s *url = NULL;

	if (0 >= message_get_BODY(reply->request, &b, &blen, &err)) {
		if (!err)
			err = NEWERROR(CODE_BAD_REQUEST, "Missing Body");
		g_prefix_error(&err, "No content: ");
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (!b || blen<=0) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid body");
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	struct meta2_raw_content_s *content =
		meta2_maintenance_content_unmarshall_buffer(b, blen, &err);

	if (!content) {
		if (!err)
			err = NEWERROR(CODE_BAD_REQUEST, "unknown error");
		g_prefix_error(&err, "Decoding error: ");
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, content,
			(GDestroyNotify)meta2_maintenance_destroy_content);

	/* Defines a container id in context url if body raw content is the only
	 * information we have about the targeted container (the url is mandatory
	 * for potential has_container filter called later, so this action prevent
	 * from null url and ugly meta2 behaviour
	 */
	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}

	if(!hc_url_get(url, HCURL_HEXID)) {
		gchar strcid[STRLEN_CONTAINERID];
		container_id_to_string(content->container_id, strcid, sizeof(strcid));
		hc_url_set(url, HCURL_HEXID, strcid);
	}

	return FILTER_OK;
}

int
meta2_filter_extract_header_prop_action(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_STRING2("ACTION", "ACTION", 1);
	if(NULL != meta2_filter_ctx_get_param(ctx, "ACTION")) {
		meta2_filter_ctx_add_param(ctx, "BODY_OPT", "OK");
	}

	return FILTER_OK;
}

int
meta2_filter_extract_header_chunk_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	void _cleaner(gpointer ptr) {
		GSList **lists = ptr;
		_bean_cleanl2(lists[0]);
		_bean_cleanl2(lists[1]);
		// FIXME memleak with <lists> itself ?
	}
	GSList **lists = g_malloc0(2 * sizeof(GSList *));
	EXTRACT_HEADER_BEANS(M2_KEY_NEW_CHUNKS, lists[0]);
	EXTRACT_HEADER_BEANS(M2_KEY_OLD_CHUNKS, lists[1]);
	meta2_filter_ctx_set_input_udata(ctx, lists, _cleaner);
	return FILTER_OK;
}

int
meta2_filter_extract_body_beans(struct gridd_filter_ctx_s *ctx,
                struct gridd_reply_ctx_s *reply)
{
	GSList *l = NULL;
	const char *opt = meta2_filter_ctx_get_param(ctx, "BODY_OPT");

	TRACE_FILTER();

	/* get the message body */
	GError *err = message_extract_body_encoded (reply->request, (opt==NULL), &l, bean_sequence_decoder);
	if (err) {
		_bean_cleanl2 (l);
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST,
					"Invalid request, Empty / Invalid body"));
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, l, (GDestroyNotify)_bean_cleanl2);
	return FILTER_OK;
}

int
meta2_filter_extract_body_strings(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *l = NULL;
	const char *opt = meta2_filter_ctx_get_param(ctx, "BODY_OPT");

	TRACE_FILTER();

	GError *err = message_extract_body_encoded (reply->request, (opt==NULL), &l, strings_unmarshall);
	if (err) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST,
					"Invalid request, Empty / Invalid body"));
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, l, g_free0);
	return FILTER_OK;
}

static void
_ci_list_clean(gpointer cil)
{
	g_slist_free_full ((GSList*)cil, (GDestroyNotify)chunk_info_clean);
}

int
meta2_filter_extract_body_chunk_info(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList *l = NULL;

	TRACE_FILTER();

	GError *err = message_extract_body_encoded (reply->request, TRUE, &l, chunk_info_unmarshall);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, l, _ci_list_clean);
	return FILTER_OK;
}

int
meta2_filter_extract_header_string_K_f1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_STRING2("field_1", "K", 0);
	return FILTER_OK;
}

int
meta2_filter_extract_header_append(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_STRING2("APPEND", "APPEND", 1);
	return FILTER_OK;
}

int
meta2_filter_extract_header_spare(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_OPT(M2_KEY_SPARE);
	const gchar *type = meta2_filter_ctx_get_param(ctx, M2_KEY_SPARE);

	if (type != NULL) {
		/* No content length in spare request */
		meta2_filter_ctx_add_param(ctx, "CONTENT_LENGTH_OPT", "OK");
	}

	// Body beans are required only when doing blacklist spare request
	if (type == NULL || g_ascii_strcasecmp(type, M2V2_SPARE_BY_BLACKLIST))
		meta2_filter_ctx_add_param(ctx, "BODY_OPT", "OK");
	return FILTER_OK;
}

int
meta2_filter_extract_header_string_V_f2(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];

	TRACE_FILTER();
	EXTRACT_STRING2("field_2", "V", 0);
	return FILTER_OK;
}

int
meta2_filter_extract_opt_header_string_V_f2(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];

	TRACE_FILTER();
	EXTRACT_STRING2("field_2", "V", 1);
	return FILTER_OK;
}

static int
_extract_header_flag(const gchar *n, struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gboolean flag = 0;

	TRACE_FILTER();
	e = message_extract_flag(reply->request, n, 0, &flag);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	if (flag)
		meta2_filter_ctx_add_param(ctx, n, "1");
	return FILTER_OK;
}

int
meta2_filter_extract_header_forceflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return _extract_header_flag("FORCE", ctx, reply);
}

int
meta2_filter_extract_header_purgeflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return _extract_header_flag("PURGE", ctx, reply);
}

int
meta2_filter_extract_header_flushflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return _extract_header_flag("FLUSH", ctx, reply);
}

int
meta2_filter_extract_header_localflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	int ret = _extract_header_flag("LOCAL", ctx, reply);
	if (meta2_filter_ctx_get_param(ctx, "LOCAL")) {
		/* This is a hack to avoid changing every meta2_backend.h
		 * function prototype. */
		struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
		hc_url_set_option(url, META2_URL_LOCAL_BASE, "true");
	}
	return ret;
}

int
meta2_filter_extract_header_flags32(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	guint32 flags = 0;
	gchar strflags[32];

	TRACE_FILTER();
	e = message_extract_flags32(reply->request, "FLAGS", FALSE, &flags);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	g_snprintf(strflags, sizeof(strflags), "%"G_GUINT32_FORMAT, flags);
	meta2_filter_ctx_add_param(ctx, M2_KEY_GET_FLAGS, strflags);
	return FILTER_OK;
}

int
meta2_filter_extract_body_flags32(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	GByteArray *body = NULL;

	TRACE_FILTER();
	e = message_extract_body_gba(reply->request, &body);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, body, (GDestroyNotify)metautils_gba_unref);
	if (body->len != 4) {
		e = NEWERROR(CODE_BAD_REQUEST, "Invalid flags in body");
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_extract_header_string_size(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	const char *opt = meta2_filter_ctx_get_param(ctx, "CONTENT_LENGTH_OPT");

	TRACE_FILTER();
	EXTRACT_STRING(NAME_MSGKEY_CONTENTLENGTH, (opt != NULL));
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_ns(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *err;
	gchar ns[LIMIT_LENGTH_NSNAME];
	struct hc_url_s *url;

	TRACE_FILTER();

	memset(ns, 0, sizeof(ns));
	err = message_extract_string(reply->request, NAME_MSGKEY_NAMESPACE,
			ns, sizeof(ns));
	if (err) {
		g_clear_error(&err);
		err = message_extract_string(reply->request, NAME_MSGKEY_VIRTUALNAMESPACE,
				ns, sizeof(ns));
		if (err) {
			g_clear_error(&err);
		}
	}

	if (!*ns) {
		const struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
		g_strlcpy(ns, m2b->backend.ns_name, sizeof(ns));
	}

	if (!(url = meta2_filter_ctx_get_url(ctx))) {
		url = hc_url_empty();
		meta2_filter_ctx_set_url(ctx, url);
	}
	hc_url_set(url, HCURL_NS, ns);

	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_position_prefix(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_STRING("POSITION_PREFIX", TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_chunkid(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024]; // XXX: is there a maximum length for chunk ids?
	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_CHUNK_ID, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_overwrite(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_OVERWRITE, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_max_keys(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_STRING(M2_KEY_MAX_KEYS, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_list_params(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(M2_KEY_SNAPSHOT);
	EXTRACT_OPT(M2_KEY_PREFIX);
	EXTRACT_OPT(M2_KEY_MARKER);
	EXTRACT_OPT(M2_KEY_MARKER_END);
	EXTRACT_OPT(M2_KEY_MAX_KEYS);
	return FILTER_OK;
}

int
meta2_filter_extract_header_cid_dst(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_extract_cid(ctx, reply, "DST_CID");
}

int
meta2_filter_extract_header_cid_src(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	GError *err;
	container_id_t cid;
	gchar strcid[STRLEN_CONTAINERID];

	err = message_extract_cid(reply->request, "SRC_CID", &cid);
	if (err != NULL) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	container_id_to_string(cid, strcid, sizeof(strcid));
	meta2_filter_ctx_add_param(ctx, "SRC_CID", strcid);

	return FILTER_OK;
}

int
meta2_filter_extract_header_addr_src(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gint rc;
	void *f = NULL;
	size_t f_size = 0;
	GSList *l = NULL;
	GError *err = NULL;
	addr_info_t *ai = NULL;

	TRACE_FILTER();

	rc = message_get_field(reply->request, "SRC_ADDR", 8, &f, &f_size, &err);
	if (rc == 0) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}
	if (rc < 0) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_INTERNAL_ERROR, "Invalid peer address"));
		return FILTER_KO;
	}

	if (0 >= addr_info_unmarshall(&l, f, &f_size, &err)) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	if (!l) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST, "empty peer address list"));
		return FILTER_KO;
	}

	ai = g_malloc0(sizeof(addr_info_t));

	memcpy(ai, l->data, sizeof(addr_info_t));
	meta2_filter_ctx_set_input_udata(ctx, ai, (GDestroyNotify)g_free);
	g_slist_foreach(l, addr_info_gclean, NULL);
	g_slist_free(l);

	return FILTER_OK;
}

int
meta2_filter_extract_header_snapshot_hardrestore(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _extract_header_flag(M2_KEY_SNAPSHOT_HARDRESTORE, ctx, reply);
}

