/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#define EXTRACT_STRING2(FieldName,VarName,Opt) do { \
	e = metautils_message_extract_string(reply->request, FieldName, buf, sizeof(buf)); \
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
	e = metautils_message_extract_string(reply->request, Name, buf, sizeof(buf)); \
	if (NULL != e) { \
		g_clear_error(&e); \
	} else { \
		meta2_filter_ctx_add_param(ctx, Name, buf); \
	} \
} while (0)

#define EXTRACT_HEADER_BEANS(FieldName,Variable) do {\
	GError *err = metautils_message_extract_header_encoded(reply->request, FieldName, TRUE, &Variable, bean_sequence_decoder);\
	if (err) { \
		meta2_filter_ctx_set_error(ctx, err);\
		return FILTER_KO;\
	} \
} while(0)

int
meta2_filter_extract_header_url(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	const gchar *err = NULL;
	struct oio_url_s *url = metautils_message_extract_url (reply->request);
    if (!oio_url_check(url, NULL, &err)) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST,
					"Invalid request, Invalid %s", err));
		oio_url_pclean(&url);
		return FILTER_KO;
    }
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
	EXTRACT_STRING(NAME_MSGKEY_COPY, TRUE);
	if (NULL != meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_COPY))
		meta2_filter_ctx_add_param(ctx, "BODY_OPT", "OK");
	return FILTER_OK;
}

int
meta2_filter_extract_header_storage_policy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[65];

	TRACE_FILTER();
	EXTRACT_STRING(NAME_MSGKEY_STGPOLICY, TRUE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_version_policy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	char buf[65];

	TRACE_FILTER();
	EXTRACT_STRING(NAME_MSGKEY_STGPOLICY, TRUE);
	return FILTER_OK;
}

static void
_plist_cleaner(gpointer ptr)
{
	GSList **lists = ptr;
	_bean_cleanl2(lists[0]);
	_bean_cleanl2(lists[1]);
	g_free (lists);
}


int
meta2_filter_extract_header_chunk_beans(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GSList **lists = g_malloc0(2 * sizeof(GSList *));
	EXTRACT_HEADER_BEANS(NAME_MSGKEY_NEW, lists[0]);
	EXTRACT_HEADER_BEANS(NAME_MSGKEY_OLD, lists[1]);
	meta2_filter_ctx_set_input_udata(ctx, lists, _plist_cleaner);
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
	GError *err = metautils_message_extract_body_encoded (reply->request, (opt==NULL), &l, bean_sequence_decoder);
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
meta2_filter_extract_header_append(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_STRING2(NAME_MSGKEY_APPEND, "APPEND", 1);
	return FILTER_OK;
}

int
meta2_filter_extract_header_spare(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SPARE);
	const gchar *type = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_SPARE);

	if (type != NULL) {
		/* No content length in spare request */
		meta2_filter_ctx_add_param(ctx, "CONTENT_LENGTH_OPT", "OK");
	}

	// Body beans are required only when doing blacklist spare request
	if (type == NULL || g_ascii_strcasecmp(type, M2V2_SPARE_BY_BLACKLIST))
		meta2_filter_ctx_add_param(ctx, "BODY_OPT", "OK");
	return FILTER_OK;
}

static int
_extract_header_flag(const gchar *n, struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	if (metautils_message_extract_flag(reply->request, n, 0))
		meta2_filter_ctx_add_param(ctx, n, "1");
	return FILTER_OK;
}

int
meta2_filter_extract_header_localflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _extract_header_flag(NAME_MSGKEY_LOCAL, ctx, reply);
}

int
meta2_filter_extract_header_flags32(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	gchar strflags[16];
	GError *e = NULL;
	guint32 flags = 0;

	TRACE_FILTER();
	e = metautils_message_extract_flags32(reply->request, NAME_MSGKEY_FLAGS, FALSE, &flags);
	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	g_snprintf(strflags, sizeof(strflags), "%"G_GUINT32_FORMAT, flags);
	meta2_filter_ctx_add_param(ctx, NAME_MSGKEY_FLAGS, strflags);
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
meta2_filter_extract_header_optional_overwrite(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_OVERWRITE);
	EXTRACT_OPT(NAME_MSGKEY_UPDATE);
	return FILTER_OK;
}

int
meta2_filter_extract_admin(struct gridd_filter_ctx_s *ctx,
			     struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_ADMIN_COMMAND);
	return FILTER_OK;
}

int
meta2_filter_extract_list_params(struct gridd_filter_ctx_s *ctx,
        struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_PREFIX);
	EXTRACT_OPT(NAME_MSGKEY_MARKER);
	EXTRACT_OPT(NAME_MSGKEY_MARKER_END);
	EXTRACT_OPT(NAME_MSGKEY_MAX_KEYS);
	return FILTER_OK;
}

