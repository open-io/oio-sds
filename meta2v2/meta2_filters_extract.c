/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#define EXTRACT_STRING(Name, Opt) do { \
	buf[0] = 0; \
	e = metautils_message_extract_string(reply->request, Name, !Opt, \
			buf, sizeof(buf)); \
	if (e) { \
		GRID_ERROR("Failed to extract '%s': (%d) %s (reqid=%s)", \
				Name, e->code, e->message, oio_ext_get_reqid()); \
		meta2_filter_ctx_set_error(ctx, e); \
		return FILTER_KO; \
	} else if (buf[0]) { \
		meta2_filter_ctx_add_param(ctx, Name, buf); \
	} \
} while (0)

#define EXTRACT_OPT(Name) EXTRACT_STRING(Name, TRUE)

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
				"Invalid request: invalid %s", err));
		oio_url_pclean(&url);
		return FILTER_KO;
	}
	meta2_filter_ctx_set_url(ctx, url);
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
		meta2_filter_ctx_set_error(ctx,
			BADREQ("Invalid request, Empty / Invalid body: (%d) %s",
					err->code, err->message));
		g_error_free(err);
		return FILTER_KO;
	}

	meta2_filter_ctx_set_input_udata(ctx, l, (GDestroyNotify)_bean_cleanl2);
	return FILTER_OK;
}

int
meta2_filter_extract_header_peers(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[512];

	TRACE_FILTER();
	EXTRACT_OPT(SQLX_ADMIN_PEERS);
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
meta2_filter_extract_header_urgentflag(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _extract_header_flag(NAME_MSGKEY_URGENT, ctx, reply);
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
meta2_filter_extract_header_optional_delete_marker(
		struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_DELETE_MARKER);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_bypass_governance(
		struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_BYPASS_GOVERNANCE);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_dryrun(
		struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_DRYRUN);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_slo_manifest(
		struct gridd_filter_ctx_s *ctx, struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SLO_MANIFEST);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_overwrite(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[128];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_OVERWRITE);
	EXTRACT_OPT(NAME_MSGKEY_UPDATE);
	EXTRACT_OPT(NAME_MSGKEY_CHANGE_POLICY);
	EXTRACT_OPT(NAME_MSGKEY_SKIP_DATA_MOVE);
	EXTRACT_OPT(NAME_MSGKEY_FORCE_EVENT_EMIT);
	EXTRACT_OPT(NAME_MSGKEY_RESTORE_DRAINED);
	return FILTER_OK;
}

int
meta2_filter_extract_header_string_maxvers(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_MAXVERS);
	return FILTER_OK;
}

int
meta2_filter_extract_header_optional_async_replication(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64*1000];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_REPLI_DESTS);
	EXTRACT_OPT(NAME_MSGKEY_REPLI_ID);
	EXTRACT_OPT(NAME_MSGKEY_REPLI_PROJECT_ID);
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
	const char *admin = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_ADMIN_COMMAND);
	oio_ext_set_admin(oio_str_parse_bool(admin, FALSE));
	return FILTER_OK;
}

int
meta2_filter_extract_force_master(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_FORCE_MASTER);
	const char *force_master = meta2_filter_ctx_get_param(
			ctx, NAME_MSGKEY_FORCE_MASTER);
	oio_ext_set_force_master(oio_str_parse_bool(force_master, FALSE));
	return FILTER_OK;
}

int
meta2_filter_extract_user_agent(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_USER_AGENT);
	const char *user_agent = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_USER_AGENT);
	oio_ext_set_user_agent(user_agent);
	return FILTER_OK;
}

int
meta2_filter_extract_list_params(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	// The prefix, marker and marker_end can be the size of an object name
	gchar buf[LIMIT_LENGTH_CONTENTPATH];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_PREFIX);
	EXTRACT_OPT(NAME_MSGKEY_DELIMITER);
	EXTRACT_OPT(NAME_MSGKEY_MARKER);
	EXTRACT_OPT(NAME_MSGKEY_VERSIONMARKER);
	EXTRACT_OPT(NAME_MSGKEY_MARKER_END);
	EXTRACT_OPT(NAME_MSGKEY_MAX_KEYS);
	EXTRACT_OPT(NAME_MSGKEY_VERSION);
	return FILTER_OK;
}

int
meta2_filter_extract_limit(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_LIMIT);
	return FILTER_OK;
}

int
meta2_filter_extract_force_versioning(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_STRING(NAME_MSGKEY_FORCE_VERSIONING, TRUE);
	/* TODO(mbo) we should validate value */
	const char *force_versioning = meta2_filter_ctx_get_param(
			ctx, NAME_MSGKEY_FORCE_VERSIONING);
	oio_ext_set_force_versioning(force_versioning);
	return FILTER_OK;
}

int
meta2_filter_extract_region(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[64];
	EXTRACT_OPT(NAME_MSGKEY_REGION);
	return FILTER_OK;
}

int
meta2_filter_extract_simulate_versioning(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SIM_VER);
	const char *simulate_versioning = meta2_filter_ctx_get_param(
			ctx, NAME_MSGKEY_SIM_VER);
	oio_ext_set_simulate_versioning(
			oio_str_parse_bool(simulate_versioning, FALSE));
	return FILTER_OK;
}

int
meta2_filter_extract_find_shards_params(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SHARDING_STRATEGY);
	return FILTER_OK;
}


int
meta2_filter_extract_prepare_shard_params(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SHARDING_ACTION);
	return FILTER_OK;
}


int
meta2_filter_extract_sharding_info(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SHARD_COMMAND);
	const char *is_shard = meta2_filter_ctx_get_param(ctx,
			NAME_MSGKEY_SHARD_COMMAND);
	oio_ext_set_is_shard_redirection(oio_str_parse_bool(is_shard, FALSE));

	if (oio_ext_is_shard_redirection()) {
		GPtrArray *tmp = g_ptr_array_new();
		gchar **names = metautils_message_get_field_names(reply->request);
		for (gchar **n = names; names && *n; ++n) {
			if (!g_str_has_prefix(*n, NAME_MSGKEY_PREFIX_SHARED_PROPERTY))
				continue;
			gchar *value = metautils_message_extract_string_copy(
						reply->request, *n);
			if (value && *value == ' ') {
				g_ptr_array_add(tmp, g_strdup(
					(*n) + sizeof(NAME_MSGKEY_PREFIX_SHARED_PROPERTY) - 1));
				g_ptr_array_add(tmp, g_strdup(value+1));
			}
			g_free(value);
		}
		g_strfreev(names);
		oio_ext_set_shared_properties(
				(gchar**) metautils_gpa_to_array(tmp, TRUE));
	}

	return FILTER_OK;
}

int
meta2_filter_extract_prefix(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_PREFIX);
	return FILTER_OK;
}

int
meta2_filter_extract_suffix(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_SUFFIX);
	return FILTER_OK;
}


int
meta2_filter_extract_lifecycle_action_params(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;
	gchar buf[1024];
	TRACE_FILTER();
	EXTRACT_OPT(NAME_MSGKEY_ACTION_TYPE);
	return FILTER_OK;
}