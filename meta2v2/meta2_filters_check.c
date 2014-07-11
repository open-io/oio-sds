#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta2.disp"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <glib.h>

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

static int
_meta2_filter_check_ns_name(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, int optional)
{
	(void) reply;
	TRACE_FILTER();
	const struct meta2_backend_s *backend = meta2_filter_ctx_get_backend(ctx);
	const char *req_ns = hc_url_get(meta2_filter_ctx_get_url(ctx), HCURL_NSPHYS);

	if (!backend || !backend->ns_name[0]) {
		GRID_DEBUG("Missing information for namespace checking");
		meta2_filter_ctx_set_error(ctx, NEWERROR(500,
					"Missing backend information, cannot check namespace"));
		return FILTER_KO;
	}

	if (!req_ns) {
		if (optional) {
			return FILTER_OK;
		}
		GRID_DEBUG("Missing namespace name in request");
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST,
					"Bad Request: Missing namespace name information"));
		return FILTER_KO;
	}

	if (0 != g_ascii_strcasecmp(backend->ns_name, req_ns)) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_BAD_REQUEST,
					"Request namespace [%s] does not match server namespace [%s]",
					req_ns, backend->ns_name));
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_check_ns_name(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_check_ns_name(ctx, reply, 0);
}

int
meta2_filter_check_optional_ns_name(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	return _meta2_filter_check_ns_name(ctx, reply, 1);
}

int
meta2_filter_check_backend(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b;

	(void) reply;
	TRACE_FILTER();
	m2b = meta2_filter_ctx_get_backend(ctx);
	if (meta2_backend_initiated(m2b))
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, NEWERROR(500, "Backend not ready"));
	return FILTER_KO;
}

int
meta2_filter_check_ns_is_master(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) ctx;
	(void) reply;
	TRACE_FILTER();
	return FILTER_OK;
}

int
meta2_filter_check_ns_is_slave(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) ctx;
	(void) reply;
	TRACE_FILTER();
	return FILTER_OK;
}

int
meta2_filter_check_ns_not_wormed(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) ctx;
	(void) reply;
	TRACE_FILTER();
	return FILTER_OK;
}

int
meta2_filter_check_ns_is_writable(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	const gchar *vns = hc_url_get(meta2_filter_ctx_get_url(ctx), HCURL_NS);
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	gboolean found = FALSE;

	(void) reply;
	TRACE_FILTER();

	if (!m2b || !meta2_backend_is_quota_enabled(m2b))
		return FILTER_OK;

	g_mutex_lock(m2b->lock_ns_info);
	found = namespace_info_is_vns_writable(&(m2b->ns_info), vns);
	g_mutex_unlock(m2b->lock_ns_info);

	if (!found) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_NAMESPACE_FULL, "VNS full"));
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_check_prop_key_prefix(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	TRACE_FILTER();

	const char *k = meta2_filter_ctx_get_param(ctx, "K");

	if(!g_str_has_prefix(k, "user.") && !g_str_has_prefix(k, "sys.")) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(CODE_WRONG_PROP_PREFIX,
				"Property must start with prefix user."));
		return FILTER_KO;
	}

	return FILTER_OK;
}

int
meta2_filter_check_snapshot_name(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	const gchar *snapshot_name = NULL;

	TRACE_FILTER();

	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	if (!hc_url_has(url, HCURL_SNAPSHOT)) {
		if (!hc_url_has(url, HCURL_VERSION)) {
			meta2_filter_ctx_set_error(ctx,
					NEWERROR(CODE_BAD_REQUEST,
						"Missing snapshot URL parameter: %s",
						hc_url_get(url, HCURL_WHOLE)));
			return FILTER_KO;
		} else {
			// Take snapshot name from version
			hc_url_set(url, HCURL_SNAPSHOT, hc_url_get(url, HCURL_VERSION));
		}
	}

	snapshot_name = hc_url_get(url, HCURL_SNAPSHOT);
	if (strlen(snapshot_name) <= 0) {
		meta2_filter_ctx_set_error(ctx,
				NEWERROR(CODE_BAD_REQUEST, "Snapshot name is empty"));
		return FILTER_KO;
	} else if (snapshot_name[0] >= '0' && snapshot_name[0] <= '9') {
		// snapshot names should not start with digits
		meta2_filter_ctx_set_error(ctx,
				NEWERROR(CODE_BAD_REQUEST, "Invalid snapshot name: '%s' (%s)",
					hc_url_get(url, HCURL_SNAPSHOT),
					"must not start with digits"));
		return FILTER_KO;
	}

	return FILTER_OK;
}

