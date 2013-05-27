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

#include <metatypes.h>
#include <metautils.h>
#include <metacomm.h>
#include <hc_url.h>

#include <glib.h>

#include <transport_gridd.h>

#include "../server/gridd_dispatcher_filters.h"

#include "./meta2_macros.h"
#include "./meta2_filter_context.h"
#include "./meta2_filters.h"
#include "./meta2_backend_internals.h"
#include "./meta2_bean.h"
#include "./meta2v2_remote.h"
#include "./generic.h"
#include "./autogen.h"

#define TRACE_FILTER() GRID_TRACE2("%s", __FUNCTION__)

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
		meta2_filter_ctx_set_error(ctx, NEWERROR(400,
					"Bad Request: Missing namespace name information"));
		return FILTER_KO;
	}

	if (0 != g_ascii_strcasecmp(backend->ns_name, req_ns)) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(400,
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
	(void) ctx;
	(void) reply;
	TRACE_FILTER();
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
		meta2_filter_ctx_set_error(ctx, NEWERROR(462, "Property must start with prefix user."));
		return FILTER_KO;
	}

	return FILTER_OK;
}


