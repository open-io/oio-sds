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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <metautils/lib/metautils_strings.h>
#include <metautils/lib/common_variables.h>
#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <events/oio_events_queue.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <cluster/lib/gridcluster.h>

static int
_meta2_filter_check_ns_name(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply, int optional)
{
	(void) reply;
	TRACE_FILTER();
	const struct meta2_backend_s *backend = meta2_filter_ctx_get_backend(ctx);
	const char *req_ns = oio_url_get(meta2_filter_ctx_get_url(ctx), OIOURL_NS);

	if (!backend || !backend->ns_name[0]) {
		GRID_DEBUG("Missing information for namespace checking");
		meta2_filter_ctx_set_error(ctx, SYSERR("backend not ready"));
		return FILTER_KO;
	}

	if (!req_ns) {
		if (optional)
			return FILTER_OK;
		GRID_DEBUG("Missing namespace name in request");
		meta2_filter_ctx_set_error(ctx, BADREQ("No namespace"));
		return FILTER_KO;
	}

	if (0 != g_ascii_strcasecmp(backend->ns_name, req_ns)) {
		meta2_filter_ctx_set_error(ctx, BADNS());
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
	(void) reply;
	TRACE_FILTER();
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	if (meta2_backend_initiated(m2b))
		return FILTER_OK;
	meta2_filter_ctx_set_error(ctx, SYSERR("Backend not ready"));
	return FILTER_KO;
}

int
meta2_filter_check_ns_is_master(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	TRACE_FILTER();
	struct meta2_backend_s *backend = meta2_filter_ctx_get_backend(ctx);

	const char *admin = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_ADMIN_COMMAND);
	if (oio_str_parse_bool(admin, FALSE)) {
		GRID_DEBUG("admin mode is on");
		return FILTER_OK;
	}

	gboolean master = TRUE;

	g_mutex_lock(&backend->nsinfo_lock);
	gchar *state = namespace_get_state(backend->nsinfo);
	g_mutex_unlock(&backend->nsinfo_lock);
	if (state) {
		master = (0 != g_strcmp0(state, NS_STATE_VALUE_SLAVE));
		g_free(state);
	}

	if (master)
		return FILTER_OK;
	GRID_TRACE("NS is slave, operation failed");
	meta2_filter_ctx_set_error(ctx, SYSERR("NS slave!"));
	return FILTER_KO;
}

int
meta2_filter_check_ns_not_wormed(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	const char *admin = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_ADMIN_COMMAND);
	if (oio_str_parse_bool(admin, FALSE)) {
		if (GRID_DEBUG_ENABLED())
			GRID_DEBUG("admin mode is on");
		return FILTER_OK;
	}
	if (oio_ns_mode_worm) {
		if (GRID_DEBUG_ENABLED())
			GRID_DEBUG("NS wormed!");
		meta2_filter_ctx_set_error(ctx, SYSERR("NS wormed!"));
		return FILTER_KO;
	}
	TRACE_FILTER();
	return FILTER_OK;
}

int
meta2_filter_check_url_cid (struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	TRACE_FILTER();
	if (url && oio_url_has(url, OIOURL_HEXID))
		return FILTER_OK;
	meta2_filter_ctx_set_error (ctx, BADREQ("Invalid URL"));
	return FILTER_KO;
}

int
meta2_filter_check_events_not_stalled (struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;
	TRACE_FILTER ();

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	if (m2b->notifier && meta2_backend_initiated (m2b)) {
		if (oio_events_queue__is_stalled (m2b->notifier)) {
			meta2_filter_ctx_set_error(ctx, BUSY("Too many pending events"));
			return FILTER_KO;
		}
	}

	return FILTER_OK;
}

