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
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_json.h>

static void
_append_url (GString *gs, struct hc_url_s *url)
{
	void _append (const char *n, const char *v) {
		if (v)
			g_string_append_printf (gs, "\"%s\":\"%s\"", n, v);
		else
			g_string_append_printf (gs, "\"%s\":null", n);
	}
	_append ("ns", hc_url_get(url, HCURL_NS));
	g_string_append_c (gs, ',');
	_append ("account", hc_url_get(url, HCURL_ACCOUNT));
	g_string_append_c (gs, ',');
	_append ("user", hc_url_get(url, HCURL_USER));
	g_string_append_c (gs, ',');
	_append ("type", hc_url_get(url, HCURL_TYPE));
	g_string_append_c (gs, ',');
	_append ("id", hc_url_get(url, HCURL_HEXID));
}

int
meta2_filter_action_notify_container_CREATE(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (!m2b->notify.hook)
		return FILTER_OK;

	GString *gs = g_string_new ("{");
	g_string_append (gs, "\"event\":\""NAME_SRVTYPE_META2".container.create\"");
	g_string_append_printf (gs, ",\"when\":%"G_GINT64_FORMAT, g_get_real_time());
	g_string_append (gs, ",\"data\":{");
	g_string_append (gs, "\"url\":{");
	_append_url (gs, url);
	g_string_append (gs, "}}}");
	m2b->notify.hook (m2b->notify.udata, g_string_free (gs, FALSE));

	return FILTER_OK;
}

int
meta2_filter_action_notify_container_DESTROY(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (!m2b->notify.hook)
		return FILTER_OK;

	GString *gs = g_string_new ("{");
	g_string_append (gs, "\"event\":\"" NAME_SRVTYPE_META2 ".container.destroy\"");
	g_string_append_printf (gs, ",\"when\":%"G_GINT64_FORMAT, g_get_real_time());
	g_string_append (gs, ",\"data\":{");
	g_string_append (gs, "\"url\":{");
	_append_url (gs, url);
	g_string_append (gs, "}}}");
	m2b->notify.hook (m2b->notify.udata, g_string_free (gs, FALSE));

	return FILTER_OK;
}

int
meta2_filter_action_touch_content_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return FILTER_OK;
}

int
meta2_filter_action_touch_container_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	return FILTER_OK;
}

