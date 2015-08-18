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

struct on_bean_ctx_s *
_on_bean_ctx_init(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	struct on_bean_ctx_s * obc = g_malloc0(sizeof(struct on_bean_ctx_s));
	obc->l = NULL;
	obc->first = TRUE;
	obc->ctx = ctx;
	obc->reply = reply;
	return obc;
}

void
_on_bean_ctx_append_udata_list(struct on_bean_ctx_s *obc)
{
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(obc->ctx);

	if (m2b->notify.hook) {
		if (obc->first) {
			obc->first = FALSE;
			meta2_filter_ctx_set_input_udata(obc->ctx, obc->l,
					(GDestroyNotify)_bean_cleanl2);
		} else {
			meta2_filter_ctx_set_input_udata2(obc->ctx,
					metautils_gslist_precat(obc->l,
						(GSList*)meta2_filter_ctx_get_input_udata(obc->ctx)),
					(GDestroyNotify) _bean_cleanl2, FALSE);
		}
	} else {
		GRID_TRACE("Events disabled, cleaning beans immediately");
		_bean_cleanl2(obc->l);
	}
}

void
_on_bean_ctx_send_list(struct on_bean_ctx_s *obc, gboolean final)
{
	/* marshall the list, send and clean it */
	if (NULL != obc->l) {
		obc->l = g_slist_reverse (obc->l);
		obc->reply->add_body(bean_sequence_marshall(obc->l));
		_on_bean_ctx_append_udata_list(obc);
	}
	if (final)
		obc->reply->send_reply(CODE_FINAL_OK, "OK");
	else
		obc->reply->send_reply(CODE_PARTIAL_CONTENT, "Partial content");
	obc->l = NULL;
}

void
_on_bean_ctx_clean(struct on_bean_ctx_s *obc)
{
	if(!obc)
		return;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(obc->ctx);

	if (obc->l) {
		if (!m2b->notify.hook)
			_bean_cleanl2(obc->l);
		obc->l = NULL;
	}
	obc->reply = NULL;
	obc->ctx = NULL;
	g_free(obc);
}

int
meta2_filter_fill_subject(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	reply->subject("%s|%s", hc_url_get(url, HCURL_WHOLE), hc_url_get(url, HCURL_HEXID));
	return FILTER_OK;
}

#define FILL_URL_FIELD(K, F) do { \
	tmp = meta2_filter_ctx_get_param(ctx, K); \
	if(NULL != tmp) { \
		hc_url_set(url, F, tmp); \
		tmp = NULL; \
	} \
} while(0)

int
meta2_filter_fail_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	GError *e = NULL;

	TRACE_FILTER();
	e = meta2_filter_ctx_get_error(ctx);
	if(NULL != e) {
		GRID_DEBUG("Error defined by KO execution filter, return it");
		reply->send_error(0, e);
	} else {
		GRID_DEBUG("Error not defined by KO execution filter, return %u", CODE_INTERNAL_ERROR);
		reply->send_error(0, NEWERROR(CODE_INTERNAL_ERROR,
					"Request execution failed : No error"));
	}

	return FILTER_OK;
}

int
meta2_filter_success_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	(void) ctx;
	reply->send_reply(CODE_FINAL_OK, "OK");
	return FILTER_OK;
}

int
meta2_filter_not_implemented_reply(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	TRACE_FILTER();
	(void) ctx;
	reply->send_reply(CODE_NOT_IMPLEMENTED, "NOT IMPLEMENTED");
	return FILTER_OK;
}
