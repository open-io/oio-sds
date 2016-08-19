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

#include <glib.h>

#include <server/transport_gridd.h>
#include <server/gridd_dispatcher_filters.h>
#include <meta2v2/meta2_filters.h>
#include <meta2v2/meta2_filter_context.h>
#include <meta2v2/generic.h>
#include <events/oio_events_queue.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2_backend_internals.h>

int
meta2_filter_action_touch_content_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) ctx, (void) reply;
	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct oio_url_s *url = meta2_filter_ctx_get_url(ctx);
	GString *gs = oio_event__create (META2_EVENTS_PREFIX".content.touch",
					 url);
	g_string_append (gs, ",\"data\":null}");
	oio_events_queue__send (m2b->notifier, g_string_free (gs, FALSE));
	return FILTER_OK;
}

int
meta2_filter_action_touch_container_v1(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) ctx, (void) reply;
	return FILTER_OK;
}

