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

#include <metautils/metautils.h>
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
#include <sqliterepo/election.h>
#include <resolver/hc_resolver.h>

int
meta2_filter_action_exit_election(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);

	if (hc_url_has(url,HCURL_HEXID)) {
		struct sqlx_name_s n = {
			.base = hc_url_get(url,HCURL_HEXID),
			.type = NAME_SRVTYPE_META2,
			.ns = m2b->backend.ns_name
		};
		GError *err = sqlx_repository_exit_election(m2b->backend.repo, &n);
		hc_decache_reference_service(m2b->resolver, url, NAME_SRVTYPE_META2);
		if (err) {
			meta2_filter_ctx_set_error(ctx, err);
			return FILTER_KO;
		}
	} else {
		election_manager_exit_all(sqlx_repository_get_elections_manager(
					m2b->backend.repo), NULL, FALSE);
	}
	return FILTER_OK;
}

int
meta2_filter_action_update_storage_policy(struct gridd_filter_ctx_s *ctx,
		struct gridd_reply_ctx_s *reply)
{
	(void) reply;

	struct meta2_backend_s *m2b = meta2_filter_ctx_get_backend(ctx);
	struct hc_url_s *url = meta2_filter_ctx_get_url(ctx);
	const char *stgpol = meta2_filter_ctx_get_param(ctx, NAME_MSGKEY_STGPOLICY);

	GError *err = meta2_backend_set_stgpol (m2b, url, stgpol);
	if (!err)
		return FILTER_OK;
	meta2_filter_ctx_set_error (ctx, err);
	return FILTER_KO;
}

