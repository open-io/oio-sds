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

static int
_update_content_storage_policy(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *stgpol)
{
	GError *e = NULL;
	GSList *beans = NULL;
	gpointer alias = NULL;
	gpointer header = NULL;

	void _get_alias_header_cb(gpointer udata, gpointer bean) {
		(void) udata;
		if(DESCR(bean) == &descr_struct_ALIASES)
			alias = bean;
		else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS)
			header = bean;
		else
			_bean_clean(bean);
	}

	if (!hc_url_has(url, HCURL_PATH))
		e = NEWERROR(CODE_BAD_REQUEST, "No content path");
	if (!e)
		e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _get_alias_header_cb, NULL);
	if (NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	/* Check sp not already in place */
	if (0 == g_ascii_strcasecmp(CONTENTS_HEADERS_get_policy(header)->str, stgpol)) {
		_bean_clean(header);
		_bean_clean(alias);
		_bean_cleanl2(beans);
		return FILTER_OK;
	}

	/* XXX */
	g_mutex_lock (&m2b->nsinfo_lock);
	e = storage_policy_check_compat_by_name(m2b->nsinfo,
			CONTENTS_HEADERS_get_policy(header)->str, stgpol);
	g_mutex_unlock (&m2b->nsinfo_lock);

	if (e != NULL) {
		GRID_DEBUG("Failed to update storage policy: %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		_bean_clean(header);
		_bean_clean(alias);
		_bean_cleanl2(beans);
		return FILTER_KO;
	}

	CONTENTS_HEADERS_set2_policy(header, stgpol);

	beans = g_slist_prepend(g_slist_prepend(beans, header), alias);
	e = meta2_backend_update_alias_header(m2b, url, beans);
	_bean_cleanl2(beans);

	if (NULL != e) {
		GRID_DEBUG("Failed to update alias/headers: %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
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
	struct storage_policy_s *sp = NULL;

	/* ensure storage policy */
	GError *err = NULL;
	if (!stgpol)
		err = NEWERROR(CODE_BAD_REQUEST, "Missing storage policy");
	if (!err) {
		/* XXX race condition around the nsinfo */
		g_mutex_lock (&m2b->nsinfo_lock);
		sp = storage_policy_init (m2b->nsinfo, stgpol);
		g_mutex_unlock (&m2b->nsinfo_lock);
	}
	if (!sp)
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid storage policy [%s]", stgpol);
	if (err) {
		meta2_filter_ctx_set_error(ctx, err);
		return FILTER_KO;
	}

	storage_policy_clean(sp);
	return _update_content_storage_policy(ctx, m2b, url, stgpol);
}

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
