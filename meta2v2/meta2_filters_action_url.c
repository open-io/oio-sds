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
#include <storage_policy.h>

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
_update_container_storage_policy(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *stgpol)
{
	GError *e = NULL;
	GByteArray *val = g_byte_array_append(g_byte_array_new(), (const guint8*)stgpol, strlen(stgpol));

	GSList l = {.data=NULL, .next=NULL};
	struct meta2_property_s m2p;

	l.data = &m2p;
	m2p.name = "sys.storage_policy";
	m2p.version = 0;
	m2p.value = val;
	e = meta2_backend_set_container_properties(m2b, url,
			M2V2_FLAG_NOFORMATCHECK, &l);

	g_byte_array_free(val, TRUE);

	if (NULL != e) {
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	}

	return FILTER_OK;
}

static int
_update_content_storage_policy(struct gridd_filter_ctx_s *ctx, struct meta2_backend_s *m2b,
		struct hc_url_s *url, const char *stgpol)
{
	auto void _get_alias_header_cb(gpointer udata, gpointer bean);

	GError *e = NULL;
	GSList *beans = NULL;
	gpointer alias = NULL;
	gpointer header = NULL;


	void _get_alias_header_cb(gpointer udata, gpointer bean) {
		(void) udata;
		if(DESCR(bean) == &descr_struct_ALIASES)
			alias = bean;
		else if(DESCR(bean) == &descr_struct_CONTENTS_HEADERS) 
			header = bean;
		else if(DESCR(bean) == &descr_struct_CONTENTS)
			beans = g_slist_prepend(beans, bean);
		else
			_bean_clean(bean);
	}

	e = meta2_backend_get_alias(m2b, url, M2V2_FLAG_NODELETED, _get_alias_header_cb, NULL);
	if(NULL != e) {
		GRID_DEBUG("Failed to get alias : %s", e->message);
		meta2_filter_ctx_set_error(ctx, e);
		return FILTER_KO;
	} 

	/* Check sp not already in place */
	if(0 == g_ascii_strcasecmp(CONTENTS_HEADERS_get_policy(header)->str, stgpol)) {
		_bean_clean(header);
		_bean_clean(alias);
		_bean_cleanl2(beans);
		return FILTER_OK;
	}

	CONTENTS_HEADERS_set2_policy(header, stgpol);

	GHashTable *unpacked = metadata_unpack_string(ALIASES_get_mdsys(alias)->str, &e);
	metadata_add_printf(unpacked, "storage-policy", stgpol);
	GByteArray *pack = metadata_pack(unpacked, NULL);
	g_hash_table_destroy(unpacked);
	g_byte_array_append(pack, (const guint8*)"\0", 1);
	char *mdsys = (char *)g_byte_array_free(pack, FALSE);
	ALIASES_set2_mdsys(alias, mdsys);
	g_free(mdsys);

	beans = g_slist_prepend(g_slist_prepend(beans, header), alias);
	e = meta2_backend_update_alias_header(m2b, url, beans);
	_bean_cleanl2(beans);

	if(NULL != e) {
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
	const char *stgpol = meta2_filter_ctx_get_param(ctx, M2_KEY_STORAGE_POLICY);
	struct storage_policy_s *sp = NULL;
	struct namespace_info_s ni;
	memset(&ni, 0, sizeof(ni));
	meta2_backend_get_nsinfo(m2b, &ni);

	/* ensure storage policy */
	if((!stgpol) || (NULL ==(sp = storage_policy_init(&ni, stgpol)))) {
		meta2_filter_ctx_set_error(ctx, NEWERROR(400, "Invalid storage policy [%s]", stgpol));
		return FILTER_KO;
	}

	namespace_info_clear(&ni);
	storage_policy_clean(sp);

	if(hc_url_has(url, HCURL_PATH))
		return _update_content_storage_policy(ctx, m2b, url, stgpol);
	return _update_container_storage_policy(ctx, m2b, url, stgpol);

}
