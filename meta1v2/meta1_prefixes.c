/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <stddef.h>
#include <string.h>

#include <sqlite3.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <meta0v2/meta0_remote.h>
#include <meta0v2/meta0_utils.h>
#include <sqliterepo/sqliterepo.h>

#include "./internals.h"
#include "./internals_sqlite.h"
#include "./meta1_prefixes.h"
#include "./meta1_backend.h"

#define SWAP_PTR(P0,PNEW) do { \
	if (!(P0)) { (P0) = (PNEW); (PNEW) = NULL; } \
	else { void *p = (P0); (P0) = (PNEW); (PNEW) = p; } } while (0)

struct meta1_prefixes_set_s
{
	guint8 *cache;
	GPtrArray *by_prefix;
	GMutex lock;
};

/* CACHE operations --------------------------------------------------------- */

#define BITPOS(X) (1<<((X)%8))

static void
_cache_manage(guint8 *cache, const guint8 *prefix)
{
	register const guint16 slot = *((const guint16*)prefix);
	cache[ slot / 8 ] |= BITPOS(slot);
}

static gboolean
_cache_is_managed(const guint8 *cache, const guint8 *prefix)
{
	register const guint16 slot = *((const guint16*)prefix);
	return BOOL(cache[ slot / 8 ] & BITPOS(slot));
}

/* NS operations ------------------------------------------------------------ */

void
meta1_prefixes_manage_all(struct meta1_prefixes_set_s *m1ps)
{
	EXTRA_ASSERT(m1ps != NULL);
	g_mutex_lock(&m1ps->lock);
	for (guint i=0; i<65536 ;++i) {
		guint16 i16 = i;
		_cache_manage(m1ps->cache, (guint8*)&i16);
	}
	g_mutex_unlock(&m1ps->lock);
}

static guint8*
_cache_from_m0l(const GSList *l, const struct addr_info_s *ai)
{
	guint8 *result = g_malloc0(8192);

	for (; l ;l=l->next) {
		const struct meta0_info_s *m0i = l->data;
		if (unlikely(!m0i)) continue;

		if (addr_info_equal(&(m0i->addr), ai)) {
			const guint8 *max = m0i->prefixes + m0i->prefixes_size;
			for (guint8 *p = m0i->prefixes; p<max ;p+=2)
				_cache_manage(result, p);
		}
	}

	return result;
}

static GError*
_cache_load_from_m0(struct meta1_prefixes_set_s *m1ps,
		const struct addr_info_s *local_addr,
		const struct addr_info_s *m0_addr,
		GArray **updated_prefixes,
		gboolean *meta0_ok,
		guint digits,
		gint64 deadline)
{
	EXTRA_ASSERT(m1ps != NULL);
	GRID_TRACE2("%s(%p,%p,%p)", __FUNCTION__, m1ps, local_addr, m0_addr);

	GPtrArray *by_prefix = NULL;
	GSList *m0info_list = NULL;
	guint8 *cache = NULL;
	GError *err = NULL;
	gchar m0[STRLEN_ADDRINFO];

	grid_addrinfo_to_string (m0_addr, m0, sizeof(m0));

	err = meta0_remote_get_meta1_all(m0, &m0info_list, deadline);
	if (err) {
		g_prefix_error(&err, "Remote error: ");
		goto label_exit;
	}
	if (!m0info_list) {
		GRID_DEBUG("META0 has no prefix configured!");
		goto label_exit;
	}

	*meta0_ok = TRUE;

	cache = _cache_from_m0l(m0info_list, local_addr);
	if (!cache) {
		err = SYSERR("Cache allocation error");
		goto label_exit;
	}

	err = meta1_prefixes_check_coalescence_all(cache, digits);
	if (NULL != err) {
		g_prefix_error(&err, "Meta0 consistency check: ");
		goto label_exit;
	}

	by_prefix = meta0_utils_list_to_array(m0info_list);

	g_mutex_lock(&m1ps->lock);
	GRID_DEBUG("Got %u prefixes from M0, %u in place",
			by_prefix->len, m1ps->by_prefix ? m1ps->by_prefix->len : 0);

	if (m1ps->by_prefix) {
		*updated_prefixes = g_array_new(FALSE, FALSE, sizeof(guint16));
		for (guint i = 0; i < CID_PREFIX_COUNT; i++) {
			const guint16 prefix = i;
			const guint8 *bin = (guint8*)&prefix;
			const gboolean before = _cache_is_managed(m1ps->cache, bin);
			const gboolean after = _cache_is_managed(cache, bin);
			if (BOOL(before) != BOOL(after))
				g_array_append_vals(*updated_prefixes, bin, 1);
		}
	}

	SWAP_PTR(m1ps->by_prefix, by_prefix);
	SWAP_PTR(m1ps->cache, cache);
	g_mutex_unlock(&m1ps->lock);

label_exit:
	if (by_prefix)
		meta0_utils_array_clean(by_prefix);
	if (cache)
		g_free(cache);
	g_slist_free_full(m0info_list, (GDestroyNotify)meta0_info_clean);
	return err;
}

static GError*
_cache_load_from_ns(struct meta1_prefixes_set_s *m1ps, const char *ns_name,
		const char *local_url, GArray **updated_prefixes, gboolean *meta0_ok,
		guint digits, gint64 deadline)
{
	struct addr_info_s local_ai = {{0}};
	gboolean done = FALSE;

	EXTRA_ASSERT(m1ps != NULL);

	if (!ns_name || !local_url) {
		GRID_TRACE("META1 prefix set not configured to be reloaded from a namespace");
		return NULL;
	}

	grid_string_to_addrinfo(local_url, &local_ai);

	/* Get the META0 address */
	GError *err = NULL;
	GSList *m0_list = NULL;
	err = conscience_get_services (ns_name, NAME_SRVTYPE_META0, FALSE, &m0_list, deadline);
	if (err != NULL) {
		g_prefix_error(&err, "META0 locate error : ");
		return err;
	}

	if (!m0_list)
		return NEWERROR(0, "No META0 available in the namespace");;

	/* Get the prefixes list */
	m0_list = metautils_gslist_shuffle (m0_list);
	for (GSList *m0 = m0_list ; m0 && !err && !done ; m0 = m0->next) {
		const struct service_info_s *si = m0->data;
		err = _cache_load_from_m0(m1ps, &local_ai, &(si->addr),
				updated_prefixes, meta0_ok, digits, deadline);
		if (!err) {
			done = TRUE;
		} else {
			GRID_WARN("M0 cache loading error : (%d) %s", err->code, err->message);
			if (CODE_IS_NETWORK_ERROR(err->code))
				g_clear_error(&err);
		}
	}

	g_slist_free_full(m0_list, (GDestroyNotify)service_info_clean);
	if (!err && !done)
		err = NEWERROR(0, "No META0 replied");
	return err;
}

/* Public API --------------------------------------------------------------- */

gboolean
meta1_prefixes_is_managed(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes)
{
	if (!m1ps || !m1ps->cache || !bytes)
		return FALSE;
	g_mutex_lock(&m1ps->lock);
	gboolean rc = _cache_is_managed(m1ps->cache, bytes);
	g_mutex_unlock(&m1ps->lock);
	return rc;
}

void
meta1_prefixes_clean(struct meta1_prefixes_set_s *m1ps)
{
	if (!m1ps)
		return;
	if (m1ps->cache)
		g_free(m1ps->cache);
	if (m1ps->by_prefix)
		meta0_utils_array_clean(m1ps->by_prefix);
	g_mutex_clear(&m1ps->lock);
	memset(m1ps, 0, sizeof(*m1ps));
	g_free(m1ps);
}

GError*
meta1_prefixes_load(struct meta1_prefixes_set_s *m1ps,
		const char *ns_name, const char *local_url,
		GArray **updated_prefixes, gboolean *meta0_ok, guint digits,
		gint64 deadline)
{
	GError *err = NULL;

	EXTRA_ASSERT(m1ps != NULL);
	EXTRA_ASSERT(ns_name != NULL);
	EXTRA_ASSERT(local_url != NULL);

	err = _cache_load_from_ns(m1ps, ns_name, local_url, updated_prefixes,
			meta0_ok, digits, deadline);
	if (NULL != err)
		g_prefix_error(&err, "NS loading error : ");
	else
		GRID_DEBUG("Prefixes reloaded for NS[%s]", ns_name);

	return err;
}

gchar**
meta1_prefixes_get_all(struct meta1_prefixes_set_s *m1ps)
{
	EXTRA_ASSERT(m1ps != NULL);

	int i,done;
	union {
		guint16 prefix;
		guint8 b[2];
	} u;
	gchar **result = g_malloc0(sizeof(gchar*)* (65536 + 1));
	gchar name[8];

	u.prefix = 0;

	for (i=done=0; i<65536 ;i++,u.prefix++) {
		if (meta1_prefixes_is_managed(m1ps, u.b)) {
			g_snprintf(name, sizeof(name), "%02X%02X", u.b[0], u.b[1]);
			result[done] = g_strdup(name);

			done++;
		}
	}
	result[done] = NULL;

	return result;
}

struct meta1_prefixes_set_s *
meta1_prefixes_init(void)
{
	struct meta1_prefixes_set_s *m1ps =
		g_malloc0(sizeof(struct meta1_prefixes_set_s));
	m1ps->cache = g_malloc0(8192);
	g_mutex_init(&m1ps->lock);
	m1ps->by_prefix = NULL;
	return m1ps;
}

gchar **
meta1_prefixes_get_peers(struct meta1_prefixes_set_s *m1ps,
		const guint8 *bytes)
{
	EXTRA_ASSERT(m1ps != NULL);
	g_mutex_lock(&m1ps->lock);
	gchar **a = meta0_utils_array_get_urlv(m1ps->by_prefix, bytes);
	g_mutex_unlock(&m1ps->lock);
	return a;
}

/* @private */
struct _check_ctx_s {
	GError *err;
	const guint8 *cache;
};

static gboolean
_on_prefix(gpointer u, const guint8 *grp, const guint8 *pfx)
{
	struct _check_ctx_s *ctx = u;
	if (NULL != ctx->err)
		return FALSE;
	gboolean pfx_present = _cache_is_managed(ctx->cache, pfx);
	gboolean grp_present = _cache_is_managed(ctx->cache, grp);
	if (pfx_present == grp_present)
		return TRUE;
	ctx->err = ERRPTF("Invalid Group=%02X%02X Prefix=%02X%02X",
			grp[0], grp[1], pfx[0], pfx[1]);
	return FALSE;
}

GError *
meta1_prefixes_check_coalescence (const guint8 *cache, const guint8 *bytes,
		guint digits)
{
	struct _check_ctx_s ctx = {NULL, cache};
	meta0_utils_foreach_prefix_in_group(bytes, digits, _on_prefix, &ctx);
	return ctx.err;
}

GError *
meta1_prefixes_check_coalescence_all (const guint8 *cache, guint digits)
{
	struct _check_ctx_s ctx = {NULL, cache};
	meta0_utils_foreach_prefix(digits, _on_prefix, &ctx);
	return ctx.err;
}

