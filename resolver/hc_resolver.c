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
# define G_LOG_DOMAIN "grid.sqlx.resolve"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include "../metautils/lib/metautils.h"
#include "../metautils/lib/hc_url.h"
#include "../metautils/lib/hashstr.h"
#include "../metautils/lib/lrutree.h"
#include "../cluster/lib/gridcluster.h"
#include "../meta0v2/meta0_remote.h"
#include "../meta1v2/meta1_remote.h"

#include "./hc_resolver.h"
#include "./hc_resolver_internals.h"

/* Packing */
static inline gsize
_strv_total_length(gchar **v)
{
	register gsize total = 0;
	for (; *v; v++)
		total += 1+strlen(*v);
	return total;
}

/* Packing */
static inline void
_strv_concat(register gchar *d, gchar **src)
{
	register gchar *s, c;

	while (NULL != (s = *(src++))) {
		do {
			*(d++) = (c = *(s++));
		} while (c);
	}
}

/* Unpacking */
static inline void
_strv_pointers(gchar **dst, gchar *src, guint count)
{
	while (count--) {
		register gsize s = strlen(src) + 1;
		*(dst++) = g_memdup(src, s);
		src += s;
	}
}

/* Public API -------------------------------------------------------------- */

static struct cached_element_s*
hc_resolver_element_create(gchar **value, time_t ttl)
{
	gsize s;
	struct cached_element_s *elt;

	g_assert(value != NULL);

	s = offsetof(struct cached_element_s, s) + _strv_total_length(value);

	elt = g_malloc(s);
	elt->count_served = 0;
	elt->use = time(0);
	elt->ttl = ttl;
	elt->count_elements = g_strv_length(value);
	_strv_concat(elt->s, value);

	return elt;
}

static gchar**
hc_resolver_element_extract(struct cached_element_s *elt)
{
	gchar **result;

	if (!elt)
		return NULL;

	result = g_malloc((elt->count_elements + 1) * sizeof(gchar*));
	_strv_pointers(result, elt->s, elt->count_elements);
	result[elt->count_elements] = NULL;

	return result;
}

struct hc_resolver_s*
hc_resolver_create(void)
{
	struct hc_resolver_s *resolver = g_malloc0(sizeof(struct hc_resolver_s));
	resolver->max_elements = 1000U;
	resolver->max_served = 64;
	resolver->lock = g_mutex_new();
	resolver->cache = lru_tree_create((GCompareFunc)hashstr_quick_cmp,
			g_free, g_free, 0);
	return resolver;
}

void
hc_resolver_destroy(struct hc_resolver_s *r)
{
	if (!r)
		return;
	if (r->cache)
		lru_tree_destroy(r->cache);
	if (r->lock)
		g_mutex_free(r->lock);
	g_free(r);
}

static gchar**
hc_resolver_get_cached(struct hc_resolver_s *r, const struct hashstr_s *k)
{
	gchar **result = NULL;
	struct cached_element_s *elt;

	g_mutex_lock(r->lock);
	if (NULL != (elt = lru_tree_get(r->cache, k))) {
		elt->count_served ++;
		if (!(r->flags & HC_RESOLVER_NOATIME))
			elt->use = time(0);
		result = hc_resolver_element_extract(elt);
	}
	g_mutex_unlock(r->lock);

	return result;
}

static void
hc_resolver_store(struct hc_resolver_s *r, const struct hashstr_s *key,
		gchar **v, time_t ttl)
{
	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	struct cached_element_s *elt = hc_resolver_element_create(v, ttl);
	struct hashstr_s *k = hashstr_dup(key);

	g_mutex_lock(r->lock);
	lru_tree_insert(r->cache, k, elt);
	g_mutex_unlock(r->lock);
}

static void
hc_resolver_forget(struct hc_resolver_s *r, const struct hashstr_s *k)
{
	g_mutex_lock(r->lock);
	lru_tree_remove(r->cache, k);
	g_mutex_unlock(r->lock);
}

/* ------------------------------------------------------------------------- */

static gchar **
_srvlit_to_urlv(GSList *l)
{
	gchar str[64];
	struct service_info_s *si;
	GPtrArray *tmp;

	tmp = g_ptr_array_new();
	for (; l ;l=l->next) {
		si = l->data;
		addr_info_to_string(&(si->addr), str, sizeof(str));
		g_ptr_array_add(tmp, g_strdup_printf("1|%s|%s|", si->type, str));
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

static GError*
_resolve_meta0(struct hc_resolver_s *r, const gchar *ns, gchar ***result)
{
	struct hashstr_s *hk;
	GError *err = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, ns);
	hk = hashstr_printf("meta0|%s", ns);

	/* Try to hit the cache */
	if (!(*result = hc_resolver_get_cached(r, hk))) {
		GSList *allm0;

		/* Now attempt a real resolution */
		if (!(allm0 = list_namespace_services(ns, "meta0", &err))) {
			if (!err)
				err = NEWERROR(500, "No meta0 available");
			*result = NULL;
		}
		else {
			*result = _srvlit_to_urlv(allm0);
			g_slist_foreach(allm0, service_info_gclean, NULL);
			g_slist_free(allm0);
			allm0 = NULL;

			/* then fill the cache */
			hc_resolver_store(r, hk, *result, 300);
			err = NULL;
		}
	}

	g_free(hk);
	return err;
}

/* ------------------------------------------------------------------------- */

static gchar **
_m0list_to_urlv(GSList *l)
{
	gchar str[STRLEN_ADDRINFO];
	GPtrArray *tmp;

	tmp = g_ptr_array_new();
	for (; l ;l=l->next) {
		struct meta0_info_s *m0i = l->data;
		addr_info_to_string(&(m0i->addr), str, sizeof(str));
		g_ptr_array_add(tmp, g_strdup_printf("1|meta1|%s|", str));
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

static GError *
_resolve_m1_through_one_m0(const gchar *m0, const guint8 *prefix, gchar ***result)
{
	GError *err = NULL;
	struct addr_info_s ai;

	GRID_TRACE2("%s(%s,%02X%02X)", __FUNCTION__, m0, prefix[0], prefix[1]);
	meta1_strurl_get_address(m0, &ai);

	do {
		GSList *lmap = meta0_remote_get_meta1_one(&ai, 30000, prefix, &err);
		if (!lmap) {
			if (err)
				return err;
			return NEWERROR(500, "No meta1 found");
		}
		else {
			*result = _m0list_to_urlv(lmap);
			g_slist_foreach(lmap, meta0_info_gclean, NULL);
			g_slist_free(lmap);
			err = NULL;
		}
	} while (0);

	return err;
}

static GError *
_resolve_m1_through_many_m0(gchar **urlv, const guint8 *prefix, gchar ***result)
{
	GError *err;
	guint i, last;
	gchar *url;

	GRID_TRACE2("%s(%02X%02X)", __FUNCTION__, prefix[0], prefix[1]);
	for (last=g_strv_length(urlv); last ;last--) {
		/* pick a random URL */
		i = rand() % last;
		url = urlv[i];

		if (!(err = _resolve_m1_through_one_m0(url, prefix, result)))
			return NULL;
		if (err->code < 100)
			g_error_free(err);

		/* swap 'i' and 'last' */
		urlv[i] = urlv[last-1];
		urlv[last-1] = url;
	}

	return NEWERROR(500, "No META0 answered");
}

static GError *
_resolve_meta1(struct hc_resolver_s *r, struct hc_url_s *u, gchar ***result)
{
	struct hashstr_s *hk;
	GError *err = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, hc_url_get(u, HCURL_WHOLE));

	hk = hashstr_printf("meta1|%s|%.4s",
			hc_url_get(u, HCURL_NSPHYS),
			hc_url_get(u, HCURL_HEXID));

	/* Try to hit the cache */
	if (!(*result = hc_resolver_get_cached(r, hk))) {
		/* get a meta0, then store it in the cache */
		gchar **m0urlv = NULL;

		err = _resolve_meta0(r, hc_url_get(u, HCURL_NSPHYS), &m0urlv);
		if (err != NULL)
			g_prefix_error(&err, "M0 resolution error: ");
		else {
			err = _resolve_m1_through_many_m0(m0urlv, hc_url_get_id(u), result);
			if (!err)
				hc_resolver_store(r, hk, *result, 180);
			g_strfreev(m0urlv);
		}
	}

	g_free(hk);
	return err;
}

/* ------------------------------------------------------------------------- */

static GError *
_resolve_service_through_one_m1(const gchar *m1, struct hc_url_s *u,
		const gchar *s, gchar ***result)
{
	GError *err = NULL;
	struct addr_info_s ai;

	GRID_TRACE2("%s(%s,%s,%s)", __FUNCTION__, m1, hc_url_get(u, HCURL_WHOLE), s);
	meta1_strurl_get_address(m1, &ai);

	*result = meta1v2_remote_list_reference_services(&ai, &err,
			hc_url_get(u, HCURL_NS), hc_url_get_id(u), s, 30.0, 300.0);

	return err;
}

static GError *
_resolve_service_through_many_meta1(gchar **urlv, struct hc_url_s *u,
		const gchar *s, gchar ***result)
{
	GError *err;
	guint i, last;
	gchar *url;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, hc_url_get(u, HCURL_WHOLE), s);

	for (last=g_strv_length(urlv); last ;last--) {
		/* pick a random URL */
		i = rand() % last;
		url = urlv[i];

		if (!(err = _resolve_service_through_one_m1(url, u, s, result)))
			return NULL;
		if (err->code < 100)
			g_error_free(err);

		/* swap 'i' and 'last' */
		urlv[i] = urlv[last-1];
		urlv[last-1] = url;
	}

	return NEWERROR(500, "No META0 answered");
}

static GError*
_resolve_reference_service(struct hc_resolver_s *r, struct hashstr_s *hk,
		struct hc_url_s *u, const gchar *s, gchar ***result)
{
	GError *err;
	gchar **m1urlv = NULL;

	GRID_TRACE2("%s(%s,%s,%s)", __FUNCTION__, hashstr_str(hk),
			hc_url_get(u, HCURL_WHOLE), s);

	/* Try to hit the cache for the service itself */
	*result = hc_resolver_get_cached(r, hk);
	if (NULL != *result)
		return NULL;

	/* now attempt a real resolution */
	if (NULL != (err = _resolve_meta1(r, u, &m1urlv)))
		return err;

	err = _resolve_service_through_many_meta1(m1urlv, u, s, result);
	if (!err) {
		/* fill the cache */
		if (!(r->flags & HC_RESOLVER_NOCACHE))
			hc_resolver_store(r, hk, *result, 60);
	}

	g_strfreev(m1urlv);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
hc_resolve_reference_service(struct hc_resolver_s *r, struct hc_url_s *url,
		const gchar *srvtype, gchar ***result)
{
	GError *err;
	struct hashstr_s *hk;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, hc_url_get(url, HCURL_WHOLE), srvtype);
	g_assert(r != NULL);
	g_assert(url != NULL);
	g_assert(srvtype != NULL);
	g_assert(result != NULL);
	g_assert(hc_url_get_id(url) != NULL);
	g_assert(hc_url_has(url, HCURL_NS));

	hk = hashstr_printf("%s|%s|%s", srvtype,
			hc_url_get(url, HCURL_NSPHYS),
			hc_url_get(url, HCURL_HEXID));
	err = _resolve_reference_service(r, hk, url, srvtype, result);
	g_free(hk);

	return err;
}

void
hc_decache_reference_service(struct hc_resolver_s *r, struct hc_url_s *url,
		const gchar *srvtype)
{
	struct hashstr_s *hk;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, hc_url_get(url, HCURL_WHOLE), srvtype);
	g_assert(r != NULL);
	g_assert(url != NULL);
	g_assert(srvtype != NULL);

	if (!r->cache || r->flags & HC_RESOLVER_NOCACHE)
		return;

	hk = hashstr_printf("meta0|%s", hc_url_get(url, HCURL_NSPHYS));
	hc_resolver_forget(r, hk);
	g_free(hk);

	hk = hashstr_printf("meta1|%s|%.4s", hc_url_get(url, HCURL_NSPHYS),
			hc_url_get(url, HCURL_HEXID));
	hc_resolver_forget(r, hk);
	g_free(hk);

	hk = hashstr_printf("%s|%s|%s", srvtype,
			hc_url_get(url, HCURL_NSPHYS),
			hc_url_get(url, HCURL_HEXID));
	hc_resolver_forget(r, hk);
	g_free(hk);
}

