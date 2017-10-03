/*
OpenIO SDS resolver
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

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <resolver/resolver_variables.h>

#include <cluster/lib/gridcluster.h>
#include <meta0v2/meta0_remote.h>
#include <meta1v2/meta1_remote.h>
#include <resolver/hc_resolver_internals.h>

/* Packing */
static void
_strv_concat(register gchar *d, const char * const *src)
{
	const char *s;
	while (NULL != (s = *(src++))) {
		register char c;
		do {
			*(d++) = (c = *(s++));
		} while (c);
	}
}

/* Unpacking */
static void
_strv_pointers(gchar **dst, gchar *src, guint count)
{
	while (count--) {
		register gsize s = strlen(src) + 1;
		*(dst++) = g_memdup(src, s);
		src += s;
	}
}

static gchar **
hc_resolver_element_extract(struct cached_element_s *elt)
{
	if (!elt)
		return NULL;

	gchar **result = g_malloc((elt->count_elements + 1) * sizeof(gchar*));
	_strv_pointers(result, elt->s, elt->count_elements);
	result[elt->count_elements] = NULL;

	return result;
}

static struct cached_element_s*
hc_resolver_element_create (const char * const *value)
{
	gsize s;
	struct cached_element_s *elt;

	EXTRA_ASSERT(value != NULL);

	s = offsetof(struct cached_element_s, s) + oio_strv_length_total(value);

	elt = g_malloc(s);
	elt->count_elements = oio_strv_length(value);
	_strv_concat(elt->s, value);

	return elt;
}

/* Public API -------------------------------------------------------------- */

struct hc_resolver_s*
hc_resolver_create(void)
{
	struct hc_resolver_s *resolver = g_malloc0(sizeof(struct hc_resolver_s));

	resolver->csm0 = lru_tree_create((GCompareFunc)hashstr_quick_cmp,
			g_free, g_free, 0);

	resolver->services = lru_tree_create((GCompareFunc)hashstr_quick_cmp,
			g_free, g_free, 0);

	g_mutex_init(&resolver->lock);
	return resolver;
}

void
hc_resolver_configure (struct hc_resolver_s *r, enum hc_resolver_flags_e f)
{
	g_assert (r != NULL);
	r->flags = f;
}

void
hc_resolver_qualify (struct hc_resolver_s *r,
		gboolean (*qualify) (gconstpointer))
{
	g_assert (r != NULL);
	g_assert (qualify != NULL);
	r->service_qualifier = qualify;
}

void
hc_resolver_notify (struct hc_resolver_s *r,
		void (*notify) (gconstpointer))
{
	g_assert (r != NULL);
	g_assert (notify != NULL);
	r->service_notifier = notify;
}

void
hc_resolver_destroy(struct hc_resolver_s *r)
{
	if (!r)
		return;
	if (r->csm0)
		lru_tree_destroy(r->csm0);
	if (r->services)
		lru_tree_destroy(r->services);
	g_mutex_clear(&r->lock);
	g_free(r);
}

static gchar **
hc_resolver_get_cached(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *k)
{
	gchar **result = NULL;
	struct cached_element_s *elt;

	g_mutex_lock(&r->lock);
	if (NULL != (elt = lru_tree_get(lru, k)))
		result = hc_resolver_element_extract(elt);
	g_mutex_unlock(&r->lock);

	return result;
}

static void
hc_resolver_store(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *key, const char * const *v)
{
	if (!v || !*v)
		return;
	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	struct cached_element_s *elt = hc_resolver_element_create(v);
	struct hashstr_s *k = hashstr_dup(key);

	g_mutex_lock(&r->lock);
	lru_tree_insert(lru, k, elt);
	g_mutex_unlock(&r->lock);
}

static void
hc_resolver_forget(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *k)
{
	if (lru) {
		g_mutex_lock(&r->lock);
		lru_tree_remove(lru, k);
		g_mutex_unlock(&r->lock);
	}
}

/* ------------------------------------------------------------------------- */

static struct hashstr_s *
_m0_key (const char *ns)
{
	return hashstr_printf("0|%s", ns);
}

static struct hashstr_s *
_m1_key (struct oio_url_s *u)
{
	return hashstr_printf("1|%.4s|%s", oio_url_get(u, OIOURL_HEXID),
			oio_url_get(u, OIOURL_NS));
}

static struct hashstr_s *
_srv_key (const char *srvtype, struct oio_url_s *u)
{
	return hashstr_printf("%s|%s|%s", srvtype, oio_url_get(u, OIOURL_HEXID),
			oio_url_get(u, OIOURL_NS));
}

static gchar **
_srvlist_to_urlv(GSList *l)
{
	gchar str[64];
	GPtrArray *tmp;

	tmp = g_ptr_array_new();
	for (; l ;l=l->next) {
		struct service_info_s *si = l->data;
		grid_addrinfo_to_string(&(si->addr), str, sizeof(str));
		g_ptr_array_add(tmp, g_strdup_printf("1|%s|%s|", si->type, str));
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar **) g_ptr_array_free(tmp, FALSE);
}

static GError*
_resolve_meta0(struct hc_resolver_s *r, const char *ns, gchar ***result)
{
	struct hashstr_s *hk;
	GError *err = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, ns);
	hk = _m0_key(ns);

	/* Try to hit the cache */
	if (!(*result = hc_resolver_get_cached(r, r->csm0, hk))) {
		GSList *allm0;

		/* Now attempt a real resolution */
		err = conscience_get_services (ns, NAME_SRVTYPE_META0, FALSE, &allm0);
		if (!allm0 || err) {
			if (!err)
				err = NEWERROR(CODE_INTERNAL_ERROR, "No meta0 available");
			*result = NULL;
		}
		else {
			*result = _srvlist_to_urlv(allm0);
			g_slist_foreach(allm0, service_info_gclean, NULL);
			g_slist_free(allm0);
			allm0 = NULL;

			/* then fill the cache */
			hc_resolver_store(r, r->csm0, hk,
					(const char * const *) *result);
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
		grid_addrinfo_to_string(&(m0i->addr), str, sizeof(str));
		g_ptr_array_add(tmp, g_strdup_printf("1|%s|%s|", NAME_SRVTYPE_META1, str));
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar **) g_ptr_array_free(tmp, FALSE);
}

static GError *
_resolve_m1_through_one_m0(const char *m0, const guint8 *prefix, gchar ***result)
{
	GError *err = NULL;

	GRID_TRACE2("%s(%s,%02X%02X)", __FUNCTION__, m0, prefix[0], prefix[1]);
	gchar *url = meta1_strurl_get_address(m0);
	STRING_STACKIFY(url);

	do {
		GSList *lmap = NULL;
		err = meta0_remote_get_meta1_one(url, prefix, &lmap);
		if (err)
			return err;
		*result = _m0list_to_urlv(lmap);
		g_slist_foreach(lmap, meta0_info_gclean, NULL);
		g_slist_free(lmap);
	} while (0);

	return err;
}

static GError *
_resolve_m1_through_many_m0(struct hc_resolver_s *r, const char * const *urlv,
		const guint8 *prefix, gchar ***result)
{
	GRID_TRACE2("%s(%02X%02X)", __FUNCTION__, prefix[0], prefix[1]);

	if (urlv && *urlv) {
		gsize len = oio_strv_length(urlv);
		if (r->service_qualifier) {
			/* url already contains ip:port, and not meta1_service_url_s */
			gboolean _wrap (gconstpointer p) {
				return r->service_qualifier ((const char*)p);
			}
			len = oio_ext_array_partition ((void**)urlv, len, _wrap);
		}
		if (len > 1 && oio_resolver_dir_shuffle)
			oio_ext_array_shuffle ((void**)urlv, len);
	}

	for (const char * const *purl=urlv; *purl ;++purl) {
		GError *err = _resolve_m1_through_one_m0(*purl, prefix, result);
		EXTRA_ASSERT((err!=NULL) ^ (*result!=NULL));
		if (!err)
			return NULL;
		if (!CODE_IS_NETWORK_ERROR(err->code))
			return err;
		if (r->service_notifier)
			r->service_notifier (*purl);
		g_error_free(err);
	}

	return NEWERROR(CODE_INTERNAL_ERROR, "No META0 answered");
}

static GError *
_resolve_meta1(struct hc_resolver_s *r, struct oio_url_s *u, gchar ***result)
{
	struct hashstr_s *hk;
	GError *err = NULL;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(u, OIOURL_WHOLE));

	hk = _m1_key (u);

	/* Try to hit the cache */
	if (!(*result = hc_resolver_get_cached(r, r->csm0, hk))) {
		/* get a meta0, then store it in the cache */
		gchar **m0urlv = NULL;

		err = _resolve_meta0(r, oio_url_get(u, OIOURL_NS), &m0urlv);
		if (err != NULL)
			g_prefix_error(&err, "M0 resolution error: ");
		else {
			err = _resolve_m1_through_many_m0(r, (const char * const *)m0urlv,
					oio_url_get_id(u), result);
			if (!err)
				hc_resolver_store(r, r->csm0, hk,
						(const char * const *) *result);
			g_strfreev(m0urlv);
		}
	}

	g_free(hk);
	return err;
}

/* ------------------------------------------------------------------------- */

static GError *
_resolve_service_through_many_meta1(struct hc_resolver_s *r,
		const char * const *urlv, struct oio_url_s *u, const char *s,
		gchar ***result)
{
	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, oio_url_get(u, OIOURL_WHOLE), s);

	if (urlv && *urlv) {
		gsize len = oio_strv_length (urlv);
		if (r->service_qualifier) {
			/* we must the callback because our array contains packed URL */
			gboolean _wrap (gconstpointer p) {
				gchar *m1u = meta1_strurl_get_address ((const char*)p);
				STRING_STACKIFY (m1u);
				return r->service_qualifier (m1u);
			}
			len = oio_ext_array_partition ((void**)urlv, len, _wrap);
		}
		if (len > 1 && oio_resolver_dir_shuffle)
			oio_ext_array_shuffle ((void**)urlv, len);
	}

	for (const char * const *purl=urlv; *purl ;++purl) {

		gchar *m1 = meta1_strurl_get_address(*purl);
		GError *err = meta1v2_remote_list_reference_services(m1, u, s, result);
		if (err && CODE_IS_NETWORK_ERROR(err->code) && r->service_notifier)
			r->service_notifier (m1);
		g_free0(m1);

		if (!err)
			return NULL;
		if (!CODE_IS_NETWORK_ERROR(err->code))
			return err;
		g_clear_error(&err);
	}

	return NEWERROR(CODE_INTERNAL_ERROR, "No META0 answered");
}

static GError*
_resolve_reference_service(struct hc_resolver_s *r, struct hashstr_s *hk,
		struct oio_url_s *u, const char *s, gchar ***result)
{
	GError *err;
	gchar **m1urlv = NULL;

	GRID_TRACE2("%s(%s,%s,%s)", __FUNCTION__, hashstr_str(hk),
			oio_url_get(u, OIOURL_WHOLE), s);

	/* Try to hit the cache for the service itself */
	*result = hc_resolver_get_cached(r, r->services, hk);
	if (NULL != *result) {
		return NULL;
	}

	/* now attempt a real resolution */
	err = _resolve_meta1(r, u, &m1urlv);
	EXTRA_ASSERT((err!=NULL) ^ (m1urlv!=NULL));
	if (NULL != err)
		return err;

	err = _resolve_service_through_many_meta1(r, (const char * const *)m1urlv,
			u, s, result);
	EXTRA_ASSERT((err!=NULL) ^ (*result!=NULL));
	if (!err) {
		/* fill the cache */
		hc_resolver_store(r, r->services, hk,
				(const char * const *) *result);
	}

	g_strfreev(m1urlv);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
hc_resolve_reference_directory(struct hc_resolver_s *r, struct oio_url_s *url,
		gchar ***result)
{
	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(r != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(result != NULL);
	if (!oio_url_get_id(url) || !oio_url_has(url, OIOURL_NS))
		return BADREQ("Incomplete URL [%s]", oio_url_get(url, OIOURL_WHOLE));

	GError *err = NULL;
	gchar **m1v = NULL, **m0v = NULL;

	if (!(err = _resolve_meta0(r, oio_url_get(url, OIOURL_NS), &m0v)))
		err = _resolve_meta1(r, url, &m1v);

	if (err) {
		if (m0v) g_strfreev (m0v);
		if (m1v) g_strfreev (m1v);
		return err;
	}

	*result = g_malloc0(sizeof(gchar*) *
			(g_strv_length(m0v) + g_strv_length(m1v) + 1));
	gchar **d = *result;
	for (gchar **p=m0v; *p ;++p) { *(d++) = *p; }
	g_free (m0v); // pointers reused
	for (gchar **p=m1v; *p ;++p) { *(d++) = *p; }
	g_free (m1v); // pointers reused
	return NULL;
}

GError*
hc_resolve_reference_service(struct hc_resolver_s *r, struct oio_url_s *url,
		const char *srvtype, gchar ***result)
{
	GError *err;
	struct hashstr_s *hk;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE), srvtype);
	EXTRA_ASSERT(r != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(result != NULL);
	EXTRA_ASSERT(*result == NULL);

	if (!oio_url_get_id(url) || !oio_url_has(url, OIOURL_NS))
		return BADREQ("Incomplete URL [%s]", oio_url_get(url, OIOURL_WHOLE));

	hk = _srv_key (srvtype, url);
	err = _resolve_reference_service(r, hk, url, srvtype, result);
	g_free(hk);

	if (*result && oio_resolver_srv_shuffle)
		oio_ext_array_shuffle ((void**)*result, g_strv_length(*result));
	return err;
}

void
hc_decache_reference(struct hc_resolver_s *r, struct oio_url_s *url)
{
	struct hashstr_s *hk;

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE));
	EXTRA_ASSERT(r != NULL);
	EXTRA_ASSERT(url != NULL);

	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	if (r->flags & HC_RESOLVER_DECACHEM0) {
		hk = _m0_key (oio_url_get(url, OIOURL_NS));
		hc_resolver_forget(r, r->csm0, hk);
		g_free(hk);
	}

	hk = _m1_key (url);
	hc_resolver_forget(r, r->csm0, hk);
	g_free(hk);
}

void
hc_decache_reference_service(struct hc_resolver_s *r, struct oio_url_s *url,
		const char *srvtype)
{
	struct hashstr_s *hk;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, oio_url_get(url, OIOURL_WHOLE), srvtype);
	EXTRA_ASSERT(r != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);

	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	hk = _srv_key (srvtype, url);
	hc_resolver_forget(r, r->services, hk);
	g_free(hk);
}

static guint
_LRU_expire(struct hc_resolver_s *r, struct lru_tree_s *l, gint64 ttl)
{
	EXTRA_ASSERT(r != NULL);
	guint count = 0;
	g_mutex_lock(&r->lock);
	const gint64 now = oio_ext_monotonic_time();
	if (ttl > 0)
		count = lru_tree_remove_older(l, OLDEST(now, ttl));
	g_mutex_unlock(&r->lock);
	return count;
}

guint
hc_resolver_expire(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return _LRU_expire(r, r->csm0, oio_resolver_m0cs_default_ttl)
		+ _LRU_expire(r, r->services, oio_resolver_srv_default_ttl);
}

void
hc_resolver_tell (struct hc_resolver_s *r, struct oio_url_s *url,
		const char *srvtype, const char * const *urlv)
{
	EXTRA_ASSERT(r != NULL);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(urlv != NULL);

	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	struct hashstr_s *hk = _srv_key (srvtype, url);
	hc_resolver_store (r, r->services, hk, urlv);
	g_free (hk);
}

static guint
_LRU_purge(struct hc_resolver_s *r, struct lru_tree_s *l, guint max)
{
	guint count = 0;
	g_mutex_lock(&r->lock);
	if (max > 0)
		count = lru_tree_remove_exceeding(l, max);
	g_mutex_unlock(&r->lock);
	return count;
}

guint
hc_resolver_purge(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return _LRU_purge(r, r->csm0, oio_resolver_m0cs_default_max)
		+ _LRU_purge(r, r->services, oio_resolver_srv_default_max);
}

static void
_lru_flush(struct lru_tree_s *lru)
{
	if (!lru) return;
	lru_tree_remove_exceeding (lru, 0);
}

void
hc_resolver_flush_csm0(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(&r->lock);
	_lru_flush(r->csm0);
	g_mutex_unlock(&r->lock);
}

void
hc_resolver_flush_services(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(&r->lock);
	_lru_flush(r->services);
	g_mutex_unlock(&r->lock);
}

void
hc_resolver_info(struct hc_resolver_s *r, struct hc_resolver_stats_s *s)
{
	EXTRA_ASSERT(s != NULL);
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(&r->lock);
	s->csm0.max = oio_resolver_m0cs_default_max;
	s->csm0.ttl = oio_resolver_m0cs_default_ttl;
	s->csm0.count = lru_tree_count(r->csm0);
	s->services.max = _cache_srv_default_max;
	s->services.ttl = _cache_srv_default_ttl;
	s->services.count = lru_tree_count(r->services);
	g_mutex_unlock(&r->lock);
}

