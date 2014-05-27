#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.resolve"
#endif

#include <stddef.h>
#include <stdlib.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <meta0v2/meta0_remote.h>
#include <meta1v2/meta1_remote.h>
#include <resolver/hc_resolver_internals.h>

#include <glib.h>

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

static struct cached_element_s*
hc_resolver_element_create(gchar **value)
{
	gsize s;
	struct cached_element_s *elt;

	g_assert(value != NULL);

	s = offsetof(struct cached_element_s, s) + _strv_total_length(value);

	elt = g_malloc(s);
	elt->use = 0;
	elt->count_elements = g_strv_length(value);
	_strv_concat(elt->s, value);

	return elt;
}

/* Public API -------------------------------------------------------------- */

struct hc_resolver_s*
hc_resolver_create1(time_t now)
{
	struct hc_resolver_s *resolver = g_malloc0(sizeof(struct hc_resolver_s));

	resolver->csm0.max = HC_RESOLVER_DEFAULT_MAX_CSM0;
	resolver->csm0.ttl = HC_RESOLVER_DEFAULT_TTL_CSM0;
	resolver->csm0.cache = lru_tree_create((GCompareFunc)hashstr_quick_cmp,
			g_free, g_free, 0);

	resolver->services.max = HC_RESOLVER_DEFAULT_MAX_SERVICES;
	resolver->services.ttl = HC_RESOLVER_DEFAULT_TTL_SERVICES;
	resolver->services.cache = lru_tree_create((GCompareFunc)hashstr_quick_cmp,
			g_free, g_free, 0);

	resolver->bogonow = now;
	resolver->lock = g_mutex_new();
	return resolver;
}

struct hc_resolver_s*
hc_resolver_create(void)
{
	return hc_resolver_create1(time(0));
}

void
hc_resolver_destroy(struct hc_resolver_s *r)
{
	if (!r)
		return;
	if (r->csm0.cache)
		lru_tree_destroy(r->csm0.cache);
	if (r->services.cache)
		lru_tree_destroy(r->services.cache);
	if (r->lock)
		g_mutex_free(r->lock);
	g_free(r);
}

static gchar**
hc_resolver_get_cached(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *k)
{
	gchar **result = NULL;
	struct cached_element_s *elt;

	g_mutex_lock(r->lock);
	if (NULL != (elt = lru_tree_get(lru, k))) {
		if (!(r->flags & HC_RESOLVER_NOATIME))
			elt->use = r->bogonow;
		result = hc_resolver_element_extract(elt);
	}
	g_mutex_unlock(r->lock);

	return result;
}

static void
hc_resolver_store(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *key, gchar **v)
{
	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	struct cached_element_s *elt = hc_resolver_element_create(v);
	struct hashstr_s *k = hashstr_dup(key);

	g_mutex_lock(r->lock);
	elt->use = r->bogonow;
	lru_tree_insert(lru, k, elt);
	g_mutex_unlock(r->lock);
}

static inline void
hc_resolver_forget(struct hc_resolver_s *r, struct lru_tree_s *lru,
		const struct hashstr_s *k)
{
	if (lru) {
		g_mutex_lock(r->lock);
		lru_tree_remove(lru, k);
		g_mutex_unlock(r->lock);
	}
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
	if (!(*result = hc_resolver_get_cached(r, r->csm0.cache, hk))) {
		GSList *allm0;

		/* Now attempt a real resolution */
		if (!(allm0 = list_namespace_services2(ns, "meta0", &err))) {
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
			hc_resolver_store(r, r->csm0.cache, hk, *result);
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
	if (!(*result = hc_resolver_get_cached(r, r->csm0.cache, hk))) {
		/* get a meta0, then store it in the cache */
		gchar **m0urlv = NULL;

		err = _resolve_meta0(r, hc_url_get(u, HCURL_NSPHYS), &m0urlv);
		if (err != NULL)
			g_prefix_error(&err, "M0 resolution error: ");
		else {
			err = _resolve_m1_through_many_m0(m0urlv, hc_url_get_id(u), result);
			if (!err)
				hc_resolver_store(r, r->csm0.cache, hk, *result);
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
	guint i, last;
	gchar *url;

	GRID_TRACE2("%s(%s,%s)", __FUNCTION__, hc_url_get(u, HCURL_WHOLE), s);

	for (last=g_strv_length(urlv); last ;last--) {
		/* pick a random URL */
		i = rand() % last;
		url = urlv[i];

		GError *err = _resolve_service_through_one_m1(url, u, s, result);
		g_assert((err!=NULL) ^ (*result!=NULL));

		if (!err)
			return NULL;
		if (err->code >= 100)
			return err;
		g_clear_error(&err);

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
	*result = hc_resolver_get_cached(r, r->services.cache, hk);
	if (NULL != *result) {
		return NULL;
	}

	/* now attempt a real resolution */
	err = _resolve_meta1(r, u, &m1urlv);
	g_assert((err!=NULL) ^ (m1urlv!=NULL));
	if (NULL != err)
		return err;

	err = _resolve_service_through_many_meta1(m1urlv, u, s, result);
	g_assert((err!=NULL) ^ (*result!=NULL));
	if (!err) {
		/* fill the cache */
		if (!(r->flags & HC_RESOLVER_NOCACHE))
			hc_resolver_store(r, r->services.cache, hk, *result);
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
	if (!hc_url_get_id(url) || !hc_url_has(url, HCURL_NS))
		return NEWERROR(400, "Incomplete URL [%s]", hc_url_get(url, HCURL_WHOLE));

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

	if (r->flags & HC_RESOLVER_NOCACHE)
		return;

	hk = hashstr_printf("meta0|%s", hc_url_get(url, HCURL_NSPHYS));
	hc_resolver_forget(r, r->csm0.cache, hk);
	g_free(hk);

	hk = hashstr_printf("meta1|%s|%.4s", hc_url_get(url, HCURL_NSPHYS),
			hc_url_get(url, HCURL_HEXID));
	hc_resolver_forget(r, r->csm0.cache, hk);
	g_free(hk);

	hk = hashstr_printf("%s|%s|%s", srvtype,
			hc_url_get(url, HCURL_NSPHYS),
			hc_url_get(url, HCURL_HEXID));
	hc_resolver_forget(r, r->services.cache, hk);
	g_free(hk);
}

void
hc_resolver_set_now(struct hc_resolver_s *r, time_t now)
{
	g_assert(r != NULL);
	g_mutex_lock(r->lock);
	r->bogonow = now;
	g_mutex_unlock(r->lock);
}

static guint
_resolver_expire(struct lru_tree_s *lru, time_t oldest)
{
	struct cached_element_s *elt = NULL;
	struct hashstr_s *k = NULL;

	guint count = 0;
	while (lru_tree_get_last(lru, (void**)&k, (void**)&elt)) {
		EXTRA_ASSERT(k != NULL);
		EXTRA_ASSERT(elt != NULL);
		if (oldest <= elt->use)
			break;
		lru_tree_steal_last(lru, (void**)&k, (void**)&elt);
		metautils_pfree0(&k, NULL);
		metautils_pfree0(&elt, NULL);
		++ count;
	}
	return count;
}

static guint
_LRU_expire(struct hc_resolver_s *r, struct lru_ext_s *l)
{
	guint count = 0;
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(r->lock);
	if (l->ttl > 0 && l->cache != NULL)
		count = _resolver_expire(l->cache, r->bogonow - l->ttl);
	g_mutex_unlock(r->lock);
	return count;
}

guint
hc_resolver_expire(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return _LRU_expire(r, &r->csm0) + _LRU_expire(r, &r->services);
}

static guint
_resolver_purge(struct lru_tree_s *lru, guint umax)
{
	guint count = 0;

	for (gint64 max = umax; max < lru_tree_count(lru) ;++count) {
		struct cached_element_s *elt = NULL;
		struct hashstr_s *k = NULL;
		lru_tree_steal_last(lru, (void**)&k, (void**)&elt);
		if (k) g_free(k); k = NULL;
		if (elt) g_free(elt); elt = NULL;
	}

	return count;
}

static guint
_LRU_purge(struct hc_resolver_s *r, struct lru_ext_s *l)
{
	guint count = 0;
	g_mutex_lock(r->lock);
	if (l->max > 0 && l->cache != NULL)
		count = _resolver_purge(l->cache, l->max);
	g_mutex_unlock(r->lock);
	return count;
}

guint
hc_resolver_purge(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	return _LRU_purge(r, &r->csm0) + _LRU_purge(r, &r->services);
}

static void
_lru_flush(struct lru_tree_s *lru)
{
	if (!lru)
		return;

	struct cached_element_s *elt = NULL;
	struct hashstr_s *k = NULL;

	while (lru_tree_get_last(lru, (void**)&k, (void**)&elt)) {
		lru_tree_steal_last(lru, (void**)&k, (void**)&elt);
		if (k) g_free(k); k = NULL;
		if (elt) g_free(elt); elt = NULL;
	}
}

void
hc_resolver_flush_csm0(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(r->lock);
	_lru_flush(r->csm0.cache);
	g_mutex_unlock(r->lock);
}

void
hc_resolver_flush_services(struct hc_resolver_s *r)
{
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(r->lock);
	_lru_flush(r->services.cache);
	g_mutex_unlock(r->lock);
}

static inline void
_LRU_set_max(struct lru_ext_s *l, guint v) { if (l) l->max = v; }

static inline void
_LRU_set_ttl(struct lru_ext_s *l, time_t v) { if (l) l->ttl = v; }

void
hc_resolver_set_max_services(struct hc_resolver_s *r, guint d)
{
	if (r)
		_LRU_set_max(&r->services, d);
}

void
hc_resolver_set_ttl_services(struct hc_resolver_s *r, time_t d)
{
	if (r)
		_LRU_set_ttl(&r->services, d);
}

void
hc_resolver_set_max_csm0(struct hc_resolver_s *r, guint d)
{
	if (r)
		_LRU_set_max(&r->csm0, d);
}

void
hc_resolver_set_ttl_csm0(struct hc_resolver_s *r, time_t d)
{
	if (r)
		_LRU_set_ttl(&r->csm0, d);
}

void
hc_resolver_info(struct hc_resolver_s *r, struct hc_resolver_stats_s *s)
{
	EXTRA_ASSERT(s != NULL);
	EXTRA_ASSERT(r != NULL);
	g_mutex_lock(r->lock);
	s->clock = r->bogonow;
	s->csm0.max = r->csm0.max;
	s->csm0.ttl = r->csm0.ttl;
	s->csm0.count = lru_tree_count(r->csm0.cache);
	s->services.max = r->services.max;
	s->services.ttl = r->services.ttl;
	s->services.count = lru_tree_count(r->services.cache);
	g_mutex_unlock(r->lock);
}

