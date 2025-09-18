/*
OpenIO SDS conscience central server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <math.h>
#include <glob.h>

#include <glib.h>
#include <zmq.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/server_variables.h>
#include <server/network_server.h>
#include <server/transport_gridd.h>

#include "expr.h"
#include <expr.yacc.h>

# define NAME_GROUPNAME_STORAGE_POLICY "STORAGE_POLICY"
# define NAME_GROUPNAME_DATA_SECURITY "DATA_SECURITY"

# define KEY_ALERT_LIMIT "alert_frequency_limit"
# define KEY_SCORE_TIMEOUT "score_timeout"
# define KEY_SCORE_EXPR "score_expr"
# define KEY_PUT_SCORE_EXPR "put_score_expr"
# define KEY_GET_SCORE_EXPR "get_score_expr"
# define KEY_SCORE_VARBOUND "score_variation_bound"
# define KEY_SCORE_LOCK "lock_at_first_register"
# define KEY_POOL_TARGETS "targets"

# define GROUP_PREFIX_TYPE "type:"
# define GROUP_PREFIX_POOL "pool:"

# define TIME_DEFAULT_ALERT_LIMIT 300L

# define EXPR_DEFAULT_META0 "100"
# define EXPR_DEFAULT_META1 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_META2 "root(2,((num stat.cpu)*(num stat.io)))"
# define EXPR_DEFAULT_RAWX  "root(3,((num stat.cpu)*(num stat.io)*(num stat.space)))"

static struct network_server_s *server = NULL;
static struct gridd_request_dispatcher_s *dispatcher = NULL;

static struct grid_task_queue_s *gtq_admin = NULL;
static GThread *th_admin = NULL;

static struct namespace_info_s *nsinfo = NULL;
static GByteArray *nsinfo_cache = NULL;

static gchar *service_url = NULL;
static gchar *hub_me = NULL;
static gchar *hub_group = NULL;
static gint hub_publish_stale_delay = 0;
static gint hub_startup_delay = 0;
static gint hub_threads = 0;
static gint hub_group_size = 0;
static gchar *path_stgpol = NULL;
static gchar *path_srvcfg = NULL;

static GRWLock rwlock_srv = {};
static GTree *srvtypes = NULL;

static gboolean flag_serialize_srvinfo_stats = FALSE;
static gboolean flag_serialize_srvinfo_tags = TRUE;
static gboolean flush_stats_on_refresh = FALSE;

static gboolean config_system = TRUE;
static GSList *config_paths = NULL;

static GMutex persistence_lock = {0};
static GString *persistence_path = NULL;
static time_t persistence_period = 30;
static gboolean synchronize_at_startup = FALSE;

static const guint8 header[] = { 0x30, 0x80 };
static const guint8 footer[] = { 0x00, 0x00 };

static GQuark gq_count_hub_flush = 0;
static GQuark gq_time_hub_flush = 0;
static GQuark gq_count_hub_remove = 0;
static GQuark gq_lag_hub_remove = 0;
static GQuark gq_time_hub_remove = 0;
static GQuark gq_count_hub_update = 0;
static GQuark gq_lag_hub_update = 0;
static GQuark gq_time_hub_update = 0;

/** Hold a serialized version of the list of services of each type. */
static gboolean cache_service_lists = FALSE;
static gboolean cache_full_service_lists = FALSE;
static GMutex srv_lists_lock = {0};
static GHashTable *srv_list_cache = NULL;
static GHashTable *full_srv_list_cache = NULL;
static GThread *srv_cache_thread = NULL;
static gint64 srv_cache_interval = 250 * G_TIME_SPAN_MILLISECOND;

static gchar *statsd_host = NULL;
static gint statsd_port = 8125;

/* ------------------------------------------------------------------------- */

# ifndef LIMIT_LENGTH_SRVDESCR
#  define LIMIT_LENGTH_SRVDESCR (LIMIT_LENGTH_SRVTYPE + 1 + STRLEN_ADDRINFO)
# endif

# ifndef LIMIT_LENGTH_SERVICE_ID
#  define LIMIT_LENGTH_SERVICE_ID (36 + 1)
# endif

struct conscience_srv_s {
	addr_info_t addr;

	struct conscience_srvtype_s *srvtype;
	GPtrArray *tags;
	GByteArray *cache;

	score_t put_score;
	score_t get_score;
	time_t time_last_alert;
	gboolean put_locked;
	gboolean get_locked;

	time_t tags_mtime;
	time_t lock_mtime;

	/*a ring by service type */
	struct conscience_srv_s *next;
	struct conscience_srv_s *prev;

	gchar description[LIMIT_LENGTH_SRVDESCR];
	gchar service_id[LIMIT_LENGTH_SERVICE_ID];
};

enum score_type_e
{
	PUT = 1 << 0,
	GET = 1 << 1,
};

struct conscience_srvtype_s
{
	gchar *put_score_expr_str;
	gchar *get_score_expr_str;
	struct expr_s *put_score_expr;
	struct expr_s *get_score_expr;
	GHashTable *services_ht;  /**<Maps (addr_info_t*) to (conscience_srv_s*)*/

	GRWLock rw_lock;

	time_t alert_frequency_limit;
	time_t score_expiration;
	gint32 score_variation_bound;
	gboolean lock_at_first_register;

	struct conscience_srv_s services_ring;

	gchar type_name[LIMIT_LENGTH_SRVTYPE];
};

typedef gboolean (service_callback_f) (struct conscience_srv_s * srv, gpointer udata);

static void
conscience_srv_clear_tags(struct conscience_srv_s *service)
{
	while (service->tags->len > 0) {
		struct service_tag_s *tag = g_ptr_array_index(service->tags, 0);
		service_tag_destroy(tag);
		g_ptr_array_remove_index_fast(service->tags, 0);
	}
}

static void
conscience_srv_destroy(struct conscience_srv_s *service)
{
	if (!service)
		return;

	/* free the tags */
	if (service->tags) {
		conscience_srv_clear_tags(service);
		g_ptr_array_free(service->tags, TRUE);
	}

	if (service->cache) {
		GByteArray *gba = service->cache;
		service->cache = NULL;
		g_byte_array_unref(gba);
	}

	/*remove from the ring */
	if (service->prev)
		service->prev->next = service->next;
	if (service->next)
		service->next->prev = service->prev;

	/*cleans the structure */
	g_free(service);
}

static gboolean
conscience_srv_compute_score(struct conscience_srv_s *service, enum score_type_e score_type)
{
	struct conscience_srvtype_s *srvtype;

	gchar *getField(const char *b, const char *f) {
		EXTRA_ASSERT(f != NULL);
		char str_name[128];
		g_snprintf(str_name,sizeof(str_name),"%s.%s", b, f);
		struct service_tag_s *pTag = service_info_get_tag(service->tags, str_name);
		if (!pTag) {
			GRID_DEBUG("[%s/%s/] Undefined tag wanted: %s", nsinfo->name, srvtype->type_name, f);
			return NULL;
		}
		switch (pTag->type) {
		case STVT_I64:
			return g_strdup_printf("%"G_GINT64_FORMAT, pTag->value.i);
		case STVT_REAL:
			return g_strdup_printf("%f", pTag->value.r);
		case STVT_BOOL:
			return g_strdup_printf("%d", pTag->value.b ? 1 : 0);
		case STVT_STR:
			return g_strdup(pTag->value.s);
		case STVT_BUF:
			return g_strdup(pTag->value.buf);
		}
		GRID_DEBUG("[%s/%s/] invalid tag value: %s", nsinfo->name, srvtype->type_name, f);
		return NULL;
	}
	gchar *getStat(const char *f) { return getField("stat", f); }
	gchar *getTag(const char *f) { return getField("tag", f); }
	accessor_f *getAcc(const char *b) {
		EXTRA_ASSERT(b != NULL);
		switch (*b) {
			case 's':
				if (!strcmp(b, "stat"))
					return getStat;
				return NULL;
			case 't':
				if (!strcmp(b, "tag"))
					return getTag;
				/* FALLTHROUGH */
			default:
				return NULL;
		}
	}

	gboolean compute_score(gint32 *pResult, struct expr_s *pExpr, gint32 old_score)
	{
		EXTRA_ASSERT(pExpr != NULL);
		gdouble d = 0.0;
		if (expr_evaluate(&d, pExpr, getAcc))
			return FALSE;

		gint32 current = isnan(d) ? 0 : floor(d);

		if (old_score >= 0) {
			if (srvtype->score_variation_bound > 0) {
				gint32 max = old_score + srvtype->score_variation_bound;
				current = MIN(current,max);
			}
		}
		*pResult = CLAMP(current, 0, 100);
		return TRUE;
	}


	EXTRA_ASSERT(service != NULL);
	srvtype = service->srvtype;
	EXTRA_ASSERT(srvtype != NULL);

	gboolean ret = TRUE;
	if (score_type & PUT && !service->put_locked) {
		ret = compute_score(&service->put_score.value, srvtype->put_score_expr, service->put_score.value);
	}
	if (score_type & GET && !service->get_locked) {
		ret &= compute_score(&service->get_score.value, srvtype->get_score_expr, service->get_score.value);
	}
	return ret;
}

static void
conscience_srv_fill_srvinfo_header(struct service_info_s *dst,
		struct conscience_srv_s *src)
{
	EXTRA_ASSERT(src != NULL);
	EXTRA_ASSERT(src->srvtype != NULL);
	EXTRA_ASSERT(dst != NULL);
	EXTRA_ASSERT(sizeof(dst->type) == sizeof(src->srvtype->type_name));

	memcpy(&dst->addr, &src->addr, sizeof(addr_info_t));
	memcpy(&dst->put_score, &src->put_score, sizeof(score_t));
	memcpy(&dst->get_score, &src->get_score, sizeof(score_t));
	g_strlcpy(dst->type, src->srvtype->type_name, sizeof(dst->type));
	g_strlcpy(dst->ns_name, oio_server_namespace, sizeof(dst->ns_name));
}

static void
conscience_srv_fill_srvinfo(struct service_info_s *dst,
		struct conscience_srv_s *src)
{
	EXTRA_ASSERT(dst != NULL);
	EXTRA_ASSERT(src != NULL);
	conscience_srv_fill_srvinfo_header(dst, src);
	dst->tags = service_info_copy_tags(src->tags);
}

#define conscience_srv_clean_udata(srv) do { \
	if (srv->cache) g_byte_array_unref(srv->cache); \
	srv->cache = NULL; \
} while (0)

static GByteArray *
_conscience_srv_serialize(struct conscience_srv_s *srv)
{
	GPtrArray *tags = NULL;

	/* prepare the srvinfo */
	struct service_info_s *si = g_alloca(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);

	if ((!flag_serialize_srvinfo_stats && !flag_serialize_srvinfo_tags)
			|| !si->tags || si->tags->len <= 0) {
		/* ignore all the tags */
		tags = si->tags;
		si->tags = NULL;
	} else if (flag_serialize_srvinfo_stats ^ flag_serialize_srvinfo_tags) {
		/* filter the tags */
		guint u;
		for (u=0; u < si->tags->len ;) {
			struct service_tag_s *tag = si->tags->pdata[u];
			const gboolean _t = !flag_serialize_srvinfo_tags && g_str_has_prefix(tag->name, "tag.");
			const gboolean _s = !flag_serialize_srvinfo_stats && g_str_has_prefix(tag->name, "stat.");
			if (_t || _s) {
				service_tag_destroy(tag);
				g_ptr_array_remove_index_fast(si->tags, u);
			} else {
				u++;
			}
		}
	}

	/* encode it and append to the pending body */
	GByteArray *gba = service_info_marshall_1(si, NULL);
	if (tags)
		si->tags = tags;
	service_info_clean_tags(si);
	return gba;
}

static void
_conscience_srv_prepare_cache(struct conscience_srv_s *srv)
{
	conscience_srv_clean_udata(srv);
	srv->cache = _conscience_srv_serialize(srv);
#ifdef HAVE_ENBUG
	g_usleep(cs_enbug_serialize_delay);
#endif
}

static guint
hash_service_id(gconstpointer p)
{
	return djb_hash_buf(p, sizeof(addr_info_t));
}

static gboolean
conscience_srvtype_set_type_expression(struct conscience_srvtype_s * srvtype,
	GError ** err, const gchar * expr_str, enum score_type_e score_type)
{
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(expr_str != NULL);

	/*replaces the string */
	if (score_type & PUT)
	{
		struct expr_s *pE = NULL;
		if (expr_parse(expr_str, &pE)) {
			GSETCODE(err, CODE_INTERNAL_ERROR,
					"Failed to parse expression '%s'",
					expr_str);
			return FALSE;
		}
		if (srvtype->put_score_expr_str)
			g_free(srvtype->put_score_expr_str);
		if (srvtype->put_score_expr)
			expr_clean(srvtype->put_score_expr);
		srvtype->put_score_expr_str = g_strdup(expr_str);
		srvtype->put_score_expr = pE;
	}
	if (score_type & GET)
	{
		struct expr_s *pE = NULL;
		if (expr_parse(expr_str, &pE)) {
			GSETCODE(err, CODE_INTERNAL_ERROR,
					"Failed to parse expression '%s'",
					expr_str);
			return FALSE;
		}
		if (srvtype->get_score_expr_str)
			g_free(srvtype->get_score_expr_str);
		if (srvtype->get_score_expr)
			expr_clean(srvtype->get_score_expr);
		srvtype->get_score_expr_str = g_strdup(expr_str);
		srvtype->get_score_expr = pE;
	}
	return TRUE;
}

static void
conscience_srvtype_init(struct conscience_srvtype_s *srvtype)
{
	EXTRA_ASSERT(srvtype != NULL);
	conscience_srvtype_set_type_expression(srvtype, NULL, "100", PUT | GET);
	srvtype->alert_frequency_limit = TIME_DEFAULT_ALERT_LIMIT;
	srvtype->score_expiration = 300;
	srvtype->score_variation_bound = 5;
	srvtype->lock_at_first_register = TRUE;
	g_rw_lock_init(&srvtype->rw_lock);
}

static struct conscience_srvtype_s *
conscience_srvtype_create(const char *type)
{
	EXTRA_ASSERT(type != NULL);
	struct conscience_srvtype_s *srvtype = g_malloc0(sizeof(*srvtype));

	conscience_srvtype_init(srvtype);

	srvtype->services_ht = g_hash_table_new_full(hash_service_id,
			addr_info_equal, NULL, NULL);

	if (type)
		g_strlcpy(srvtype->type_name, type, sizeof(srvtype->type_name));
	srvtype->services_ring.next = &(srvtype->services_ring);
	srvtype->services_ring.prev = &(srvtype->services_ring);
	return srvtype;
}

static void
conscience_srvtype_flush(struct conscience_srvtype_s *srvtype)
{
	EXTRA_ASSERT(srvtype != NULL);

	g_hash_table_steal_all(srvtype->services_ht);

	guint counter = 0;
	const struct conscience_srv_s *beacon = &(srvtype->services_ring);
	struct conscience_srv_s *cur, *nxt;
	for (cur = beacon->next; cur && cur != beacon; cur = nxt) {
		nxt = cur->next;
		conscience_srv_destroy(cur);
		counter++;
	}

	GRID_DEBUG("Service type [%s] flushed, [%u] services removed",
		srvtype->type_name, counter);
}

static void
conscience_srvtype_destroy(struct conscience_srvtype_s *srvtype)
{
	if (!srvtype)
		return;

	conscience_srvtype_flush(srvtype);

	if (srvtype->services_ht)
		g_hash_table_destroy(srvtype->services_ht);
	if (srvtype->put_score_expr)
		expr_clean(srvtype->put_score_expr);
	if (srvtype->put_score_expr_str) {
		*(srvtype->put_score_expr_str) = '\0';
		g_free(srvtype->put_score_expr_str);
	}
	if (srvtype->get_score_expr)
		expr_clean(srvtype->get_score_expr);
	if (srvtype->get_score_expr_str) {
		*(srvtype->get_score_expr_str) = '\0';
		g_free(srvtype->get_score_expr_str);
	}

	g_rw_lock_clear(&srvtype->rw_lock);
	g_free(srvtype);
}

static void
conscience_srvtype_remove_srv(struct conscience_srvtype_s *srvtype,
		const addr_info_t *srvid, time_t mtime)
{
	struct conscience_srv_s *srv = g_hash_table_lookup(srvtype->services_ht, srvid);
	if (srv) {
		if (mtime) {
			if (srv->lock_mtime > mtime || srv->tags_mtime > mtime) {
				// The service has been re-registered
				return;
			}
		}

		g_hash_table_remove(srvtype->services_ht, srvid);
		srv->prev->next = srv->next;
		srv->next->prev = srv->prev;
		srv->next = srv->prev = NULL;
		conscience_srv_destroy(srv);
	}
}

static struct conscience_srv_s *
conscience_srvtype_register_srv(struct conscience_srvtype_s *srvtype,
		const addr_info_t *srvid)
{
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(srvid != NULL);

	struct conscience_srv_s *service = g_malloc0(sizeof(struct conscience_srv_s));
	memcpy(&(service->addr), srvid, sizeof(addr_info_t));
	service->tags_mtime = 0;
	service->tags = g_ptr_array_new();
	service->lock_mtime = 0;
	service->put_locked = FALSE;
	service->put_score.timestamp = 0;
	service->put_score.value = -1;
	service->get_locked = FALSE;
	service->get_score.timestamp = 0;
	service->get_score.value = -1;
	service->srvtype = srvtype;

	/*build the service description once for all*/
	gsize desc_size = g_snprintf(service->description, sizeof(service->description),
			"%s/", srvtype->type_name);
	grid_addrinfo_to_string(&service->addr,
		service->description+desc_size, sizeof(service->description)-desc_size);

	/*register the service with its ID*/
	g_hash_table_insert(srvtype->services_ht, &service->addr, service);

	/*ring insertion */
	srvtype->services_ring.next->prev = service;
	service->prev = &(srvtype->services_ring);

	service->next = srvtype->services_ring.next;
	srvtype->services_ring.next = service;

	return service;
}

static guint
conscience_srvtype_zero_expired(struct conscience_srvtype_s * srvtype,
		service_callback_f *callback, gpointer u)
{
	EXTRA_ASSERT(srvtype);

	guint count = 0U;

	time_t oldest = 0, now = oio_ext_real_seconds();
	if (now > srvtype->score_expiration)
		oldest = now - srvtype->score_expiration;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, srvtype->services_ht);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct conscience_srv_s *p_srv = value;
		if (p_srv->put_score.timestamp < oldest || p_srv->get_score.timestamp < oldest) {
			if (p_srv->put_score.value > 0 && !p_srv->put_locked) {
				p_srv->put_score.value = 0;
				p_srv->put_score.timestamp = now;
			}
			if (p_srv->get_score.value > 0 && !p_srv->get_locked) {
				p_srv->get_score.value = 0;
				p_srv->get_score.timestamp = now;
			}
			p_srv->tags_mtime = now * G_TIME_SPAN_SECOND;
			struct service_tag_s *tag =
					service_info_ensure_tag(p_srv->tags, NAME_TAGNAME_UP);
			service_tag_set_value_boolean(tag, FALSE);
			_conscience_srv_prepare_cache(p_srv);
			if (callback)
				callback(p_srv, u);
			count++;
		}
	}

	return count;
}

static gboolean
conscience_srvtype_run_all(struct conscience_srvtype_s * srvtype,
		service_callback_f *callback, gpointer udata)
{
	const struct conscience_srv_s *beacon = &(srvtype->services_ring);
	for (struct conscience_srv_s *srv = beacon->next;
			srv && srv != beacon;
			srv = srv->next) {
		if (!callback(srv, udata))
			return FALSE;
	}
#ifdef HAVE_ENBUG
	g_usleep(cs_enbug_list_delay);
#endif
	return TRUE;
}

static void
conscience_update_srv(gboolean first, time_t now, gint32 si_score,
		enum score_type_e score_type, struct conscience_srv_s *p_srv)
{
	gboolean locked = FALSE;
	gchar score_type_name[4];
	if (score_type == PUT) {
		locked = p_srv->put_locked;
		strcpy(score_type_name, "put");
	} else if (score_type == GET) {
		locked = p_srv->get_locked;
		strcpy(score_type_name, "get");
	}

	if (si_score == SCORE_UNSET || si_score == SCORE_UNLOCK) {
		if (first) {
			GRID_TRACE2("SRV %s score first [%s]", score_type_name, p_srv->description);
			p_srv->lock_mtime = now;
			if (score_type == PUT) {
				GRID_INFO("First time seeing %s (service_id=%s), will be locked",
						p_srv->description, p_srv->service_id);
				p_srv->put_score.value = 0;
			} else if (score_type == GET) {
				p_srv->get_score.value = 0;
			}
			locked = TRUE;
		} else {
			if (si_score == SCORE_UNLOCK) {
				p_srv->lock_mtime = now;
				if (locked) {
					GRID_TRACE2("SRV %s score unlocked [%s]", score_type_name, p_srv->description);
					locked = FALSE;
					conscience_srv_compute_score(p_srv, score_type);
				} else {
					GRID_TRACE2("SRV %s score already unlocked [%s]", score_type_name, p_srv->description);
				}
			} else { /* UNSET, a.k.a. regular computation */
				if (locked) {
					GRID_TRACE2("SRV %s score untouched [%s]", score_type_name, p_srv->description);
				} else {
					if (conscience_srv_compute_score(p_srv, score_type)) {
						GRID_TRACE2("SRV %s score refreshed [%s]", score_type_name, p_srv->description);
					} /* else ... a trace is already written */
				}
			}
		}
	} else { /* LOCK */
		p_srv->lock_mtime = now;
		if (locked) {
			GRID_TRACE2("SRV %s score already locked [%s]", score_type_name, p_srv->description);
		} else {
			GRID_TRACE2("SRV %s score locked [%s]", score_type_name, p_srv->description);
			locked = TRUE;
		}
		if (score_type == PUT) {
			p_srv->put_score.value = CLAMP(si_score, SCORE_DOWN, SCORE_MAX);
		} else if (score_type == GET) {
			p_srv->get_score.value = CLAMP(si_score, SCORE_DOWN, SCORE_MAX);
		}
	}
	if (score_type == PUT) {
		p_srv->put_locked = locked;
	} else if (score_type == GET) {
		p_srv->get_locked = locked;
	}
}

static struct conscience_srv_s *
conscience_srvtype_refresh(struct conscience_srvtype_s *srvtype, struct service_info_s *si)
{
	EXTRA_ASSERT (NULL != si);

	struct service_tag_s *tag_first = service_info_get_tag(si->tags, NAME_TAGNAME_FIRST);
	gboolean really_first = FALSE;

	/* register the service if necessary, excepted if unlocking */
	struct conscience_srv_s *p_srv = g_hash_table_lookup(srvtype->services_ht, &si->addr);
	if (!p_srv) {
		if (si->put_score.value == SCORE_UNLOCK && si->get_score.value == SCORE_UNLOCK) {
			return NULL;
		} else {
			p_srv = conscience_srvtype_register_srv(srvtype, &si->addr);
			g_assert_nonnull (p_srv);
			really_first = tag_first && tag_first->type == STVT_BOOL && tag_first->value.b;

			/* retrieve Service ID if present */
			if (si->tags) {
				const guint max = si->tags->len;
				for (guint i = 0; i < max; i++) {
					struct service_tag_s *tag = g_ptr_array_index(si->tags, i);
					if (tag == tag_first) continue;

					if (g_strcmp0(tag->name, "tag.service_id")) {
						continue;
					}

					service_tag_to_string(tag, p_srv->service_id, LIMIT_LENGTH_SERVICE_ID);
					GRID_TRACE("associate %s to %s", p_srv->description, p_srv->service_id);
				}
			}
		}
	}

	time_t now = oio_ext_real_time();

	/* Refresh the tags: create missing, replace existing
	 * (if the tags are not flushed before). */
	gboolean tags_updated = FALSE;
	if (si->tags && si->tags->len) {
		GRID_TRACE("Refreshing tags for srv [%.*s]",
				(int)LIMIT_LENGTH_SRVDESCR, p_srv->description);
		if (flush_stats_on_refresh) {
			conscience_srv_clear_tags(p_srv);
		}
		const guint max = si->tags->len;
		for (guint i = 0; i < max; i++) {
			struct service_tag_s *tag = g_ptr_array_index(si->tags, i);
			if (tag == tag_first) continue;

			tags_updated = TRUE;
			struct service_tag_s *orig =
				service_info_ensure_tag(p_srv->tags, tag->name);
			service_tag_copy(orig, tag);
		}
	}
	if (tags_updated) {
		p_srv->tags_mtime = now;
		p_srv->put_score.timestamp = now / G_TIME_SPAN_SECOND;
		p_srv->get_score.timestamp = now / G_TIME_SPAN_SECOND;
	}

	gboolean first = really_first && srvtype->lock_at_first_register;
	conscience_update_srv(first, now, si->put_score.value, PUT, p_srv);
	conscience_update_srv(first, now, si->get_score.value, GET, p_srv);

	/* Set a tag to reflect the locked/unlocked state of the service.
	 * Modifying service_info_s would cause upgrade issues. */
	struct service_tag_s *lock_tag = service_info_ensure_tag(
			p_srv->tags, NAME_TAGNAME_LOCK);
	if (p_srv->put_locked && p_srv->get_locked) {
		service_tag_set_value_boolean(lock_tag, TRUE);
	} else {
		service_tag_set_value_boolean(lock_tag, FALSE);
	}
	struct service_tag_s *put_lock_tag = service_info_ensure_tag(
			p_srv->tags, NAME_TAGNAME_PUT_LOCK);
	service_tag_set_value_boolean(put_lock_tag, p_srv->put_locked);
	struct service_tag_s *get_lock_tag = service_info_ensure_tag(
			p_srv->tags, NAME_TAGNAME_GET_LOCK);
	service_tag_set_value_boolean(get_lock_tag, p_srv->get_locked);

	return p_srv;
}

#define conscience_lock_W_srvtypes() g_rw_lock_writer_lock(&rwlock_srv)
#define conscience_unlock_W_srvtypes() g_rw_lock_writer_unlock(&rwlock_srv)

#define conscience_lock_R_srvtypes() g_rw_lock_reader_lock(&rwlock_srv);
#define conscience_unlock_R_srvtypes() g_rw_lock_reader_unlock(&rwlock_srv);

static struct conscience_srvtype_s *
conscience_get_srvtype(const gchar * type, const gboolean autocreate)
{
	conscience_lock_R_srvtypes();
	struct conscience_srvtype_s *srvtype = g_tree_lookup(srvtypes, type);
	conscience_unlock_R_srvtypes();
	if (!srvtype && autocreate) {
		conscience_lock_W_srvtypes();
		srvtype = conscience_srvtype_create(type);
		g_tree_insert(srvtypes, g_strdup(type), srvtype);
		conscience_unlock_W_srvtypes();
	}
	return srvtype;
}

static gchar **
conscience_get_srvtype_names(void)
{
	conscience_lock_R_srvtypes();
	gchar **result = gtree_string_keys(srvtypes);
	conscience_unlock_R_srvtypes();
	return result;
}

static GError *
conscience_run_srvtypes(const gchar *type, service_callback_f * callback, gpointer udata)
{
	GError *err = NULL;
	struct conscience_srvtype_s *srvtype =
		conscience_get_srvtype(type, FALSE);

	if (!srvtype) {
		err = BADSRVTYPE(type);
	} else {
		g_rw_lock_reader_lock(&(srvtype->rw_lock));
		gboolean rc = conscience_srvtype_run_all(srvtype, callback, udata);
		g_rw_lock_reader_unlock(&(srvtype->rw_lock));
		if (!rc)
			err = SYSERR("Configuration error with [%s]", type);
	}
	return err;
}

/* ------------------------------------------------------------------------- */

static volatile gboolean hub_running = FALSE;
static volatile gboolean hub_working = FALSE;
static void *hub_zctx = NULL;
static void *hub_zpub = NULL;
static void *hub_zsub = NULL;
static GAsyncQueue *hub_queue = NULL;
static GThread *hub_thread_pub = NULL;
static GThread *hub_thread_sub = NULL;
static GThreadPool *pool_update_srv = NULL;


static const char *
hub_action_to_str(const char action)
{
	switch (action) {
		case 'P':
			return "CS_PSH";
		case 'R':
			return "CS_DEL";
		case 'F':
			/* CS_FLUSH does not exist, "flush" is a special case of CS_DEL */
			return "CS_FLUSH";
		default:
			return "undefined";
	}
}

static void
send_hub_stat(const gchar *way, const gchar action, const int code)
{
	gchar metric_name[256] = {0};
	g_snprintf(metric_name, sizeof(metric_name),
			"hub_%s.%s.%d.count", way, hub_action_to_str(action), code);
	network_server_incr_stat(server, metric_name);
}

static void
send_hub_timing(const gchar *way, const gchar action, const int code,
		gint64 micros)
{
	gchar metric_name[256] = {0};
	g_snprintf(metric_name, sizeof(metric_name),
			"hub_%s.%s.%d.timing", way, hub_action_to_str(action), code);
	network_server_send_timing(server, metric_name, micros);
}

static void
_et_bim_cest_dans_le_hub (gchar *m)
{
	if (*m) {
		int rc = zmq_send(hub_zpub, m, 1, ZMQ_SNDMORE);
		if (rc < 0) {
			GRID_WARN("HUB: failed to publish action: (%d) %s",
					errno, strerror(errno));
		} else if (rc != 1) {
			GRID_WARN("HUB: failed to publish action: "
					"unexpected number of bytes sent: %d (expected=1)",
					rc);
			send_hub_stat("sent", m[0], EMSGSIZE);
		} else {
			GRID_TRACE2("HUB: published 1 action / %d bytes", rc);
			int mlen = strlen(m+1);
			rc = zmq_send(hub_zpub, m+1, mlen, ZMQ_DONTWAIT);
			if (rc < 0) {
				GRID_WARN("HUB: failed to publish service: (%d) %s",
						errno, strerror(errno));
				send_hub_stat("sent", m[0], errno);
			} else if (rc != mlen) {
				GRID_WARN("HUB: failed to publish service: "
						"unexpected number of bytes sent: %d (expected=%d)",
						rc, mlen);
				send_hub_stat("sent", m[0], EMSGSIZE);
			} else {
				GRID_TRACE2("HUB: published 1 service / %d bytes", rc);
				send_hub_stat("sent", m[0], 0);
			}
		}
	}
	g_free (m);
}

static gpointer
hub_worker_pub (gpointer p)
{
	while (hub_running) {
		gchar *m = g_async_queue_timeout_pop (hub_queue, G_TIME_SPAN_SECOND);
		if (!m) continue;
		_et_bim_cest_dans_le_hub (m);
	}

	GRID_INFO("HUB worker waiting for the last events");
	for (;;) {
		gchar *m = g_async_queue_try_pop (hub_queue);
		if (!m) break;
		_et_bim_cest_dans_le_hub (m);
	}

	GRID_INFO("HUB worker exiting");
	return p;
}

static void
_alert_service_with_zeroed_score(struct conscience_srv_s *srv)
{
	time_t now = oio_ext_monotonic_seconds ();
	if (srv->time_last_alert < now - srv->srvtype->alert_frequency_limit) {
		GRID_WARN("[NS=%s][%s][SCORE=0] service=%.*s (service_id=%s)",
				oio_server_namespace, srv->srvtype->type_name,
				(int)sizeof(srv->description), srv->description,
				srv->service_id);
		srv->time_last_alert = now;
	}
}

/* -------------------------------------------------------------------------- */

static struct service_info_dated_s *
service_info_dated_new2(struct conscience_srv_s *srv)
{
	struct service_info_dated_s *sid = g_malloc0(sizeof(
			struct service_info_dated_s));
	sid->si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(sid->si, srv);
	sid->lock_mtime = srv->lock_mtime;
	sid->tags_mtime = srv->tags_mtime;
	return sid;
}

static struct conscience_srv_s *
conscience_srvtype_refresh_dated(
		struct conscience_srvtype_s *srvtype,
		struct service_info_dated_s *sid)
{
	/* register the service if necessary */
	struct conscience_srv_s *p_srv = g_hash_table_lookup(
			srvtype->services_ht, &sid->si->addr);
	if (!p_srv) {
		p_srv = conscience_srvtype_register_srv(srvtype, &sid->si->addr);
		g_assert_nonnull(p_srv);

		/* retrieve Service ID if present */
		if (sid->si->tags) {
			const guint max = sid->si->tags->len;
			for (guint i = 0; i < max; i++) {
				struct service_tag_s *tag = g_ptr_array_index(
						sid->si->tags, i);
				if (g_strcmp0(tag->name, "tag.service_id")) {
					continue;
				}

				service_tag_to_string(tag, p_srv->service_id,
						LIMIT_LENGTH_SERVICE_ID);
				GRID_TRACE("associate %s to %s", p_srv->description,
						p_srv->service_id);
			}
		}
	}

	/* Refresh the lock */
	if (sid->lock_mtime > p_srv->lock_mtime) {
		GRID_TRACE("Refreshing locks for srv [%.*s]",
				(int)LIMIT_LENGTH_SRVDESCR, p_srv->description);
		p_srv->lock_mtime = sid->lock_mtime;

		struct service_tag_s *tag_lock = service_info_get_tag(
				sid->si->tags, NAME_TAGNAME_LOCK);

		struct service_tag_s *tag_put_lock = service_info_get_tag(
				sid->si->tags, NAME_TAGNAME_PUT_LOCK);
		if (tag_put_lock) {
			p_srv->put_locked = tag_put_lock->type == STVT_BOOL && tag_put_lock->value.b;
		} else {
			// The put_locked tag does not exist, use the original tag to not change the behavior
			p_srv->put_locked = tag_lock && tag_lock->type == STVT_BOOL && tag_lock->value.b;
		}

		struct service_tag_s *tag_get_lock = service_info_get_tag(
				sid->si->tags, NAME_TAGNAME_GET_LOCK);
		if (tag_get_lock) {
			p_srv->get_locked = tag_get_lock->type == STVT_BOOL && tag_get_lock->value.b;
		} else {
			// The get_locked tag does not exist, use the original tag to not change the behavior
			p_srv->get_locked = tag_lock && tag_lock->type == STVT_BOOL && tag_lock->value.b;
		}

		if (p_srv->put_locked)
			p_srv->put_score.value = CLAMP(sid->si->put_score.value, SCORE_DOWN,
					SCORE_MAX);

		if (p_srv->get_locked)
			p_srv->get_score.value = CLAMP(sid->si->get_score.value, SCORE_DOWN,
					SCORE_MAX);

		/* Set a tag to reflect the locked/unlocked state of the service.
		 * Modifying service_info_s would cause upgrade issues. */
		struct service_tag_s *lock_tag = service_info_ensure_tag(
				p_srv->tags, NAME_TAGNAME_LOCK);
		if (p_srv->put_locked && p_srv->get_locked) {
			service_tag_set_value_boolean(lock_tag, TRUE);
		} else {
			service_tag_set_value_boolean(lock_tag, FALSE);
		}
		tag_put_lock = service_info_ensure_tag(p_srv->tags, NAME_TAGNAME_PUT_LOCK);
		service_tag_set_value_boolean(tag_put_lock, p_srv->put_locked);
		tag_get_lock = service_info_ensure_tag(p_srv->tags, NAME_TAGNAME_GET_LOCK);
		service_tag_set_value_boolean(tag_get_lock, p_srv->get_locked);
	}

	/* refresh the tags: create missing, replace existing
	 * (but the tags are not flushed before) */
	if (sid->tags_mtime > p_srv->tags_mtime) {
		GRID_TRACE("Refreshing tags for srv [%.*s]",
				(int)LIMIT_LENGTH_SRVDESCR, p_srv->description);
		p_srv->tags_mtime = sid->tags_mtime;
		p_srv->put_score.timestamp = sid->tags_mtime / G_TIME_SPAN_SECOND;
		p_srv->get_score.timestamp = sid->tags_mtime / G_TIME_SPAN_SECOND;

		if (sid->si->tags) {
			const guint max = sid->si->tags->len;
			for (guint i = 0; i < max; i++) {
				struct service_tag_s *tag = g_ptr_array_index(sid->si->tags, i);
				struct service_tag_s *orig = service_info_ensure_tag(
						p_srv->tags, tag->name);
				service_tag_copy(orig, tag);
			}
		}

		if (!p_srv->put_locked || !p_srv->get_locked) {
			conscience_srv_compute_score(p_srv, PUT | GET);
		}
	}

	return p_srv;
}

static void
push_service_dated(struct service_info_dated_s *sid)
{
	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(
			sid->si->type, FALSE);

	time_t now = oio_ext_real_time();
	gint64 repli_lag = now - MAX(sid->tags_mtime, sid->lock_mtime);
	if (!srvtype) {
		GRID_ERROR("Service type [%s/%s] not found",
				oio_server_namespace, sid->si->type);
		send_hub_timing("lag", 'P', ENOENT, repli_lag);
		return;
	}
	send_hub_timing("lag", 'P', 0, repli_lag);

	/* TODO(FVE): measure time to obtain the lock, send alert. */
	gint64 start = oio_ext_monotonic_time();
	g_rw_lock_writer_lock(&srvtype->rw_lock);
	struct conscience_srv_s *srv = \
			conscience_srvtype_refresh_dated(srvtype, sid);
	if (srv) {
		/* shortcut for services tagged DOWN */
		gboolean is_up = FALSE;
		struct service_tag_s *tag_up = service_info_get_tag(
				sid->si->tags, NAME_TAGNAME_UP);
		if (tag_up && service_tag_get_value_boolean(tag_up, &is_up, NULL) \
				&& !is_up) {
			if (!srv->put_locked)
				srv->put_score.value = 0;
			if (!srv->get_locked)
				srv->get_score.value = 0;
			/* TODO(FVE): send alert outside of the lock. */
			if (!srv->put_locked || !srv->get_locked)
				_alert_service_with_zeroed_score(srv);
		}
		/* Prepare the serialized form of the service */
		_conscience_srv_prepare_cache (srv);
	}
	g_rw_lock_writer_unlock(&srvtype->rw_lock);
	gint64 duration = oio_ext_monotonic_time() - start;

	oio_stats_add(
		gq_count_hub_update, 1,
		gq_lag_hub_update, repli_lag,
		gq_time_hub_update, duration,
		0, 0
	);
}

static void
rm_service_dated(struct service_info_dated_s *sid)
{
	gchar str_desc[LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE \
			+ STRLEN_ADDRINFO];
	int str_desc_len = g_snprintf(str_desc, sizeof(str_desc),
			"%s/%s/", oio_server_namespace, sid->si->type);
	grid_addrinfo_to_string(&(sid->si->addr), str_desc + str_desc_len,
			sizeof(str_desc) - str_desc_len);

	time_t now = oio_ext_real_time();
	gint64 repli_lag = now - MAX(sid->tags_mtime, sid->lock_mtime);

	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(
			sid->si->type, FALSE);
	if (!srvtype) {
		GRID_ERROR("Service type not found [%s]", str_desc);
		send_hub_timing("lag", 'R', ENOENT, repli_lag);
		return;
	}
	send_hub_timing("lag", 'R', 0, repli_lag);

	gint64 start = oio_ext_monotonic_time();
	g_rw_lock_writer_lock(&srvtype->rw_lock);
	conscience_srvtype_remove_srv(srvtype, &sid->si->addr,
			sid->lock_mtime);
	g_rw_lock_writer_unlock(&srvtype->rw_lock);
	gint64 duration = oio_ext_monotonic_time() - start;

	oio_stats_add(
		gq_count_hub_remove, 1,
		gq_lag_hub_remove, repli_lag,
		gq_time_hub_remove, duration,
		0, 0
	);
	GRID_INFO("Service removed [%s]", str_desc);
}

/* -------------------------------------------------------------------------- */

static struct service_info_dated_s *
push_service(struct service_info_s *si)
{
	struct service_info_dated_s *sid = NULL;

	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(si->type, FALSE);
	if (!srvtype) {
		GRID_ERROR("Service type [%s/%s] not found",
				oio_server_namespace, si->type);
	} else {
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		struct conscience_srv_s *srv = conscience_srvtype_refresh(srvtype, si);
		if (srv) {
			/* shortcut for services tagged DOWN */
			gboolean bval = FALSE;
			struct service_tag_s *tag = service_info_get_tag(si->tags, NAME_TAGNAME_UP);
			if (tag && service_tag_get_value_boolean(tag, &bval, NULL) && !bval) {
				if (!srv->put_locked)
					srv->put_score.value = 0;
				if (!srv->get_locked)
					srv->get_score.value = 0;
				if (!srv->put_locked || !srv->get_locked)
					_alert_service_with_zeroed_score(srv);
			}
			/* Prepare the serialized form of the service */
			_conscience_srv_prepare_cache (srv);

			sid = service_info_dated_new2(srv);
		}
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
	}

	return sid;
}

static struct service_info_dated_s *
rm_service(struct service_info_s *si)
{
	struct service_info_dated_s *sid = NULL;

	gchar str_desc[LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO];
	int str_desc_len = g_snprintf(
			str_desc, sizeof(str_desc), "%s/%s/",
			oio_server_namespace, si->type);
	grid_addrinfo_to_string(
			&(si->addr), str_desc + str_desc_len, sizeof(str_desc) - str_desc_len);

	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(si->type, FALSE);
	if (!srvtype) {
		GRID_ERROR("Service type not found [%s]", str_desc);
	} else {
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		time_t now = oio_ext_real_time();
		conscience_srvtype_remove_srv(srvtype, &si->addr, 0);
		sid = service_info_dated_new(si, now);
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
		GRID_INFO("Service removed [%s]", str_desc);
	}

	return sid;
}

static void
_load_and_update_service(gpointer srv_data, gpointer udata UNUSED)
{
	gchar *json_data = srv_data;
	struct service_info_dated_s *sid = NULL;
	GError *err = service_info_dated_load_json(json_data, &sid, FALSE);
	EXTRA_ASSERT((err != NULL) ^ (sid != NULL));
	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s", err->code, err->message);
		g_clear_error (&err);
	} else {
		push_service_dated(sid);
		service_info_dated_free(sid);
	}
	g_free(json_data);
}

static void
_on_push (const guint8 *b, gsize l)
{
	/* Copy the buffer received from the HUB, send it to a thread pool
	 * for decoding (we don't want to block the HUB). */
	gchar *json_data = g_strndup((gchar*)b, l);
	if (pool_update_srv) {
		metautils_gthreadpool_push("SRVUPD", pool_update_srv, json_data);
	} else {
		_load_and_update_service(json_data, NULL);
	}
}

static void
_on_remove (const guint8 *b, gsize l)
{
	struct service_info_dated_s *sid = NULL;
	gchar *tmp = g_strndup ((gchar*)b, l);
	GError *err = service_info_dated_load_json (tmp, &sid, FALSE);
	EXTRA_ASSERT((err != NULL) ^ (sid != NULL));
	g_free (tmp);

	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	} else {
		rm_service_dated(sid);
		service_info_dated_free(sid);
	}
}

static void
_on_flush (const guint8 *b, gsize l)
{
	gchar *tmp = g_strndup ((gchar*)b, l);
	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(tmp, FALSE);
	if (!srvtype) {
		GRID_ERROR("[NS=%s][SRVTYPE=%s] not found", oio_server_namespace, tmp);
	} else {
		gint64 start = oio_ext_monotonic_time();
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		conscience_srvtype_flush(srvtype);
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
		gint64 duration = oio_ext_monotonic_time() - start;

		oio_stats_add(
			gq_count_hub_flush, 1,
			gq_time_hub_flush, duration,
			0, 0,
			0, 0
		);
		GRID_NOTICE("[NS=%s][SRVTYPE=%s] flush done!",
				oio_server_namespace, srvtype->type_name);
	}
	g_free (tmp);
}

static void
_on_each_message (void *zin, void (*hook) (const guint8 *, gsize))
{
	int rc;
	zmq_msg_t msg;
	zmq_msg_init (&msg);
	do {
		rc = zmq_msg_recv (&msg, zin, ZMQ_DONTWAIT);
		if (rc < 0) {
			GRID_WARN("HUB: failed to receive service: (%d) %s",
					errno, strerror(errno));
		} else if (rc == 0) {
			GRID_INFO("HUB: received 1 service with no data");
		} else {
			GRID_TRACE2("HUB: received 1 service / %d bytes", rc);
			if (hook)
				hook(zmq_msg_data(&msg), zmq_msg_size(&msg));
		}
	} while (rc >= 0 && zmq_msg_more(&msg));
	zmq_msg_close (&msg);
}

static gpointer
hub_worker_sub (gpointer p)
{
	while (hub_running) {

		/* poll incoming messages */
		zmq_pollitem_t items[1] = {
			{hub_zsub, -1, ZMQ_POLLIN, 0},
		};
		int rc = zmq_poll (items, 1, 1000);
		if (rc == 0) continue;
		if (rc < 0) {
			if (errno == ETERM) break;
			if (errno == EINTR || errno == EAGAIN) continue;
			GRID_WARN("ZMQ poll error: (%d) %s", errno, strerror(errno));
			break;
		}
		GRID_TRACE2("HUB activity!");

		/* manage them */
		for (guint i=0; i<1024; ++i) {
			zmq_msg_t msg;
			zmq_msg_init (&msg);
			rc = zmq_msg_recv (&msg, hub_zsub, ZMQ_DONTWAIT);
			if (rc < 0) {
				if (errno == ETERM)
					break;
				if (errno == EINTR || errno == EAGAIN)
					continue;
				GRID_WARN("HUB: failed to receive action: (%d) %s",
						errno, strerror(errno));
				send_hub_stat("recv", 0, errno);
				break;
			} else if (rc != 1) {
				GRID_WARN("HUB: failed to receive action: "
						"unexpected number of bytes received: %d (expected=1)",
						rc);
				send_hub_stat("recv", 0, EMSGSIZE);
				break;
			}
			const char *action = (const char*) zmq_msg_data(&msg);
			const int more = zmq_msg_more(&msg);
			GRID_TRACE2("HUB: received 1 action size=%d more=%d action=%c",
					rc, more, *action);
			send_hub_stat("recv", *action, 0);
			if (more) {
				switch (*action) {
					case 'P':
						_on_each_message (hub_zsub, _on_push);
						break;
					case 'R':
						_on_each_message (hub_zsub, _on_remove);
						break;
					case 'F':
						_on_each_message (hub_zsub, _on_flush);
						break;
					default:
						_on_each_message (hub_zsub, NULL);
						break;
				}
			}
			zmq_msg_close (&msg);
			hub_working = TRUE;
		}
	}

	return p;
}

static void
hub_publish_service (const struct service_info_dated_s *sid)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'P');
	service_info_dated_encode_json(encoded, sid, TRUE);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

static void
hub_remove_service (const struct service_info_dated_s *sid)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'R');
	service_info_dated_encode_json(encoded, sid, TRUE);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

static void
hub_flush_srvtype (const char *name)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'F');
	g_string_append (encoded, name);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

/* Utterly complicated RPC: service fetch ---------------------------------- */

static GByteArray *
_conscience_srv_serialize_full(struct conscience_srv_s *srv)
{
	struct service_info_s *si = g_alloca(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);
	GByteArray *gba = service_info_marshall_1(si, NULL);
	service_info_clean_tags(si);
	return gba;
}

static gboolean
_prepare_full(struct conscience_srv_s *srv, gpointer u)
{
	GByteArray *gba_body = u;
	EXTRA_ASSERT(srv != NULL);
	EXTRA_ASSERT(gba_body != NULL);

	GByteArray *gba = _conscience_srv_serialize_full(srv);
	g_byte_array_append(gba_body, gba->data, gba->len);
	g_byte_array_free(gba, TRUE);
	return TRUE;
}

static gboolean
_prepare_cached(struct conscience_srv_s *srv, gpointer u)
{
	GByteArray *gba_body = u;
	EXTRA_ASSERT(srv != NULL);
	EXTRA_ASSERT(gba_body != NULL);

	/* Reuse the serialized version of the service
	 * that was made at registration time (saves CPU) */
	if (srv->cache) {
		g_byte_array_append(gba_body, srv->cache->data, srv->cache->len);
		return TRUE;
	} else {
		/* Serialize the service without its tags and stats */
		GByteArray *gba = _conscience_srv_serialize(srv);
		g_byte_array_append(gba_body, gba->data, gba->len);
		g_byte_array_free(gba, TRUE);
		return TRUE;
	}
}

static gboolean
_cs_dispatch_SRV(struct gridd_reply_ctx_s *reply,
	 gpointer g UNUSED, gpointer h UNUSED)
{
	GError *err = NULL;
	gboolean cache_hit = TRUE;
	GByteArray *serialized = NULL;
	gchar strtype[LIMIT_LENGTH_SRVTYPE];

	err = metautils_message_extract_string(
			reply->request, NAME_MSGKEY_TYPENAME, TRUE,
			strtype, sizeof(strtype));
	if (err) {
		g_prefix_error(&err, "Invalid service type: ");
		reply->send_error(0, err);
		return TRUE;
	}

	reply->no_access();

	const gboolean full = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FULL, FALSE);

	/* Take a reference to the cache, so it's not freed while we use it.
	 * There is a race condition if someone calls g_hash_table_unref
	 * while we are calling g_hash_table_ref, hence the lock. */
	g_mutex_lock(&srv_lists_lock);
	GHashTable *srv_cache_ref =
			g_hash_table_ref(full? full_srv_list_cache : srv_list_cache);
	g_mutex_unlock(&srv_lists_lock);
	GByteArray *gba = g_byte_array_sized_new(8192);
	g_byte_array_append(gba, header, 2);

	if (strcmp(strtype, "all") == 0) {
		gchar **services_names = conscience_get_srvtype_names();
		for (gchar **name = services_names; !err && *name; name++) {
			if ((serialized = g_hash_table_lookup(srv_cache_ref, *name))) {
				g_byte_array_append(gba, serialized->data, serialized->len);
			} else {
				err = conscience_run_srvtypes(*name,
						full ? _prepare_full : _prepare_cached, gba);
				cache_hit = FALSE;
			}
		}
		g_free(services_names);
	} else {
		if ((serialized = g_hash_table_lookup(srv_cache_ref, strtype))) {
			g_byte_array_append(gba, serialized->data, serialized->len);
		} else {
			err = conscience_run_srvtypes(strtype,
					full ? _prepare_full : _prepare_cached, gba);
			cache_hit = FALSE;
		}
	}

	/* Release the reference to the cache.
	 * It may be freed here, if it has been regenerated in the meantime. */
	g_hash_table_unref(srv_cache_ref);

	if (err) {
		g_byte_array_free(gba, TRUE);
		reply->send_error(0, err);
	} else {
		reply->subject("cache:%s\tsrv_type:%s%s",
				cache_hit? "HIT" : "MISS",
				strtype,
				full? "\top_type:full" : ""
		);
		g_byte_array_append(gba, footer, 2);
		reply->add_body(gba);
		reply->send_reply(200, "OK");
	}

	return 1;
}

/* Simple RPC -------------------------------------------------------------- */

static gboolean
_cs_dispatch_NSINFO(struct gridd_reply_ctx_s *reply,
		gpointer g UNUSED, gpointer h UNUSED)
{
	reply->no_access();
	EXTRA_ASSERT(nsinfo_cache != NULL);
	GByteArray *body = g_byte_array_ref(nsinfo_cache);
	reply->add_body (body);
	reply->send_reply(CODE_FINAL_OK, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_TYPES(struct gridd_reply_ctx_s *reply,
		gpointer g UNUSED, gpointer h UNUSED)
{
	reply->no_access();
	gchar **namev = conscience_get_srvtype_names();
	reply->add_body(STRV_encode_gba(namev));
	g_free(namev);
	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_PUSH(struct gridd_reply_ctx_s *reply,
		gpointer g UNUSED, gpointer h UNUSED)
{
	reply->no_access();

	/* XXX(FVE): we could extract the namespace name from a header
	 * and compare it to the local one. I think it was done in the past
	 * but has been removed to save a bit of bandwidth and CPU time. */
	GSList *list_srvinfo = NULL;
	GError *err = metautils_message_extract_body_encoded(
			reply->request, TRUE, &list_srvinfo, service_info_unmarshall);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/*Now push each service and reply the success */
	guint count = 0;
	for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
		struct service_info_s *si = l->data;
		if (!metautils_addr_valid_for_connect(&si->addr)
				|| !oio_str_is_set(si->type)) {
			continue;
		} else if (!oio_str_is_set(si->ns_name)) {
			gchar srvaddr[STRLEN_ADDRINFO];
			grid_addrinfo_to_string(&si->addr, srvaddr, sizeof(srvaddr));
			GRID_DEBUG("Got a service without ns_name: %s %s",
					si->type, srvaddr);
		} else if (g_strcmp0(oio_server_namespace, si->ns_name) != 0) {
			gchar srvaddr[STRLEN_ADDRINFO];
			grid_addrinfo_to_string(&si->addr, srvaddr, sizeof(srvaddr));
			GRID_WARN("Got a service from namespace %s: %s %s, refusing it!",
					si->ns_name, si->type, srvaddr);
			continue;
		}
		struct service_info_dated_s *sid = push_service(si);
		if (sid) {
			hub_publish_service(sid);
			service_info_dated_free(sid);
		}
		++ count;
	}
	GRID_DEBUG("Pushed %u items (reqid=%s)", count, oio_ext_get_reqid());
	g_slist_free_full (list_srvinfo, (GDestroyNotify) service_info_clean);

	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_FLUSH(struct gridd_reply_ctx_s *reply)
{
	GError *err = NULL;
	gchar strtype[LIMIT_LENGTH_SRVTYPE];

	err = metautils_message_extract_string(
			reply->request, NAME_MSGKEY_TYPENAME, TRUE,
			strtype, sizeof(strtype));
	if (err) {
		g_prefix_error(&err, "Invalid service type: ");
		reply->send_error(0, err);
	} else {
		_on_flush ((guint8*)strtype, strlen(strtype));
		hub_flush_srvtype (strtype);
		reply->send_reply(200, "OK");
	}
	return TRUE;
}

static gboolean
_cs_dispatch_RM(struct gridd_reply_ctx_s *reply,
		gpointer g UNUSED, gpointer h UNUSED)
{
	if (!metautils_message_has_BODY(reply->request))
		return _cs_dispatch_FLUSH(reply);

	GSList *list_srvinfo = NULL;
	GError *err = metautils_message_extract_body_encoded(
			reply->request, TRUE, &list_srvinfo, service_info_unmarshall);
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	GRID_NOTICE("[NS=%s] [%d] services to be removed",
			oio_server_namespace, g_slist_length(list_srvinfo));

	for (GSList *l = list_srvinfo; l; l = l->next) {
		struct service_info_dated_s *sid = rm_service(l->data);
		if (sid) {
			hub_remove_service(sid);
			service_info_dated_free(sid);
		}
	}

	g_slist_free_full (list_srvinfo, (GDestroyNotify) service_info_clean);
	reply->send_reply(200, "OK");
	return TRUE;
}

/* Inter-conscience hub ---------------------------------------------------- */

static gboolean
_is_in (gchar **tab, const char *u)
{
	if (!tab) return FALSE;
	while (*tab) {
		if (!strcmp(*(tab++), u))
			return TRUE;
	}
	return FALSE;
}

static GError *
_init_hub (void)
{
	gchar **split_me = hub_me ? g_strsplit(hub_me, ",", -1) : NULL;

	GRID_DEBUG("HUB me[%s] group[%s]", hub_me, hub_group);
	if (!hub_me && !hub_group)
		return NULL;

	void setint (void *z, int which, int val) {
		(void) zmq_setsockopt (z, which, &val, sizeof(val));
	}

	hub_running = TRUE;
	hub_queue = g_async_queue_new ();
	g_assert (hub_queue != NULL);
	hub_zctx = zmq_ctx_new ();
	g_assert (hub_zctx != NULL);
	hub_zsub = zmq_socket (hub_zctx, ZMQ_SUB);
	g_assert (hub_zsub != NULL);
	hub_zpub = zmq_socket (hub_zctx, ZMQ_PUB);
	g_assert (hub_zpub != NULL);

	setint (hub_zpub, ZMQ_RCVBUF, 16*1024*1024);
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "P", 1); /* push / lock / unlock */
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "R", 1); /* removal */
	zmq_setsockopt (hub_zsub, ZMQ_SUBSCRIBE, "F", 1); /* flush */
	if (split_me && *split_me) {
		for (gchar **t=split_me; *t ;++t) {
			int rc = zmq_bind (hub_zsub, *t);
			if (rc != 0) {
				const int zerr = zmq_errno ();
				return SYSERR("HUB bind error [%s]: (%d) %s",
						*t, zerr, zmq_strerror(zerr));
			} else {
				GRID_NOTICE("HUB bond to [%s]", *t);
			}
		}
	}

	setint (hub_zpub, ZMQ_LINGER, 1000);
	setint (hub_zpub, ZMQ_SNDBUF, 16*1024*1024);
	if (hub_group) {
		gchar **tokens = g_strsplit (hub_group, ",", -1);
		if (tokens) {
			for (gchar **t=tokens; *t ;++t) {
				if (_is_in (split_me, *t))
					continue;
				int rc = zmq_connect (hub_zpub, *t);
				if (rc != 0) {
					const int zerr = zmq_errno ();
					return SYSERR("HUB connect error [%s]: (%d) %s",
							*t, zerr, zmq_strerror(zerr));
				} else {
					hub_group_size++;
					GRID_NOTICE("HUB connected to [%s]", *t);
				}
			}
			g_strfreev (tokens);
		}
	}

	hub_thread_pub = g_thread_new ("hub-pub", hub_worker_pub, NULL);
	g_assert (hub_thread_pub != NULL);

	hub_thread_sub = g_thread_new ("hub-sub", hub_worker_sub, NULL);
	g_assert (hub_thread_sub != NULL);

	if (hub_threads > 0) {
		pool_update_srv = g_thread_pool_new(
				(GFunc)_load_and_update_service,
				NULL, hub_threads, FALSE, NULL);
		g_assert(pool_update_srv != NULL);
	}

	if (split_me)
		g_strfreev (split_me);
	return NULL;
}


/* Background tasks -------------------------------------------------------- */

static gboolean
service_expiration_notifier(struct conscience_srv_s *srv, gpointer u UNUSED)
{
	if (srv) {
		GRID_INFO("Service expired [%s] (score=%d get_score=%d service_id=%s)",
				srv->description, srv->put_score.value, srv->get_score.value,
				srv->service_id);
		struct service_info_dated_s *sid = service_info_dated_new2(srv);
		hub_publish_service(sid);
		service_info_dated_free(sid);
	}
	return TRUE;
}

static void
_task_expire (gpointer p UNUSED)
{
	conscience_lock_R_srvtypes();
	gchar **typev = conscience_get_srvtype_names();
	conscience_unlock_R_srvtypes();

	for (gchar **ptype=typev; typev && *ptype ;++ptype) {
		struct conscience_srvtype_s *srvtype = conscience_get_srvtype(*ptype, FALSE);
		EXTRA_ASSERT(srvtype != NULL);
		g_rw_lock_reader_lock(&srvtype->rw_lock);
		guint count = conscience_srvtype_zero_expired(srvtype,
				service_expiration_notifier, NULL);
		g_rw_lock_reader_unlock(&srvtype->rw_lock);

		if (count)
			GRID_NOTICE("Expired [%u] [%s] services", count, *ptype);
	}

	g_free(typev);
}

static void
_task_check_hub(gpointer p UNUSED)
{
	if (pool_update_srv) {
		guint unprocessed = g_thread_pool_unprocessed(pool_update_srv);
		if (unprocessed > 10000) {
			GRID_WARN("HUB: %u service updates waiting to be processed",
					unprocessed);
		} else {
			GRID_DEBUG("HUB: %u service updates waiting to be processed",
					unprocessed);
		}
	}
	gint qlen = g_async_queue_length(hub_queue);
	if (qlen > 10000) {
		GRID_WARN("HUB: %d service updates waiting to be published", qlen);
	} else if (qlen > 0) {
		GRID_DEBUG("HUB: %d service updates waiting to be published", qlen);
	}
	// TODO(FVE): check other hub-related metrics
}

static gboolean
_publish_if_locked(struct conscience_srv_s *srv, gpointer u UNUSED)
{
	EXTRA_ASSERT(srv != NULL);

	if (!(srv->get_locked || srv->put_locked)) {
		/* Service is not locked */
		return TRUE;
	}

	time_t now = oio_ext_real_time();
	gint64 delay = MAX(5, hub_publish_stale_delay) * G_TIME_SPAN_SECOND;
	if (srv->tags_mtime > (now - delay)) {
		/* Service has been updated recently */
		return TRUE;
	}

	/* Service is locked, but has not been updated recently. Maybe the
	 * conscience-agent is down. Publish the service on the hub, so new
	 * conscience instances see it exists and is locked. */
	struct service_info_dated_s *sid = service_info_dated_new2(srv);
	hub_publish_service(sid);
	GRID_DEBUG("Published locked service %s, last updated at %"G_GINT64_FORMAT,
			srv->service_id, srv->tags_mtime / G_TIME_SPAN_SECOND);
	service_info_dated_free(sid);

	return TRUE;
}

static void
_task_publish_stale_services(gpointer p UNUSED)
{
	GError *err = NULL;
	gchar **services_names = conscience_get_srvtype_names();
	for (gchar **name = services_names; !err && *name; name++){
		err = conscience_run_srvtypes(*name, _publish_if_locked, NULL);
		if (err) {
			GRID_ERROR("Failed to synchronize %s service locks: (%d) %s",
				*name, err->code, err->message);
			g_clear_error(&err);
		}
	}
	g_free(services_names);
}

static void
_prepare_one_serialized_cache(GHashTable **srv_cache_p, service_callback_f *serializer)
{
	GError *err = NULL;
	GHashTable *new_srv_cache = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);

	gchar **services_names = conscience_get_srvtype_names();
	for (gchar **name = services_names; !err && *name; name++) {
		GByteArray *serialized = g_byte_array_sized_new(8192);
		err = conscience_run_srvtypes(*name, serializer, serialized);
		g_hash_table_insert(new_srv_cache, g_strdup(*name), serialized);
		if (err)
			break;
	}
	g_free(services_names);
	if (err) {
		GRID_WARN("Failed to prepare serialized service cache: %s",
				err->message);
		g_clear_error(&err);
		g_hash_table_unref(new_srv_cache);
	} else {
		GHashTable *old_srv_cache = NULL;
		g_mutex_lock(&srv_lists_lock);
		/* Keep a pointer to the old cache. */
		old_srv_cache = *srv_cache_p;
		/* Atomically replace the pointer to the new cache. */
		*srv_cache_p = new_srv_cache;
		g_mutex_unlock(&srv_lists_lock);
		/* Then decrease the reference count of the old cache.
		 * The last thread using it will free it. */
		g_hash_table_unref(old_srv_cache);
	}
}

static void
_prepare_serialized_cache()
{
	if (cache_service_lists)
		_prepare_one_serialized_cache(&srv_list_cache, _prepare_cached);
	if (cache_full_service_lists)
		_prepare_one_serialized_cache(&full_srv_list_cache, _prepare_full);
}

static void *
_worker_prepare_serialized_cache(gpointer p UNUSED)
{
	GRID_INFO("Will build a cache of service lists at %"
			G_GINT64_FORMAT"µs interval", srv_cache_interval);
	while (grid_main_is_running()) {
		gint64 start = oio_ext_monotonic_time();
		_prepare_serialized_cache();
		gint64 duration = oio_ext_monotonic_time() - start;
		if (duration >= srv_cache_interval) {
			GRID_WARN("Service cache serialization took %"G_GINT64_FORMAT
					"µs, interval is %"G_GINT64_FORMAT"µs",
					duration, srv_cache_interval);
		} else {
			g_usleep(srv_cache_interval - duration);
		}
	}
	return NULL;
}

/* Persistence of services status -------------------------------------------*/

static gboolean
serialize_info(struct conscience_srv_s *srv, gpointer buffer)
{
	GByteArray *all_encoded = (GByteArray *) buffer;
	GByteArray *srv_encoded = _conscience_srv_serialize_full(srv);
	g_byte_array_append(all_encoded, srv_encoded->data, srv_encoded->len);
	g_byte_array_free(srv_encoded, TRUE);
	return TRUE;
}

static void
write_status(gchar *path)
{
	GError *err = NULL;
	guint nb_services = 0;
	GByteArray *all_encoded = g_byte_array_sized_new(8192);
	g_byte_array_append(all_encoded, header, 2);

	g_mutex_lock(&persistence_lock);

	gchar **services_names = conscience_get_srvtype_names();
	for (gchar **name = services_names; *name; name++){
		err = conscience_run_srvtypes(*name, serialize_info, all_encoded);

		if (err) {
			GRID_ERROR("Failed to get service info: (%d) %s",
				err->code, err->message);
			goto end;
		} else {
			nb_services++;
		}
	}

	g_byte_array_append(all_encoded, footer, 2);

#if GLIB_CHECK_VERSION(2,66,0)
	if (!g_file_set_contents_full(
			path, (const gchar *)all_encoded->data, all_encoded->len,
			G_FILE_SET_CONTENTS_DURABLE, 0644, &err)) {
#else
	if (!g_file_set_contents(
			path, (const gchar *)all_encoded->data, all_encoded->len, &err)) {
#endif
		GRID_ERROR("Failed to write service status in [%s]: (%d) %s",
			path, err->code, err->message);
	}
end:
	g_mutex_unlock(&persistence_lock);

	g_clear_error(&err);
	g_byte_array_free(all_encoded, TRUE);
	g_free(services_names);
}

static gboolean
restart_srv_from_file(gchar *path)
{
	gchar *all_encoded = NULL;
	GError *err = NULL;
	gsize length;

	if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
		return FALSE;
	}

	gboolean ret = FALSE;

	if (!g_file_get_contents(path, &all_encoded, &length, &err)) {
		GRID_ERROR("Failed to read services status from file [%s] (%d) %s",
			path, err->code, err->message);
		goto restart_end;
	}
	GSList *si_l = NULL;

	service_info_unmarshall(&si_l, all_encoded, length, &err);

	if (err) {
		GRID_ERROR("Failed to unmarshall service info: (%d) %s",
				err->code, err->message);
		goto restart_end;
	}

	for (GSList *si = si_l; si; si = si->next) {
		struct service_info_s *si_data = si->data;
		score_t old_put_score = si_data->put_score;
		score_t old_get_score = si_data->get_score;

		struct conscience_srvtype_s *srvtype = conscience_get_srvtype(
				si_data->type, FALSE);
		if (!srvtype) {
			GRID_ERROR("Service type [%s/%s] not found",
					oio_server_namespace, si_data->type);
		} else {
			/* service is not registered if score.value != 0 */
			si_data->put_score.value = 0;
			si_data->get_score.value = 0;
			/* As we don't know the modification time,
			 * set the lock modification time to 0. */
			struct service_info_dated_s *sid = service_info_dated_new(
					si_data, 0);
			struct conscience_srv_s *p_srv =
					conscience_srvtype_refresh_dated(srvtype, sid);

			/* If the lock tag exist and is true, lock both scores. */
			struct service_tag_s *tag_lock = service_info_get_tag(
					si_data->tags, NAME_TAGNAME_LOCK);
			if (tag_lock && tag_lock->type == STVT_BOOL && tag_lock->value.b) {
				p_srv->put_locked = tag_lock->value.b;
				p_srv->get_locked = tag_lock->value.b;

			/* Otherwise, restore PUT/GET lock independently */
			} else {
				/* If the put score was locked, lock it again. */
				struct service_tag_s *tag_put_lock = service_info_get_tag(
						si_data->tags, NAME_TAGNAME_PUT_LOCK);
				if (tag_put_lock) {
					service_tag_get_value_boolean(tag_put_lock, &(p_srv->put_locked), &err);
					if (err) {
						GRID_WARN("Failed to read put lock tag: %s", err->message);
						g_clear_error(&err);
					}
				}
				/* If the get score was locked, lock it again. */
				struct service_tag_s *tag_get_lock = service_info_get_tag(
						si_data->tags, NAME_TAGNAME_GET_LOCK);
				if (tag_get_lock) {
					service_tag_get_value_boolean(tag_get_lock, &(p_srv->get_locked), &err);
					if (err) {
						GRID_WARN("Failed to read get lock tag: %s", err->message);
						g_clear_error(&err);
					}
				}
			}

			/* force score to allow _task_expire to pass since
			 * it should not possible to have unlocked service with score 0 */
			p_srv->put_score = old_put_score;
			p_srv->get_score = old_get_score;

			service_info_dated_free(sid);
		}
	}
	ret = 0;
	g_slist_free_full (si_l, (GDestroyNotify) service_info_clean);

restart_end:
	if (err != NULL) {
		g_error_free(err);
	}
	g_free(all_encoded);
	return ret;
}

static gboolean
restart_srv_from_other_consciences(void)
{
	gboolean res = TRUE;
	GError *err = NULL;
	GSList *all_services = NULL;

	err = conscience_get_services(
			oio_server_namespace, "all", TRUE, &all_services, 0);

	if (!err) {
		guint count = 0;
		for (GSList *l = all_services; l; l = g_slist_next(l)) {
			struct service_info_s *si = l->data;
			if (!metautils_addr_valid_for_connect(&si->addr)
					|| !oio_str_is_set(si->type)) {
				continue;
			}
			gboolean is_locked = FALSE;
			struct service_tag_s *lock_tag = NULL;
			/* If there is no lock, we must declare the score as "unset", and
			 * let the conscience compute it. Any other value will lock it. */
			lock_tag = service_info_get_tag(si->tags, NAME_TAGNAME_GET_LOCK);
			if (!(service_tag_get_value_boolean(lock_tag, &is_locked, NULL)
					&& is_locked)) {
				si->get_score.value = SCORE_UNSET;
			}
			lock_tag = service_info_get_tag(si->tags, NAME_TAGNAME_PUT_LOCK);
			if (!(service_tag_get_value_boolean(lock_tag, &is_locked, NULL)
					&& is_locked)) {
				si->put_score.value = SCORE_UNSET;
			}
			struct service_info_dated_s *sid = push_service(si);
			if (sid) {
				service_info_dated_free(sid);
			}
			++count;
		}
		GRID_NOTICE("Loaded %u services from other consciences (reqid=%s)",
				count, oio_ext_get_reqid());
	} else {
		res = FALSE;
		GRID_WARN("Failed to load services from other consciences: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
	g_slist_free_full(all_services, (GDestroyNotify) service_info_clean);
	return res;
}

/* Main -------------------------------------------------------------------- */

static void
_patch_and_apply_configuration(void)
{
	if (server_fd_max_passive <= 0) {
		const guint maxfd = metautils_syscall_count_maxfd();
		const guint reserved = 32;
		server_fd_max_passive = maxfd - reserved;
	}

	network_server_reconfigure(server);
}

static void
_reconfigure_on_SIGHUP(void)
{
	GRID_NOTICE("SIGHUP! Reconfiguring...");
	oio_var_reset_all();
	oio_var_value_with_files(oio_server_namespace, config_system, config_paths);
	_patch_and_apply_configuration();
}

static void
_cs_action(void)
{
	GError *err = network_server_open_servers (server);
	if (err) {
		GRID_ERROR ("Failed to open the server sockets: (%d) %s", err->code, err->message);
		g_clear_error (&err);
		grid_main_set_status (1);
		return;
	}

	if (!(th_admin = grid_task_queue_run (gtq_admin, &err))) {
		GRID_ERROR ("Failed to start the admin tasks: (%d) %s", err->code, err->message);
		g_clear_error (&err);
		grid_main_set_status (1);
		return;
	}

	GRID_NOTICE("[NS=%s] Starting serving requests", oio_server_namespace);
	network_server_run (server, _reconfigure_on_SIGHUP);
}

static void
_cs_specific_stop(void)
{
	grid_task_queue_stop(gtq_admin);
	if (persistence_path)
		write_status(persistence_path->str);
	network_server_stop(server);
}

static GError*
_cs_configure_with_file(const char *path UNUSED)
{
	GError *err = NULL;
	GKeyFile *gkf = g_key_file_new();
	if (!g_key_file_load_from_file(gkf, path, G_KEY_FILE_NONE, &err))
		return err;

	service_url = g_key_file_get_value(gkf,
			"Server.conscience", "listen", NULL);
	gchar *tmp = g_key_file_get_value(gkf,
			"Plugin.conscience", "service_cache.enable", NULL);
	/* g_key_file_get_boolean() is case-sensitive */
	cache_service_lists = oio_str_parse_bool(tmp, FALSE);
	g_free(tmp);
	tmp = g_key_file_get_value(gkf,
			"Plugin.conscience", "service_cache.enable_full", NULL);
	cache_full_service_lists = oio_str_parse_bool(tmp, FALSE);
	g_free(tmp);
	if (g_key_file_has_key(
			gkf, "Plugin.conscience", "service_cache.interval", NULL)) {
		srv_cache_interval = MAX(100, (gint64)(
				g_key_file_get_double(gkf,
					"Plugin.conscience", "service_cache.interval", NULL)
				* G_TIME_SPAN_SECOND
		));
	}
	tmp = g_key_file_get_value(gkf,
			"Plugin.conscience", "synchronize_at_startup", NULL);
	synchronize_at_startup = oio_str_parse_bool(tmp, FALSE);
	g_free(tmp);
	tmp = g_key_file_get_value(gkf,
			"Plugin.conscience", "flush_stats_on_refresh", NULL);
	flush_stats_on_refresh = oio_str_parse_bool(tmp, FALSE);
	g_free(tmp);
	hub_me = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_hub.me", NULL);
	hub_group = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_hub.group", NULL);
	hub_publish_stale_delay = g_key_file_get_integer(gkf,
			"Plugin.conscience", "param_hub.publish_stale_delay", NULL);
	hub_startup_delay = g_key_file_get_integer(gkf,
			"Plugin.conscience", "param_hub.startup_delay", NULL);
	hub_threads = g_key_file_get_integer(gkf,
			"Plugin.conscience", "param_hub.threads", NULL);
	path_stgpol = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_storage_conf", NULL);
	path_srvcfg = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_service_conf", NULL);
	oio_server_namespace = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_namespace", NULL);
	g_strlcpy(nsinfo->name, oio_server_namespace, sizeof(nsinfo->name));
	statsd_host = g_key_file_get_value(gkf,
			"Plugin.conscience", "statsd.host", NULL);
	statsd_port = g_key_file_get_integer(gkf,
			"Plugin.conscience", "statsd.port", NULL);

	g_key_file_free(gkf);
	gkf = NULL;

	if (!service_url)
		return BADREQ("Missing value [%s]", "listen");
	if (!oio_server_namespace)
		return BADREQ("Missing value [%s]", "param_namespace");
	if (!path_stgpol)
		return BADREQ("Missing value [%s]", "param_storage_conf");
	if (!path_srvcfg)
		return BADREQ("Missing value [%s]", "param_service_conf");

	return NULL;
}

static GError *
fill_hashtable_with_group(GHashTable *ht, GKeyFile *gkf, const gchar *group)
{
	if (!g_key_file_has_group (gkf, group))
		return SYSERR("No '%s' group in configuration", group);

	GError *e = NULL;
	gchar **keys = g_key_file_get_keys (gkf, group, NULL, &e);
	if (!keys)
		return e;

	for (gchar **pkey = keys ; *pkey ;++pkey) {
		gchar *v = g_key_file_get_value (gkf, group, *pkey, NULL);
		if (NULL != g_hash_table_lookup(ht, *pkey))
			GRID_WARN("Duplicate key [%s][%s], new value [%s]", group, *pkey, v);
		g_hash_table_insert (ht, g_strdup(*pkey), metautils_gba_from_string(v));
		GRID_TRACE2("%s [%s] <- [%s]", group, *pkey, v);
		g_free(v);
	}

	g_strfreev(keys);
	return NULL;
}

static GError *
_init_storage_policies(const gchar *filepath)
{
	GString *names = g_string_new("");

	void _check_for_keyword(gchar *key, gpointer value UNUSED, gchar **what) {
		g_string_append_printf(names, " %s", key);
		if (!g_ascii_strcasecmp(what[0], key)) {
			GRID_WARN("Redefining '%s' %s, this may not be taken into account",
					key, what[1]);
		}
	}

	EXTRA_ASSERT(filepath != NULL);

	GError *e = NULL;
	GKeyFile *stg_conf_file = g_key_file_new();
	if (!g_key_file_load_from_file (stg_conf_file, filepath, G_KEY_FILE_NONE, &e)) {
		g_prefix_error(&e, "Parsing error [%s]: ", filepath);
		goto label_exit;
	}

	/* POLICIES */
	e = fill_hashtable_with_group(nsinfo->storage_policy,
			stg_conf_file, NAME_GROUPNAME_STORAGE_POLICY);
	if (NULL != e) {
		g_prefix_error(&e, "Storage policies [%s]: ", filepath);
		goto label_exit;
	} else {
		g_string_truncate(names, 0);
		g_hash_table_foreach(nsinfo->storage_policy, (GHFunc)_check_for_keyword,
				(gchar*[2]){STORAGE_POLICY_NONE, "storage policy"});
		GRID_NOTICE("Policies%s", names->str);
	}

	/* SECURITY */
	e = fill_hashtable_with_group(nsinfo->data_security,
			stg_conf_file, NAME_GROUPNAME_DATA_SECURITY);
	if (NULL != e) {
		g_prefix_error(&e, "Data security [%s]", filepath);
		goto label_exit;
	} else {
		g_string_truncate(names, 0);
		g_hash_table_foreach(nsinfo->data_security, (GHFunc)_check_for_keyword,
				(gchar*[2]){DATA_SECURITY_NONE, "data security"});
		GRID_NOTICE("Securities%s", names->str);
	}

label_exit:
	if (names) g_string_free(names, TRUE);
	g_key_file_free(stg_conf_file);
	return e;
}

static void
module_init_known_service_types(void)
{
	static struct srvtype_init_s {
		const gchar *name;
		const gchar *expr;
	} types_to_init[] = {
		{NAME_SRVTYPE_META0,EXPR_DEFAULT_META0},
		{NAME_SRVTYPE_META1,EXPR_DEFAULT_META1},
		{NAME_SRVTYPE_META2,EXPR_DEFAULT_META2},
		{NAME_SRVTYPE_RAWX,EXPR_DEFAULT_RAWX},
		{0,0}
	};

	for (struct srvtype_init_s *type=types_to_init; type->name ; type++) {
		struct conscience_srvtype_s *config = conscience_get_srvtype(type->name, TRUE);
		config->alert_frequency_limit = TIME_DEFAULT_ALERT_LIMIT;
		gboolean rc = conscience_srvtype_set_type_expression(
				config, NULL, type->expr, PUT | GET);
		g_assert_true(rc);
	}
}

static gboolean
_configure_srvtype(GError ** err, const gchar * type, const gchar * what, const gchar * value)
{
	EXTRA_ASSERT(what != NULL);
	EXTRA_ASSERT(value != NULL);

	/*find the service type */
	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(type, TRUE);
	if (!srvtype) {
		GSETERROR(err, "Failed to init a ServiceType");
		return FALSE;
	}

	/* adjust the parameter */
	if (g_ascii_strcasecmp(what, KEY_SCORE_TIMEOUT) == 0) {
		srvtype->score_expiration = g_ascii_strtoll(value, NULL, 10);
		GRID_INFO("[NS=%s][SRVTYPE=%s] score expiration set to [%ld] seconds",
				nsinfo->name, srvtype->type_name,
				srvtype->score_expiration);
		return TRUE;
	} else if (g_ascii_strcasecmp(what, KEY_SCORE_VARBOUND) == 0) {
		srvtype->score_variation_bound = g_ascii_strtoll(value, NULL, 10);
		GRID_INFO("[NS=%s][SRVTYPE=%s] score variation bound set to [%d]",
				nsinfo->name, srvtype->type_name,
				srvtype->score_variation_bound);
		return TRUE;
	} else if (g_ascii_strcasecmp(what, KEY_SCORE_EXPR) == 0) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value, PUT | GET)) {
			GRID_INFO("[NS=%s][SRVTYPE=%s] score expression set to [%s]",
					nsinfo->name, srvtype->type_name, value);
			return TRUE;
		}
		return FALSE;
	} else if (g_ascii_strcasecmp(what, KEY_PUT_SCORE_EXPR) == 0) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value, PUT)) {
			GRID_INFO("[NS=%s][SRVTYPE=%s] put score expression set to [%s]",
					nsinfo->name, srvtype->type_name, value);
			return TRUE;
		}
		return FALSE;
	} else if (g_ascii_strcasecmp(what, KEY_GET_SCORE_EXPR) == 0) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value, GET)) {
			GRID_INFO("[NS=%s][SRVTYPE=%s] get score expression set to [%s]",
					nsinfo->name, srvtype->type_name, value);
			return TRUE;
		}
		return FALSE;
	} else if (g_ascii_strcasecmp(what, KEY_SCORE_LOCK) == 0) {
		srvtype->lock_at_first_register = oio_str_parse_bool(value, TRUE);
		GRID_INFO("[NS=%s][SRVTYPE=%s] lock at first register: %s",
				nsinfo->name, srvtype->type_name,
				srvtype->lock_at_first_register? "yes":"no");
		return TRUE;
	} else if (g_ascii_strcasecmp(what, KEY_ALERT_LIMIT) == 0) {
		srvtype->alert_frequency_limit = g_ascii_strtoll(value, NULL, 10);
		GRID_INFO("[NS=%s][SRVTYPE=%s] Alert limit set to %ld",
				nsinfo->name, srvtype->type_name, srvtype->alert_frequency_limit);
		return TRUE;
	} else {
		GRID_WARN("[NS=%s][SRVTYPE=%s] parameter not recognized [%s] (ignored!)",
				nsinfo->name, srvtype->type_name, what);
		return TRUE;
	}
}

static void
_configure_srvpool(const char *pool, const char *what, const char *value)
{
	EXTRA_ASSERT(pool != NULL);
	EXTRA_ASSERT(what != NULL && *what != '\0');
	EXTRA_ASSERT(value != NULL && *value != '\0');

	GHashTable *svc_pools = nsinfo->service_pools;
	GByteArray *gba = g_hash_table_lookup(svc_pools, pool);
	if (!strcmp(what, KEY_POOL_TARGETS)) {
		/* Targets are passed without key, but must start with a digit */
		if (!g_ascii_isdigit(*value))
			return;
		if (!gba) {
			gba = metautils_gba_from_string(value);
			g_hash_table_insert(svc_pools, g_strdup(pool), gba);
		} else {
			g_byte_array_append(gba, (guint8*)";", 1);
			g_byte_array_append(gba, (guint8*)value, strlen(value));
		}
	} else {
		if (!gba) {
			gchar buf[256] = {0};
			g_snprintf(buf, sizeof(buf), "%s=%s", what, value);
			gba = metautils_gba_from_string(buf);
			g_hash_table_insert(svc_pools, g_strdup(pool), gba);
		} else {
			g_byte_array_append(gba, (guint8*)";", 1);
			g_byte_array_append(gba, (guint8*)what, strlen(what));
			g_byte_array_append(gba, (guint8*)"=", 1);
			g_byte_array_append(gba, (guint8*)value, strlen(value));
		}
	}
}

static GError *
_load_service_type_section(GKeyFile *svc_conf_file, const gchar *section)
{
	/*** sample **************************************************************
	[type:meta0]
	score_expr = root(3,((num stat.cpu)*(num stat.space)*(num stat.io)))
	score_variation_bound = 5
	score_timeout = 300
	lock_at_first_register = false
	*************************************************************************/
	const char *svc = section + strlen(GROUP_PREFIX_TYPE);
	GHashTable *content = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	GError *err = fill_hashtable_with_group(content, svc_conf_file, section);
	if (err) {
		g_hash_table_destroy(content);
		return err;
	}
	void _configure_section(gchar *key, GByteArray *gba, gpointer u UNUSED) {
		GError *local_err = NULL;
		/* FIXME: no '\0' */
		_configure_srvtype(&local_err, svc, key, (const char*)gba->data);
		if (local_err) {
			GRID_WARN("Failed to set %s for %s: %s",
					key, svc, local_err->message);
			g_clear_error(&local_err);
		}
	}
	g_hash_table_foreach(content, (GHFunc)_configure_section, NULL);
	g_hash_table_destroy(content);
	return err;
}

static GError *
_load_service_pool_section(GKeyFile *svc_conf_file, const char *section)
{
	/*** sample **************************************************************
	[pool:rawx3]
	targets = 1,rawx-even,rawx;1,rawx-odd,rawx;1,rawx
	*************************************************************************/
	const char *pool = section + strlen(GROUP_PREFIX_POOL);
	GHashTable *content = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	GError *err = fill_hashtable_with_group(content, svc_conf_file, section);
	if (err) {
		g_hash_table_destroy(content);
		return err;
	}
	void _configure_section(gchar *key, GByteArray *gba, gpointer u UNUSED) {
		_configure_srvpool(pool, key, (const char*)gba->data);  // FIXME: no '\0'
	}
	g_hash_table_foreach(content, (GHFunc)_configure_section, NULL);
	g_hash_table_destroy(content);
	return NULL;
}

static GError *
_init_service_conf(const gchar *filepath)
{
	GError *err = NULL;
	GKeyFile *svc_conf_file = g_key_file_new();

	if (!g_key_file_load_from_file(svc_conf_file, filepath,
			G_KEY_FILE_NONE, &err)) {
		GRID_WARN("[NS=%s] service configuration from %s failed: %s",
				nsinfo->name, filepath, err->message);
		g_key_file_free(svc_conf_file);
		return err;
	} else {
		GRID_INFO("Loading service configuration from %s", filepath);
	}

	gchar **groups = g_key_file_get_groups(svc_conf_file, NULL);
	for (gchar **group = groups; groups && *group; group++) {
		if (g_str_has_prefix(*group, GROUP_PREFIX_POOL)) {
			err = _load_service_pool_section(svc_conf_file, *group);
		} else if (g_str_has_prefix(*group, GROUP_PREFIX_TYPE)) {
			err = _load_service_type_section(svc_conf_file, *group);
		} else {
			GRID_WARN("Unknown configuration group: [%s] in file %s",
					*group, filepath);
		}
		if (err) {
			GRID_WARN("%s", err->message);
			g_clear_error(&err);
		}
	}
	g_strfreev(groups);
	g_key_file_free(svc_conf_file);
	return err;
}

static GError *
_init_services(const gchar *pattern)
{
	GError *err = NULL;
	glob_t globbuf = {};
	module_init_known_service_types();
	switch (glob(pattern, GLOB_MARK|GLOB_NOSORT|GLOB_BRACE, NULL, &globbuf)) {
		case GLOB_NOMATCH:
			err = SYSERR("No file matched [%s]", pattern);
			break;
		default:
			err = SYSERR("Failed to do pattern matching with [%s]", pattern);
		case 0:
			break;
	}

	for (char **path = globbuf.gl_pathv; !err && path && *path; path++) {
		if (g_str_has_suffix(*path, "/"))
			continue;
		err = _init_service_conf(*path);
	}

	globfree(&globbuf);
	return err;
}

#define DUAL_ERROR(FMT,...) do { \
	g_printerr("\n*** " FMT " ***\n\n", ##__VA_ARGS__); \
	GRID_ERROR(FMT, ##__VA_ARGS__); \
} while (0)

static gboolean
_config_error(const char *where, GError *err)
{
	DUAL_ERROR("Configuration error: %s: (%d) %s", where, err->code, err->message);
	g_clear_error(&err);
	return FALSE;
}

static gboolean
_cs_configure(int argc, char **argv)
{
	struct gridd_request_descr_s descr[] = {
		{"CS_CFG", _cs_dispatch_NSINFO, NULL},
		{"CS_SRV", _cs_dispatch_SRV, NULL},
		{"CS_TYP", _cs_dispatch_TYPES, NULL},
		{"CS_PSH", _cs_dispatch_PUSH, NULL},
		{"CS_DEL", _cs_dispatch_RM, NULL},
		{NULL, NULL, NULL}
	};

	if (argc != 1) {
		GRID_ERROR("Missing mandatory parameter");
		return FALSE;
	}

	gq_count_hub_flush = g_quark_from_static_string("counter req.hits.hub_flush");
	gq_time_hub_flush = g_quark_from_static_string("counter req.time.hub_flush");
	gq_count_hub_remove = g_quark_from_static_string("counter req.hits.hub_remove");
	gq_lag_hub_remove = g_quark_from_static_string("counter req.lag.hub_remove");
	gq_time_hub_remove = g_quark_from_static_string("counter req.time.hub_remove");
	gq_count_hub_update = g_quark_from_static_string("counter req.hits.hub_update");
	gq_lag_hub_update = g_quark_from_static_string("counter req.lag.hub_update");
	gq_time_hub_update = g_quark_from_static_string("counter req.time.hub_update");

	GError *err;
	if ((err = _cs_configure_with_file(argv[0])))
		return _config_error(argv[0], err);

	/* Load the central configuration facility, it will tell us our
	 * NS is locally known. */
	if (!oio_var_value_with_files(oio_server_namespace,
			config_system, config_paths)) {
		DUAL_ERROR("NS [%s] unknown in the configuration",
				oio_server_namespace);
		return FALSE;
	}
	_patch_and_apply_configuration();

	/* Start statsd client */
	if (statsd_host) {
		network_server_configure_statsd(
				server, "openio.conscience", statsd_host, statsd_port);
	} else if (oio_str_is_set(server_statsd_host)) {
		network_server_configure_statsd(
				server, "openio.conscience", server_statsd_host, server_statsd_port);
	}

	/* Start inter-conscience communication */
	if ((err = _init_hub ()))
		return _config_error("HUB", err);

	/* Load storage policy information (part of nsinfo) */
	if ((err = _init_storage_policies(path_stgpol)))
		return _config_error("Policies", err);

	/* Load service type information (score expressions, timeouts, etc.) */
	if ((err = _init_services(path_srvcfg)))
		return _config_error("Services", err);

	/* Prepare nsinfo cache */
	nsinfo_cache = namespace_info_marshall (nsinfo, NULL);

	/* Prepare serialized service lists cache */
	g_mutex_lock(&srv_lists_lock);
	srv_list_cache = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	full_srv_list_cache = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	g_mutex_unlock(&srv_lists_lock);

	/* Prepare the ASN.1 request server */
	transport_gridd_dispatcher_add_requests (dispatcher, descr, NULL);
	network_server_bind_host(server, service_url, dispatcher, transport_gridd_factory);

	/* Start internal tasks */
	grid_task_queue_register(gtq_admin, 1, _task_expire, NULL, NULL);

	/* Optionally preload service lists from a persistence file */
	if (persistence_path) {
		restart_srv_from_file(persistence_path->str);
		grid_task_queue_register(gtq_admin, persistence_period,
				(GDestroyNotify)write_status,
				NULL, persistence_path->str);
	}

	if (hub_running) {
		/* Optionally preload service lists from other conscience instances */
		if (synchronize_at_startup) {
			restart_srv_from_other_consciences();
		}
		/* Optionally wait for services updated from the hub */
		if (hub_startup_delay > 0) {
			GRID_INFO("HUB: waiting %ds before serving requests",
					hub_startup_delay);
			g_usleep(hub_startup_delay * G_TIME_SPAN_SECOND);
		}
		grid_task_queue_register(gtq_admin, 5, _task_check_hub, NULL, NULL);
		if (hub_publish_stale_delay > 0) {
			grid_task_queue_register(
					gtq_admin, 5, _task_publish_stale_services, NULL, NULL);
		}
	}

	/* If configured, prepare a cache of serialized services */
	if (cache_service_lists || cache_full_service_lists) {
		/* Do it once now, */
		_prepare_serialized_cache();
		/* then start a thread to do it regularly. */
		srv_cache_thread = g_thread_new(
				"srv-cache", _worker_prepare_serialized_cache, NULL);
		g_assert(srv_cache_thread != NULL);
	}

	return TRUE;
}

static void
_cs_set_defaults(void)
{
	gtq_admin = grid_task_queue_create ("admin");
	server = network_server_init();
	dispatcher = transport_gridd_build_empty_dispatcher ();

	g_mutex_init(&persistence_lock);
	g_mutex_init(&srv_lists_lock);
	g_rw_lock_init(&rwlock_srv);
	srvtypes = g_tree_new_full(metautils_strcmp3, NULL,
			g_free, (GDestroyNotify) conscience_srvtype_destroy);

	nsinfo = g_malloc0 (sizeof(struct namespace_info_s));
	namespace_info_init (nsinfo);
}

static void
_cs_specific_fini(void)
{
	/* stop phase */
	hub_running = FALSE;
	if (server) {
		network_server_stop (server);
		network_server_close_servers (server);
	}
	if (gtq_admin)
		grid_task_queue_stop (gtq_admin);

	/* Close phase */
	if (th_admin) g_thread_join (th_admin);
	if (srv_cache_thread) g_thread_join(srv_cache_thread);
	if (server) network_server_clean (server);
	if (dispatcher) gridd_request_dispatcher_clean (dispatcher);
	if (gtq_admin) grid_task_queue_destroy (gtq_admin);
	if (hub_thread_sub) g_thread_join(hub_thread_sub);
	if (hub_thread_pub) g_thread_join(hub_thread_pub);

	/* Stop the hub, close its ZMQ context and flush its queue */
	if (hub_zpub) zmq_close(hub_zpub);
	if (hub_zsub) zmq_close(hub_zsub);
	if (hub_zctx) zmq_term(hub_zctx);
	if (pool_update_srv) {
		g_thread_pool_free(pool_update_srv, FALSE, TRUE);
		pool_update_srv = NULL;
	}
	if (hub_queue) {
		for (gchar *m = g_async_queue_try_pop(hub_queue); m ;
				m = g_async_queue_try_pop(hub_queue))
			g_free(m);
		g_async_queue_unref(hub_queue);
	}

	metautils_gba_unref (nsinfo_cache);
	g_mutex_lock(&srv_lists_lock);
	g_hash_table_unref(srv_list_cache);
	g_hash_table_unref(full_srv_list_cache);
	g_mutex_unlock(&srv_lists_lock);
	namespace_info_free (nsinfo);

	g_rw_lock_clear(&rwlock_srv);
	g_mutex_clear(&srv_lists_lock);
	g_mutex_clear(&persistence_lock);
	if (srvtypes)
		g_tree_destroy(srvtypes);

	oio_str_clean(&service_url);
	oio_str_clean(&hub_me);
	oio_str_clean(&hub_group);
	oio_str_clean(&path_srvcfg);
	oio_str_clean(&path_stgpol);
	oio_str_clean((gchar **)&oio_server_namespace);
	oio_str_clean(&statsd_host);
}

static struct grid_main_option_s *
_cs_get_options(void)
{
	static struct grid_main_option_s _cs_options[] = {
		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

		{"PersistencePath", OT_STRING, {.str = &persistence_path},
			"Path used to register services status"},

		{"PersistencePeriod", OT_TIME, {.t = &persistence_period},
			"Period during which services are updated, in seconds"},

		{NULL, 0, {.i = 0}, NULL}
	};
	return _cs_options;
}

static const char * _cs_usage(void) { return "PATH"; }

int
main(int argc, char ** argv)
{
	struct grid_main_callbacks callbacks = {
		.options = _cs_get_options,
		.action = _cs_action,
		.set_defaults = _cs_set_defaults,
		.specific_fini = _cs_specific_fini,
		.configure = _cs_configure,
		.usage = _cs_usage,
		.specific_stop = _cs_specific_stop,
	};
	return grid_main(argc, argv, &callbacks);
}
