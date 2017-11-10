/*
OpenIO SDS conscience central server
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
static gchar *path_stgpol = NULL;
static gchar *path_srvcfg = NULL;
static gchar *nsname = NULL;

static GRWLock rwlock_srv = {};
static GTree *srvtypes = NULL;

static gboolean flag_serialize_srvinfo_stats = FALSE;
static gboolean flag_serialize_srvinfo_tags = TRUE;

static gboolean config_system = TRUE;
static GSList *config_paths = NULL;

/* ------------------------------------------------------------------------- */

# ifndef LIMIT_LENGTH_SRVDESCR
#  define LIMIT_LENGTH_SRVDESCR (LIMIT_LENGTH_SRVTYPE + 1 + STRLEN_ADDRINFO)
# endif

struct conscience_srv_s {
	addr_info_t addr;

	struct conscience_srvtype_s *srvtype;
	GPtrArray *tags;
	GByteArray *cache;

	score_t score;
	time_t time_last_alert;
	gboolean locked;

	/*a ring by service type */
	struct conscience_srv_s *next;
	struct conscience_srv_s *prev;

	gchar description[LIMIT_LENGTH_SRVDESCR];
};

struct conscience_srvtype_s
{
	gchar *score_expr_str;
	struct expr_s *score_expr;
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
conscience_srv_destroy(struct conscience_srv_s *service)
{
	if (!service)
		return;

	/* free the tags */
	if (service->tags) {
		while (service->tags->len > 0) {
			struct service_tag_s *tag = g_ptr_array_index(service->tags, 0);
			service_tag_destroy(tag);
			g_ptr_array_remove_index_fast(service->tags, 0);
		}
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
conscience_srv_compute_score(struct conscience_srv_s *service)
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

	EXTRA_ASSERT(service != NULL);
	srvtype = service->srvtype;
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(srvtype->score_expr != NULL);

	if (service->locked)
		return TRUE;

	gdouble d = 0.0;
	if (expr_evaluate(&d, srvtype->score_expr, getAcc))
		return FALSE;

	gint32 current = isnan(d) ? 0 : floor(d);

	if (service->score.value >= 0) {
		if (srvtype->score_variation_bound > 0) {
			gint32 max = service->score.value + srvtype->score_variation_bound;
			current = MIN(current,max);
		}
	}

	service->score.value = CLAMP(current, 0, 100);
	return TRUE;
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
	memcpy(&dst->score, &src->score, sizeof(score_t));
	g_strlcpy(dst->type, src->srvtype->type_name, sizeof(dst->type));
	g_strlcpy(dst->ns_name, nsname, sizeof(dst->ns_name));
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
	struct service_info_s *si = g_malloc0(sizeof(struct service_info_s));
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
	service_info_clean(si);
	return gba;
}

static void
_conscience_srv_prepare_cache(struct conscience_srv_s *srv)
{
	conscience_srv_clean_udata(srv);
	srv->cache = _conscience_srv_serialize(srv);
}

static guint
hash_service_id(gconstpointer p)
{
	return djb_hash_buf(p, sizeof(addr_info_t));
}

static gboolean
conscience_srvtype_set_type_expression(struct conscience_srvtype_s * srvtype,
	GError ** err, const gchar * expr_str)
{
	EXTRA_ASSERT(srvtype != NULL);
	EXTRA_ASSERT(expr_str != NULL);

	struct expr_s *pE = NULL;
	if (expr_parse(expr_str, &pE)) {
		GSETCODE(err, CODE_INTERNAL_ERROR,
				"Failed to parse expression '%s'",
				expr_str);
		return FALSE;
	}

	/*replaces the string */
	if (srvtype->score_expr_str)
		g_free(srvtype->score_expr_str);
	if (srvtype->score_expr)
		expr_clean(srvtype->score_expr);

	srvtype->score_expr_str = g_strdup(expr_str);
	srvtype->score_expr = pE;
	return TRUE;
}

static void
conscience_srvtype_init(struct conscience_srvtype_s *srvtype)
{
	EXTRA_ASSERT(srvtype != NULL);
	conscience_srvtype_set_type_expression(srvtype, NULL, "100");
	srvtype->alert_frequency_limit = 30;
	srvtype->score_expiration = 300;
	srvtype->score_variation_bound = 5;
	srvtype->lock_at_first_register = TRUE;
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
	if (srvtype->score_expr)
		expr_clean(srvtype->score_expr);
	if (srvtype->score_expr_str) {
		*(srvtype->score_expr_str) = '\0';
		g_free(srvtype->score_expr_str);
	}

	g_free(srvtype);
}

static void
conscience_srvtype_remove_srv(struct conscience_srvtype_s *srvtype,
		const addr_info_t *srvid)
{
	struct conscience_srv_s *srv = g_hash_table_lookup(srvtype->services_ht, srvid);
	if (srv) {
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
	service->tags = g_ptr_array_new();
	service->locked = FALSE;
	service->score.timestamp = 0;
	service->score.value = -1;
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

	time_t oldest = 0, now = oio_ext_monotonic_seconds();
	if (now > srvtype->score_expiration)
		oldest = now - srvtype->score_expiration;

	GHashTableIter iter;
	gpointer key, value;
	g_hash_table_iter_init(&iter, srvtype->services_ht);
	while (g_hash_table_iter_next(&iter, &key, &value)) {
		struct conscience_srv_s *p_srv = value;
		if (!p_srv->locked && p_srv->score.timestamp < oldest) {
			if (p_srv->score.value > 0) {
				if (callback)
					callback(p_srv, u);
				p_srv->score.value = 0;
				p_srv->score.timestamp = now;
				struct service_tag_s *tag =
						service_info_ensure_tag(p_srv->tags, NAME_TAGNAME_RAWX_UP);
				service_tag_set_value_boolean(tag, FALSE);
				conscience_srv_clean_udata(p_srv);
				count++;
			}
		}
	}

	return count;
}

static gboolean
conscience_srvtype_run_all(struct conscience_srvtype_s * srvtype,
		service_callback_f *callback, gpointer udata)
{
	const struct conscience_srv_s *beacon = &(srvtype->services_ring);
	for (struct conscience_srv_s *srv = beacon->next; srv && srv != beacon; srv = srv->next) {
		if (!callback(srv, udata))
			return FALSE;
	}
	return TRUE;
}

static struct conscience_srv_s *
conscience_srvtype_refresh(struct conscience_srvtype_s *srvtype, struct service_info_s *si)
{
	EXTRA_ASSERT (NULL != si);

	struct service_tag_s *tag_first = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_FIRST);
	gboolean really_first = FALSE;

	/* register the service if necessary, excepted if unlocking */
	struct conscience_srv_s *p_srv = g_hash_table_lookup(srvtype->services_ht, &si->addr);
	if (!p_srv) {
		if (si->score.value == SCORE_UNLOCK) {
			return NULL;
		} else {
			p_srv = conscience_srvtype_register_srv(srvtype, &si->addr);
			g_assert_nonnull (p_srv);
			really_first = tag_first && tag_first->type == STVT_BOOL && tag_first->value.b;
		}
	}

	/* refresh the tags: create missing, replace existing
	 * (but the tags are not flushed before) */
	if (si->tags) {
		GRID_TRACE("Refreshing tags for srv [%.*s]",
				(int)LIMIT_LENGTH_SRVDESCR, p_srv->description);
		const guint max = si->tags->len;
		for (guint i = 0; i < max; i++) {
			struct service_tag_s *tag = g_ptr_array_index(si->tags, i);
			if (tag == tag_first) continue;
			struct service_tag_s *orig =
				service_info_ensure_tag(p_srv->tags, tag->name);
			service_tag_copy(orig, tag);
		}
	}

	p_srv->score.timestamp = oio_ext_monotonic_seconds ();
	if (si->score.value == SCORE_UNSET || si->score.value == SCORE_UNLOCK) {
		if (really_first && srvtype->lock_at_first_register) {
			GRID_TRACE2("SRV first [%s]", p_srv->description);
			p_srv->score.value = 0;
			p_srv->locked = TRUE;
		} else {
			if (si->score.value == SCORE_UNLOCK) {
				if (p_srv->locked) {
					GRID_TRACE2("SRV unlocked [%s]", p_srv->description);
					p_srv->locked = FALSE;
					p_srv->score.value = CLAMP (p_srv->score.value, SCORE_DOWN, SCORE_MAX);
				} else {
					GRID_TRACE2("SRV already unlocked [%s]", p_srv->description);
				}
			} else { /* UNSET, a.k.a. regular computation */
				if (p_srv->locked) {
					GRID_TRACE2("SRV untouched [%s]", p_srv->description);
				} else {
					if (conscience_srv_compute_score(p_srv)) {
						GRID_TRACE2("SRV refreshed [%s]", p_srv->description);
					} /* else ... a trace is already written */
				}
			}
		}
	} else { /* LOCK */
		p_srv->score.value = CLAMP(si->score.value, SCORE_DOWN, SCORE_MAX);
		if (p_srv->locked) {
			GRID_TRACE2("SRV already locked [%s]", p_srv->description);
		} else {
			p_srv->locked = TRUE;
			GRID_TRACE2("SRV locked [%s]", p_srv->description);
		}
	}

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
		err = NEWERROR(CODE_SRVTYPE_NOTMANAGED, "Service type [%s] not managed", type);
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
static void *hub_zctx = NULL;
static void *hub_zpub = NULL;
static void *hub_zsub = NULL;
static GAsyncQueue *hub_queue = NULL;
static GThread *hub_thread_pub = NULL;
static GThread *hub_thread_sub = NULL;

static void
_et_bim_cest_dans_le_hub (gchar *m)
{
	if (*m) {
		zmq_send (hub_zpub, m, 1, ZMQ_SNDMORE);
		int rc = zmq_send (hub_zpub, m+1, strlen(m+1), ZMQ_DONTWAIT);
		if (rc > 0) {
			GRID_TRACE2("HUB published 1 service / %d bytes", rc);
		} else {
			GRID_INFO("HUB publish failed: (%d) %s", errno, strerror(errno));
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
		GRID_WARN("[NS=%s][%s][SCORE=0] service=%.*s",
				nsname, srv->srvtype->type_name,
				(int)sizeof(srv->description), srv->description);
		srv->time_last_alert = now;
	}
}

static void
push_service(struct service_info_s *si)
{
	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(si->type, FALSE);
	if (!srvtype) {
		GRID_ERROR("Service type [%s/%s] not found", nsname, si->type);
	} else {
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		struct conscience_srv_s *srv = conscience_srvtype_refresh(srvtype, si);
		if (srv) {
			/* shortcut for services tagged DOWN */
			if (!srv->locked) {
				gboolean bval = FALSE;
				struct service_tag_s *tag = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_UP);
				if (tag && service_tag_get_value_boolean(tag, &bval, NULL) && !bval) {
					srv->score.value = 0;
					_alert_service_with_zeroed_score(srv);
				}
			}
			/* Prepare the serialized form of the service */
			_conscience_srv_prepare_cache (srv);
		}
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
	}
}

static void
rm_service(struct service_info_s *si)
{
	gchar str_desc[LIMIT_LENGTH_NSNAME + LIMIT_LENGTH_SRVTYPE + STRLEN_ADDRINFO];
	int str_desc_len = g_snprintf(str_desc, sizeof(str_desc), "%s/%s/", nsname, si->type);
	grid_addrinfo_to_string(&(si->addr), str_desc + str_desc_len, sizeof(str_desc) - str_desc_len);

	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(si->type, FALSE);
	if (!srvtype) {
		GRID_ERROR("Service type not found [%s]", str_desc);
	} else {
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		conscience_srvtype_remove_srv(srvtype, &si->addr);
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
		GRID_INFO("Service removed [%s]", str_desc);
	}
}

static void
_on_push (const guint8 *b, gsize l)
{
	struct service_info_s *si = NULL;
	gchar *tmp = g_strndup ((gchar*)b, l);
	GError *err = service_info_load_json (tmp, &si, FALSE);
	EXTRA_ASSERT((err != NULL) ^ (si != NULL));
	g_free (tmp);
	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s", err->code, err->message);
		g_clear_error (&err);
	} else {
		push_service(si);
		service_info_clean (si);
	}
}

static void
_on_remove (const guint8 *b, gsize l)
{
	struct service_info_s *si = NULL;
	gchar *tmp = g_strndup ((gchar*)b, l);
	GError *err = service_info_load_json (tmp, &si, FALSE);
	EXTRA_ASSERT((err != NULL) ^ (si != NULL));
	g_free (tmp);

	if (err) {
		GRID_WARN("HUB: decoder error: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	} else {
		rm_service (si);
		service_info_clean(si);
	}
}

static void
_on_flush (const guint8 *b, gsize l)
{
	gchar *tmp = g_strndup ((gchar*)b, l);
	struct conscience_srvtype_s *srvtype = conscience_get_srvtype(tmp, FALSE);
	if (!srvtype) {
		GRID_ERROR("[NS=%s][SRVTYPE=%s] not found", nsname, tmp);
	} else {
		g_rw_lock_writer_lock(&srvtype->rw_lock);
		conscience_srvtype_flush(srvtype);
		g_rw_lock_writer_unlock(&srvtype->rw_lock);
	}

	GRID_NOTICE("[NS=%s][SRVTYPE=%s] flush done!", nsname, srvtype->type_name);
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
		if (rc > 0 && hook)
			hook (zmq_msg_data(&msg), zmq_msg_size(&msg));
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
		for (guint i=0; i<1024 ;++i) {
			zmq_msg_t msg;
			zmq_msg_init (&msg);
			rc = zmq_msg_recv (&msg, hub_zsub, ZMQ_DONTWAIT);
			if (rc < 0) {
				if (errno == ETERM) break;
				if (errno == EINTR || errno == EAGAIN) continue;
				GRID_WARN("ZMQ recv error: (%d) %s", errno, strerror(errno));
				break;
			}
			const char *action = (const char*) zmq_msg_data(&msg);
			const int more = zmq_msg_more(&msg);
			GRID_TRACE2 ("HUB message size=%d more=%d action=%c",
					rc, more, rc>0 ? *action : ' ');
			if (rc > 0) {
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
			}
			zmq_msg_close (&msg);
		}
	}

	return p;
}

static void
hub_publish_service (const struct service_info_s *si)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'P');
	service_info_encode_json (encoded, si, TRUE);
	g_async_queue_push (hub_queue, g_string_free (encoded, FALSE));
}

static void
hub_remove_service (const struct service_info_s *si)
{
	if (!hub_queue)
		return;
	GString *encoded = g_string_sized_new (256);
	g_string_append_c (encoded, 'R');
	service_info_encode_json (encoded, si, TRUE);
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
	struct service_info_s *si = g_malloc0(sizeof(struct service_info_s));
	conscience_srv_fill_srvinfo(si, srv);
	GByteArray *gba = service_info_marshall_1(si, NULL);
	service_info_clean(si);
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
	static const guint8 header[] = { 0x30, 0x80 };
	static const guint8 footer[] = { 0x00, 0x00 };
	gchar strtype[LIMIT_LENGTH_SRVTYPE] = {};

	if (!metautils_message_extract_string_noerror(
				reply->request, NAME_MSGKEY_TYPENAME, strtype, sizeof(strtype))) {
		reply->send_error(0, BADREQ("Missing/Invalid service type"));
		return TRUE;
	}

	reply->no_access();

	const gboolean full = metautils_message_extract_flag(
			reply->request, NAME_MSGKEY_FULL, FALSE);

	GByteArray *gba = g_byte_array_sized_new(8192);
	g_byte_array_append(gba, header, 2);

	GError *err = conscience_run_srvtypes(strtype,
			full ? _prepare_full : _prepare_cached, gba);

	if (err) {
		g_byte_array_free(gba, TRUE);
		reply->send_error(0, err);
	} else {
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

	GSList *list_srvinfo = NULL;
	GError *err = metautils_message_extract_body_encoded(
			reply->request, TRUE, &list_srvinfo, service_info_unmarshall);
	EXTRA_ASSERT((err != NULL) ^ (list_srvinfo != NULL));
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	/*Now push each service and reply the success */
	guint count = 0;
	for (GSList *l = list_srvinfo; l; l = g_slist_next(l)) {
		struct service_info_s *si = l->data;
		if (!metautils_addr_valid_for_connect(&si->addr)
				|| !oio_str_is_set(si->type))
			continue;
		push_service(si);
		hub_publish_service (si);
		++ count;
	}
	GRID_DEBUG("Pushed %u items", count);
	g_slist_free_full (list_srvinfo, (GDestroyNotify) service_info_clean);

	reply->send_reply(200, "OK");
	return TRUE;
}

static gboolean
_cs_dispatch_FLUSH(struct gridd_reply_ctx_s *reply)
{
	gchar strtype[LIMIT_LENGTH_SRVTYPE] = {};

	if (!metautils_message_extract_string_noerror(
				reply->request, NAME_MSGKEY_TYPENAME, strtype, sizeof(strtype))) {
		reply->send_error(0, BADREQ("Missing service type"));
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
	EXTRA_ASSERT((err != NULL) ^ (list_srvinfo != NULL));
	if (err) {
		reply->send_error(0, err);
		return TRUE;
	}

	GRID_NOTICE("[NS=%s] [%d] services to be removed",
			nsname, g_slist_length(list_srvinfo));

	for (GSList *l = list_srvinfo; l; l = l->next) {
		rm_service (l->data);
		hub_remove_service (l->data);
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

	int opt = 1;
	zmq_setsockopt (hub_zsub, ZMQ_IPV6, &opt, sizeof(int));
	zmq_setsockopt (hub_zpub, ZMQ_IPV6, &opt, sizeof(int));

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

	if (split_me)
		g_strfreev (split_me);
	return NULL;
}


/* Background tasks -------------------------------------------------------- */

static gboolean
service_expiration_notifier(struct conscience_srv_s *srv, gpointer u UNUSED)
{
	if (srv)
		GRID_INFO("Service expired [%s] (score=%d)",
				srv->description, srv->score.value);
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
	oio_var_value_with_files(nsname, config_system, config_paths);
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

	network_server_run (server, _reconfigure_on_SIGHUP);
}

static void
_cs_specific_stop(void)
{
	grid_task_queue_stop (gtq_admin);
	network_server_stop (server);
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
	hub_me = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_hub.me", NULL);
	hub_group = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_hub.group", NULL);
	path_stgpol = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_storage_conf", NULL);
	path_srvcfg = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_service_conf", NULL);
	nsname = g_key_file_get_value(gkf,
			"Plugin.conscience", "param_namespace", NULL);

	g_key_file_free(gkf);
	gkf = NULL;

	if (!service_url)
		return BADREQ("Missing value [%s]", "listen");
	if (!nsname)
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
		conscience_srvtype_init(config);
		config->alert_frequency_limit = TIME_DEFAULT_ALERT_LIMIT;
		gboolean rc = conscience_srvtype_set_type_expression(config, NULL, type->expr);
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
	if (0 == g_ascii_strcasecmp(what, KEY_SCORE_TIMEOUT)) {
		srvtype->score_expiration = g_ascii_strtoll(value, NULL, 10);
		GRID_INFO("[NS=%s][SRVTYPE=%s] score expiration set to [%ld] seconds",
				nsinfo->name, srvtype->type_name,
				srvtype->score_expiration);
		return TRUE;
	} else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_VARBOUND)) {
		srvtype->score_variation_bound = g_ascii_strtoll(value, NULL, 10);
		GRID_INFO("[NS=%s][SRVTYPE=%s] score variation bound set to [%d]",
				nsinfo->name, srvtype->type_name,
				srvtype->score_variation_bound);
		return TRUE;
	} else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_EXPR)) {
		if (conscience_srvtype_set_type_expression(srvtype, err, value)) {
			GRID_INFO("[NS=%s][SRVTYPE=%s] score expression set to [%s]",
					nsinfo->name, srvtype->type_name, value);
			return TRUE;
		}
		return FALSE;
	} else if (0 == g_ascii_strcasecmp(what, KEY_SCORE_LOCK)) {
		srvtype->lock_at_first_register = oio_str_parse_bool(value, TRUE);
		GRID_INFO("[NS=%s][SRVTYPE=%s] lock at first register: %s",
				nsinfo->name, srvtype->type_name,
				srvtype->lock_at_first_register? "yes":"no");
		return TRUE;
	} else if (0 == g_ascii_strcasecmp(what, KEY_ALERT_LIMIT)) {
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
	mask = FFFFFFFFFFFF0000
	mask_max_shift = 16
	nearby_mode=false
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

	GError *err;
	if ((err = _cs_configure_with_file(argv[0])))
		return _config_error(argv[0], err);

	/* Load the central configuration facility, it will tell us our
	 * NS is locally known. */
	if (!oio_var_value_with_files(nsname, config_system, config_paths)) {
		DUAL_ERROR("NS [%s] unknown in the configuration", nsname);
		return FALSE;
	}
	_patch_and_apply_configuration();

	if ((err = _init_hub ()))
		return _config_error("HUB", err);
	if ((err = _init_storage_policies(path_stgpol)))
		return _config_error("Policies", err);
	if ((err = _init_services(path_srvcfg)))
		return _config_error("Services", err);

	g_strlcpy(nsinfo->name, nsname, sizeof(nsinfo->name));
	nsinfo_cache = namespace_info_marshall (nsinfo, NULL);
	transport_gridd_dispatcher_add_requests (dispatcher, descr, NULL);
	network_server_bind_host(server, service_url, dispatcher, transport_gridd_factory);
	grid_task_queue_register (gtq_admin, 1, _task_expire, NULL, NULL);
	return TRUE;
}

static void
_cs_set_defaults(void)
{
	gtq_admin = grid_task_queue_create ("admin");
	server = network_server_init();
	dispatcher = transport_gridd_build_empty_dispatcher ();

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
	if (server) network_server_clean (server);
	if (dispatcher) gridd_request_dispatcher_clean (dispatcher);
	if (gtq_admin) grid_task_queue_destroy (gtq_admin);
	if (hub_thread_sub) g_thread_join(hub_thread_sub);
	if (hub_thread_pub) g_thread_join(hub_thread_pub);

	/* Stop the hub, close its ZMQ context and flush its queue */
	if (hub_zpub) zmq_close(hub_zpub);
	if (hub_zsub) zmq_close(hub_zsub);
	if (hub_zctx) zmq_term(hub_zctx);
	if (hub_queue) {
		for (gchar *m = g_async_queue_try_pop(hub_queue); m ;
				m = g_async_queue_try_pop(hub_queue))
			g_free(m);
		g_async_queue_unref(hub_queue);
	}

	metautils_gba_unref (nsinfo_cache);
	namespace_info_free (nsinfo);

	g_rw_lock_clear(&rwlock_srv);
	if (srvtypes)
		g_tree_destroy(srvtypes);

	oio_str_clean(&service_url);
	oio_str_clean(&hub_me);
	oio_str_clean(&hub_group);
	oio_str_clean(&path_srvcfg);
	oio_str_clean(&path_stgpol);
	oio_str_clean(&nsname);
}

static struct grid_main_option_s *
_cs_get_options(void)
{
	static struct grid_main_option_s _cs_options[] = {
		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

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
