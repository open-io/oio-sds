/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2025 OVH SAS

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

#include <malloc.h>

#include "common.h"
#include "actions.h"

static struct path_parser_s *path_parser = NULL;
static struct network_server_s *server = NULL;

static struct grid_task_queue_s *admin_gtq = NULL;
static struct grid_task_queue_s *upstream_gtq = NULL;
static struct grid_task_queue_s *downstream_gtq = NULL;

static GThread *admin_thread = NULL;
static GThread *upstream_thread = NULL;
static GThread *downstream_thread = NULL;

static gboolean config_system = TRUE;
static GSList *config_paths = NULL;
static GSList *config_urlv = NULL;

gchar *ns_name = NULL;

struct oio_lb_world_s *lb_world_rawx = NULL;
struct oio_lb_s *lb_rawx = NULL;

struct oio_lb_world_s *lb_world = NULL;
struct oio_lb_s *lb = NULL;

struct hc_resolver_s *resolver = NULL;
struct shard_resolver_s *shard_resolver = NULL;

oio_location_t location_num = 0;

GRWLock csurl_rwlock = {0};
gchar **csurl = NULL;
gsize csurl_count = 0;

GRWLock push_rwlock = {0};
struct lru_tree_s *push_queue = NULL;

GRWLock reg_rwlock = {0};
struct lru_tree_s *srv_registered = NULL;

GRWLock nsinfo_rwlock = {0};
struct namespace_info_s nsinfo = {{0}, 0, 0, 0};
gchar **srvtypes = NULL;

GRWLock master_rwlock = {0};
struct lru_tree_s *srv_master = NULL;

GRWLock srv_rwlock = {0};
struct lru_tree_s *srv_down = NULL;
struct lru_tree_s *srv_known = NULL;

GRWLock wanted_rwlock = {0};
gchar **wanted_srvtypes = NULL;
GBytes **wanted_prepared = NULL;

// Misc. handlers --------------------------------------------------------------

static enum http_rc_e
action_status(struct req_args_s *args)
{
	args->rp->no_access();

	if (0 == strcasecmp("HEAD", args->rq->cmd))
		return _reply_success_json(args, NULL);
	if (0 != strcasecmp("GET", args->rq->cmd))
		return _reply_method_error(args, NULL, "GET, HEAD");

	GString *gstr = g_string_sized_new (128);

	/* first, the stats about all the requests received */
	GArray *array = network_server_stat_getall();
	for (guint i=0; i<array->len ;++i) {
		struct stat_record_s *st =
				&g_array_index (array, struct stat_record_s, i);
		g_string_append_printf (gstr, "%s %"G_GUINT64_FORMAT"\n",
				g_quark_to_string (st->which), st->value);
	}
	g_array_free (array, TRUE);

	/* some stats about the internal cache */
	struct hc_resolver_stats_s s = {{0}, {0}};
	hc_resolver_info(resolver, &s);

	g_string_append_printf(gstr, "gauge cache.dir.count %"G_GINT64_FORMAT"\n",
			s.csm0.count);
	g_string_append_printf(gstr, "gauge cache.dir.max %u\n", s.csm0.max);
	g_string_append_printf(gstr, "gauge cache.dir.ttl %lu\n", s.csm0.ttl);

	g_string_append_printf(gstr, "gauge cache.srv.count %"G_GINT64_FORMAT"\n",
			s.services.count);
	g_string_append_printf(gstr, "gauge cache.srv.max %u\n", s.services.max);
	g_string_append_printf(gstr, "gauge cache.srv.ttl %lu\n", s.services.ttl);

	gint64 cd, ck;
	SRV_READ(cd = lru_tree_count(srv_down); ck = lru_tree_count(srv_known));
	g_string_append_printf(gstr, "gauge down.srv %"G_GINT64_FORMAT"\n", cd);
	g_string_append_printf(gstr, "gauge known.srv %"G_GINT64_FORMAT"\n", ck);

	args->rp->set_body_gstr(gstr);
	args->rp->set_status(HTTP_CODE_OK, "OK");
	args->rp->set_content_type("text/x-java-properties");
	args->rp->finalize();
	return HTTPRC_DONE;
}

static struct path_matching_s **
_metacd_match (const gchar *method, const gchar *path)
{
	gsize lp = strlen(path), lm = strlen(method);
	if (lp > proxy_url_path_maxlen || lm > 64)
		return g_malloc0(sizeof(struct path_matching_s*));

	gchar *key = g_alloca (lp + 2 + lm + 1);
	gchar *pk = key;

	// Copy and purify the path
	register int slash = 1;
	for (register const gchar *p = path; *p ;++p) {
		if (slash && *p == '/')
			continue;
		slash = 0;
		*(pk++) = *p;
	}

	// add a separator
	if ((slash == 0) && (*(pk-1) != '/')) {
		*(pk++) = '/';
	}
	*(pk++) = '#';

	// copy the method without slashes
	for (register const gchar *p = method; *p ;++p) {
		if (*p != '/')
			*(pk++) = *p;
	}
	*pk = '\0';

	GRID_TRACE2("matching [%s]", key);
	gchar **tokens = g_strsplit (key, "/", -1);
	for (gchar **p=tokens; *p ;++p) {
		gchar *unescaped = g_uri_unescape_string(*p,NULL);
		oio_str_reuse(p, unescaped);
	}
	struct path_matching_s **result = path_parser_match (path_parser, tokens);
	g_strfreev (tokens);
	return result;
}

static gboolean
_metacd_load_url (struct req_args_s *args, struct oio_url_s *url)
{
	const gchar *s;

	if (NULL != (s = NS()))
		oio_url_set (url, OIOURL_NS, s);

	if (NULL != (s = ACCOUNT()))
		oio_url_set (url, OIOURL_ACCOUNT, s);

	if (NULL != (s = REF()))
		oio_url_set (url, OIOURL_USER, s);

	if (NULL != (s = PATH())) {
		oio_url_set (url, OIOURL_PATH, s);
		if (NULL != (s = VERSION()))
			oio_url_set (url, OIOURL_VERSION, s);
	}

	if ((s = CID())) {
		/* Tolerate the base name (with a dot and sequence number)
		 * passed as a container ID. Also tolerate an hexadecimal prefx. */
		char cid[STRLEN_CONTAINERID] =
			"0000000000000000000000000000000000000000000000000000000000000000";
		const size_t len = strlen(s);
		if (len >= STRLEN_CONTAINERID && s[STRLEN_CONTAINERID-1] == '.') {
			g_strlcpy(cid, s, sizeof(cid));
			oio_url_set(url, OIOURL_HEXID, cid);
		} else if (0 < len && len <= 4) {
			memcpy(cid, s, len);
			oio_url_set(url, OIOURL_HEXID, cid);
		} else {
			oio_url_set(url, OIOURL_HEXID, s);
		}
		if (!oio_url_get(url, OIOURL_HEXID))
			return FALSE;
	}

	if (NULL != (s = CONTENT()))
		oio_url_set (url, OIOURL_CONTENTID, s);

	return TRUE;
}

static gboolean
_concat_headers(gchar *key, gchar *value, gpointer data)
{
	if (data != NULL && (*key == 'x' || *key == 'X')) {
		g_string_append_printf((GString*)data, " %s:%s", key, value);
	}
	return FALSE;
}

static void
_log_matching(struct http_request_s *rq,
              struct oio_requri_s *ruri UNUSED,
              struct path_matching_s **matchings UNUSED)
{
	if (!GRID_TRACE2_ENABLED())
		return;

	GString *tmp = g_string_new("");
	if (0 == strcasecmp(rq->cmd, "PUT") || 0 == strcasecmp(rq->cmd, "POST")) {
		g_tree_foreach(rq->tree_headers, (GTraverseFunc)_concat_headers, tmp);
	}

	GRID_TRACE2("URI path[%s] query[%s] fragment[%s] matches[%u] %s",
		ruri->path, ruri->query, ruri->fragment,
		g_strv_length((gchar**)matchings),
		tmp->str);
	g_string_free(tmp, TRUE);
}

static enum http_rc_e
handler_action (struct http_request_s *rq, struct http_reply_ctx_s *rp)
{
	const gint64 now = oio_ext_monotonic_time();

	/* Get a request id for the current request */
	const char *reqid = g_tree_lookup (rq->tree_headers, PROXYD_HEADER_REQID);
	if (reqid) {
		oio_ext_set_reqid(reqid);
	} else {
#if HAVE_EXTRA_DEBUG
		GRID_DEBUG("Received %s request without request id: %s",
				rq->cmd, rq->req_uri);
#endif
		oio_ext_set_prefixed_random_reqid("proxy-");
	}

	/* Load the optional 'admin' flag */
	const char *admin = g_tree_lookup (rq->tree_headers, PROXYD_HEADER_ADMIN);
	oio_ext_set_admin(oio_str_parse_bool(admin, FALSE));

	/* Load the optional 'force_master' flag */
	const char *force_master = g_tree_lookup(
			rq->tree_headers, PROXYD_HEADER_FORCE_MASTER);
	oio_ext_set_force_master(
			flag_force_master || oio_str_parse_bool(force_master, FALSE));

	/* Load the optional region: the backend will have to check if it is in
	 * the same region */
	const char* region = g_tree_lookup(rq->tree_headers, PROXYD_HEADER_REGION);
	oio_ext_set_region(region);

	/* Load the optional 'upgrade-to-tls' flag: this flag should only used for gateway  */
	const char* upgrade_to_tls = g_tree_lookup(
		rq->tree_headers, PROXYD_HEADER_UPGRADE_TO_TLS);
	oio_ext_set_upgrade_to_tls(
		oio_str_parse_bool(upgrade_to_tls, FALSE));

	/* Load the User-Agent */
	const char *user_agent = g_tree_lookup(rq->tree_headers, USER_AGENT_HEADER);
	oio_ext_set_user_agent(user_agent);

	/* Load the end-user-request flag to specify the origin of the request (external or internal)*/
	const char* end_user_request = g_tree_lookup(rq->tree_headers,
		PROXYD_HEADER_END_USER_REQUEST);
	oio_ext_set_end_user_request(oio_str_parse_bool(end_user_request, FALSE));

	/* Load the optional 'simulate_versioning' flag */
	const char *simulate_versioning = g_tree_lookup(
			rq->tree_headers, PROXYD_HEADER_SIMULATE_VERSIONING);
	oio_ext_set_simulate_versioning(
			oio_str_parse_bool(simulate_versioning, FALSE));

	/* Set sharding request to FALSE.
	 * Only a root container redirect set to TRUE. */
	oio_ext_set_is_shard_redirection(FALSE);

	/* Init shared properties to NULL.
	 * These shared properties are only used with sharded container.
	 * The root container query will populate these properties as needed. */
	oio_ext_set_shared_properties(NULL);

	/* By default, don't allow a long timeout */
	oio_ext_allow_long_timeout(FALSE);

	/* Load the optional deadline of the current request */
	const char *tostr = g_tree_lookup (rq->tree_headers, PROXYD_HEADER_TIMEOUT);
	gint64 to = 0;
	if (tostr && oio_str_is_number(tostr, &to) && to > 0) {
		oio_ext_set_deadline(now + to);
		rp->access_tail("timeout_float:%.6f", to / (float) G_TIME_SPAN_SECOND);
	} else {
		oio_ext_set_deadline(now + proxy_request_max_delay);
	}

	// Then parse the request to find a handler
	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};
	oio_requri_parse (rq->req_uri, &ruri);

	struct path_matching_s **matchings = _metacd_match (rq->cmd, ruri.path);

	_log_matching(rq, &ruri, matchings);

	GQuark gq_count = gq_count_unexpected;
	GQuark gq_time = gq_time_unexpected;

	enum http_rc_e rc;
	if (!*matchings) {
		rp->set_content_type (HTTP_CONTENT_TYPE_JSON);
		rp->set_body_gstr (g_string_new("{\"status\":404,\"message\":\"No handler found\"}"));
		rp->set_status (HTTP_CODE_NOT_FOUND, "No handler found");
		rp->finalize ();
		rc = HTTPRC_DONE;
	} else {
		struct oio_url_s *url = NULL;
		const char *err;
		struct req_args_s args = {0};
		args.req_uri = &ruri;
		args.matchings = matchings;
		args.rq = rq;
		args.rp = rp;
		args.url = url = oio_url_empty();
		args.server = server;

		if (!_metacd_load_url (&args, url)) {
			rc = _reply_format_error(&args, BADREQ("Invalid oio url"));
		} else {
			gq_count = (*matchings)->last->gq_count;
			gq_time = (*matchings)->last->gq_time;

			_request_populate_enduser(&args);

			GRID_TRACE("%s %s URL %s", __FUNCTION__,
					ruri.path, oio_url_get(args.url, OIOURL_WHOLE));

			if (!oio_url_check(url, ns_name, &err)) {
				rc = _reply_format_error(&args, BADREQ("Invalid parameter %s", err));
			} else {
				req_handler_f handler = (*matchings)->last->u;
				rc = (*handler) (&args);
			}
		}

		oio_url_pclean (&url);
		oio_pfree0(&args.top_account, NULL);
		oio_pfree0(&args.top_bucket, NULL);
		oio_pfree0(&args.top_operation, NULL);
	}

	const gint64 spent = oio_ext_monotonic_time () - rq->client->time.evt_in;

	oio_stats_add(
			gq_count, 1, gq_count_all, 1,
			gq_time, (guint64) spent, gq_time_all, (guint64) spent);

	path_matching_cleanv (matchings);
	oio_requri_clear (&ruri);
	oio_ext_set_reqid (NULL);
	oio_ext_set_region(NULL);
	return rc;
}

static struct lru_tree_s *
_push_queue_create (void)
{
	return lru_tree_create((GCompareFunc)g_strcmp0, g_free,
			(GDestroyNotify) service_info_clean, LTO_NOATIME);
}

// Administrative tasks --------------------------------------------------------

static guint
_lru_tree_expire (GRWLock *rw, struct lru_tree_s *lru, const gint64 delay)
{
	if (delay <= 0) return 0;
	const gint64 now = oio_ext_monotonic_time();
	g_rw_lock_writer_lock (rw);
	guint count = lru_tree_remove_older (lru, OLDEST(now,delay));
	g_rw_lock_writer_unlock (rw);
	return count;
}

static void
_task_expire_services_master (gpointer p UNUSED)
{
	gint64 start = oio_ext_monotonic_time();
	guint count = _lru_tree_expire (&master_rwlock, srv_master,
			ttl_expire_master_services);
	gint64 duration = oio_ext_monotonic_time() - start;
	if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("Expired %u masters in %.6fs",
				count, duration/(double)G_TIME_SPAN_SECOND);
	} else if (count) {
		GRID_DEBUG("Expired %u masters", count);
	}
}

static void
_task_expire_services_known (gpointer p UNUSED)
{
	gint64 start = oio_ext_monotonic_time();
	guint count = _lru_tree_expire (&srv_rwlock, srv_known, ttl_known_services);
	gint64 duration = oio_ext_monotonic_time() - start;
	if (count) {
		GRID_INFO("Forgot %u services, in %.6fs",
				count, duration/(double)G_TIME_SPAN_SECOND);
	} else if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("No known service expired, but analyzis took %.6fs",
				duration/(double)G_TIME_SPAN_SECOND);
	}
}

static void
_task_expire_services_down (gpointer p UNUSED)
{
	gint64 start = oio_ext_monotonic_time();
	guint count = _lru_tree_expire (&srv_rwlock, srv_down, ttl_down_services);
	gint64 duration = oio_ext_monotonic_time() - start;
	if (count) {
		GRID_INFO("Re-enabled %u services in %.6fs",
				count, duration/(double)G_TIME_SPAN_SECOND);
	} else if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("No service re-enabled, but analyzis took %.6fs",
				duration/(double)G_TIME_SPAN_SECOND);
	}
}

static void
_task_expire_local (gpointer p UNUSED)
{
	guint count = _lru_tree_expire (&reg_rwlock, srv_registered,
			ttl_expire_local_services);
	if (count)
		GRID_INFO("Expired %u local services", count);
}

static void
_task_expire_resolver (gpointer p UNUSED)
{
	gint64 start = oio_ext_monotonic_time();
	guint count_expire = hc_resolver_expire (resolver);
	guint count_purge = hc_resolver_purge (resolver);
	gint64 duration = oio_ext_monotonic_time() - start;
	if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("Resolver: expired %u, purged %u in %.6fs",
				count_expire, count_purge, duration/(double)G_TIME_SPAN_SECOND);
	} else if (count_expire || count_purge) {
		GRID_DEBUG("Resolver: expired %u, purged %u in %.6fs",
				count_expire, count_purge, duration/(double)G_TIME_SPAN_SECOND);
	}

	start = oio_ext_monotonic_time();
	count_expire = shard_resolver_expire(shard_resolver);
	count_purge = shard_resolver_purge(shard_resolver);
	duration = oio_ext_monotonic_time() - start;
	if (duration > G_TIME_SPAN_SECOND) {
		GRID_WARN("Sharding resolver: expired %u, purged %u in %.6fs",
				count_expire, count_purge, duration/(double)G_TIME_SPAN_SECOND);
	} else if (count_expire || count_purge) {
		GRID_DEBUG("Sharding resolver: expired %u, purged %u in %.6fs",
				count_expire, count_purge, duration/(double)G_TIME_SPAN_SECOND);
	}
}

static void
_task_malloc_trim(gpointer p UNUSED)
{
	VARIABLE_PERIOD_DECLARE();
	if (VARIABLE_PERIOD_SKIP(sqlx_periodic_malloctrim_period))
		return;

	malloc_trim(sqlx_periodic_malloctrim_size);
}

static void
_NOLOCK_local_score_update (const struct service_info_s *si0)
{
	gchar *k = service_info_key (si0);
	STRING_STACKIFY(k);
	struct service_info_s *si = lru_tree_get (srv_registered, k);
	if (si) {
		si->put_score.value = si0->put_score.value;
		si->get_score.value = si0->get_score.value;
	}
}

static GBytes *
_NOLOCK_precache_list_of_services (const char *type, GBytes *encoded)
{
	if (!wanted_prepared)
		wanted_prepared = g_malloc0(8 * sizeof(void*));

	GBytes **pold = NOLOCK_service_lookup_wanted (type);
	if (pold) {
		GBytes *old = *pold;
		*pold = encoded;
		return old;
	}

	size_t nb = oio_ptrv_length (wanted_prepared);
	wanted_prepared = g_realloc (wanted_prepared, sizeof(void*) * (nb+2));
	wanted_prepared[nb] = encoded;
	wanted_prepared[nb+1] = NULL;
	return NULL;
}

static GBytes *
_encode_wanted_services (const char *type, GSList *list)
{
	GString *encoded = g_string_sized_new(4096);
	g_string_append (encoded, type);
	g_string_append_c (encoded, '\0');
	g_string_append_c (encoded, '[');
	for (GSList *l=list; l ;l=l->next) {
		if (!l->data) continue;
		if (l != list) g_string_append_c (encoded, ',');
		service_info_encode_json (encoded, l->data, FALSE);
	}
	g_string_append_c (encoded, ']');
	return g_string_free_to_bytes(encoded);
}

static void
_reload_srvtype(const char *type, GSList *list)
{
	/* reloads the known services */
	time_t now = oio_ext_monotonic_seconds ();
	SRV_WRITE(for (GSList *l=list; l ;l=l->next) {
		gchar *k = service_info_key (l->data);
		lru_tree_insert (srv_known, k, (void*)now);
	});

	/* updates the score of the local services */
	if (flag_local_scores && NULL != list) {
		for (GSList *l=list; l ;l=l->next)
			REG_WRITE(_NOLOCK_local_score_update(l->data));
	}

	/* prepares a cache of services wanted by the clients */
	if (flag_cache_enabled && NULL != list) {
		GBytes *encoded = _encode_wanted_services (type, list);
		WANTED_WRITE (encoded = _NOLOCK_precache_list_of_services (type, encoded));
		g_bytes_unref (encoded);
	}

	/* reload the LB worlds, all of them #facepalm */
	if (list) {
		oio_lb_world__feed_service_info_list(lb_world, list);

		GSList *rlist = NULL;
		for (GSList *l = list; l; l=l->next) {
			struct service_info_s *si = l->data;
			if (!si || strcmp(si->type, NAME_SRVTYPE_RAWX)) continue;
			rlist = g_slist_prepend(rlist, si);
		}
		oio_lb_world__feed_service_info_list(lb_world_rawx, rlist);
		g_slist_free(rlist);
	}
}

static void
_reload_lb_service_types(
		struct oio_lb_world_s *lbw, struct oio_lb_s *lb_,
		gchar **tabtypes, GPtrArray *tabsrv, GPtrArray *taberr)
{
	struct service_update_policies_s *pols = service_update_policies_create();
	gchar *pols_cfg = oio_var_get_string(oio_ns_service_update_policy);
	service_update_reconfigure(pols, pols_cfg);
	g_free(pols_cfg);

	for (guint i=0; tabtypes[i] ;++i) {
		const char * srvtype = tabtypes[i];
		if (!oio_lb__has_pool(lb_, srvtype)) {
			GRID_DEBUG("Creating pool for service type [%s]", srvtype);
			oio_lb__force_pool(lb_,
					oio_lb_pool__from_service_policy(lbw, srvtype, pols));
		}

		if (!taberr->pdata[i])
			_reload_srvtype(srvtype, tabsrv->pdata[i]);
	}

	service_update_policies_destroy(pols);
}

static void
_free_list_of_services(gpointer p)
{
	if (!p)
		return;
	g_slist_free_full((GSList*)p, (GDestroyNotify)service_info_clean);
}

static void
_free_error(gpointer p)
{
	if (!p)
		return;
	g_error_free((GError*)p);
}

static GSList *
_filter_good_services(GSList *src, GSList **out_garbage)
{
	GSList *good = NULL, *bad = NULL;

	while (src) {
		GSList *next = src->next;
		struct service_info_s *si = src->data;

		if (metautils_addr_valid_for_connect(&si->addr)) {
			src->next = good;
			good = src;
		} else {
			src->next = bad;
			bad = src;
		}
		src = next;
	}

	*out_garbage = bad;
	return good;
}

/* If you ever plan to factorize this code with the similar part in
 * sqlx/sqlx_service.c be careful that a lot of context is expected on both
 * sides, and that even the function used to fetch the services cannot be the
 * same (sqlx talks to the proxy, the proxy talks to the conscience). */
gboolean
lb_cache_reload (void)
{
	struct namespace_info_s *nsi = NULL;
	gchar **tabtypes = NULL;
	GPtrArray *tabsrv = NULL, *taberr = NULL;
	gboolean any_loading_error = FALSE;
	down_hosts_t down = NULL;
	guint nb_down = 0;

	CSURL(cs);
	NSINFO_READ(
		tabtypes = g_strdupv_inline(srvtypes);
		nsi = namespace_info_dup(&nsinfo);
	);

	if (!tabtypes || !*tabtypes) {
		GRID_WARN("proxy not ready to reload the LB");
		any_loading_error = TRUE;
		goto out;
	}

	oio_ext_set_prefixed_random_reqid("task-reload-srv-");

	/* preload all the services */
	tabsrv = g_ptr_array_new_full(8, _free_list_of_services);
	taberr = g_ptr_array_new_full(8, _free_error);
	for (char **pt=tabtypes; *pt ;++pt) {
		GSList *srv = NULL;
		GError *e = conscience_remote_get_services(NULL, cs, *pt, FALSE, &srv,
				oio_ext_get_deadline());
		if (e) {
			GRID_WARN("Failed to load the list of [%s] in NS=%s", *pt, ns_name);
			any_loading_error = TRUE;
		}

		GSList *bad = NULL;
		srv = _filter_good_services(srv, &bad);
		g_slist_free_full(bad, (GDestroyNotify)service_info_clean);

		g_ptr_array_add(tabsrv, srv);
		g_ptr_array_add(taberr, e);
		nb_down += gridd_client_update_down_hosts(&down, srv);
	}
	gridd_client_replace_global_down_hosts(&down, nb_down);

#define reload_lb(W,L) do { \
	if (!any_loading_error) \
		oio_lb_world__increment_generation(W); \
	oio_lb_world__reload_pools(W, L, nsi); \
	_reload_lb_service_types(W, L, tabtypes, tabsrv, taberr); \
	oio_lb_world__reload_storage_policies(W, L, nsi); \
	if (!any_loading_error) \
		oio_lb_world__purge_old_generations(W); \
	else \
		oio_lb_world__rehash_all_slots(W); \
} while (0)

	/* refresh the load-balancing world */
	reload_lb(lb_world, lb);
	reload_lb(lb_world_rawx, lb_rawx);

out:
	if (tabtypes) g_free0 (tabtypes);
	if (nsi) namespace_info_free(nsi);
	if (tabsrv) g_ptr_array_free(tabsrv, TRUE);
	if (taberr) g_ptr_array_free(taberr, TRUE);
	gridd_client_clear_down_hosts(&down);
	return !any_loading_error;
}

static void
_task_reload_lb(gpointer p UNUSED)
{
	ADAPTIVE_PERIOD_DECLARE();

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	CSURL(cs);
	gint64 start = oio_ext_monotonic_time();
	if (cs && lb_cache_reload()) {
		ADAPTIVE_PERIOD_ONSUCCESS(lb_downstream_delay);
	}
	gint64 duration = oio_ext_monotonic_time() - start;
	if (duration > (lb_downstream_delay * G_TIME_SPAN_SECOND)) {
		GRID_WARN("Reloading service cache took %.6fs (reqid=%s)",
				duration/(double)G_TIME_SPAN_SECOND, oio_ext_get_reqid());
	} else {
		GRID_DEBUG("Reloading service cache took %.6fs (reqid=%s)",
				duration/(double)G_TIME_SPAN_SECOND, oio_ext_get_reqid());
	}
}

static void
_task_reload_csurl (gpointer p UNUSED)
{
	ADAPTIVE_PERIOD_DECLARE ();

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	gchar *s = oio_cfg_get_value(ns_name, OIO_CFG_CONSCIENCE);
	STRING_STACKIFY(s);
	if (s) {
		ADAPTIVE_PERIOD_ONSUCCESS(csurl_refresh_delay);
		gchar **newcs = g_strsplit(s, ",", -1);
		if (newcs) {
			const guint newcs_count = g_strv_length(newcs);
			g_rw_lock_writer_lock (&csurl_rwlock);
			gchar **tmp = csurl;
			csurl = newcs;
			newcs = tmp;
			csurl_count = newcs_count;
			g_rw_lock_writer_unlock (&csurl_rwlock);
			g_strfreev (newcs);
		}
	}
}

static void
_task_reload_nsinfo (gpointer p UNUSED)
{
	ADAPTIVE_PERIOD_DECLARE ();

	CSURL(cs);
	if (!cs)
		return; /* not ready */

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	struct namespace_info_s *ni = NULL;
	oio_ext_set_prefixed_random_reqid("task-reload-inf-");
	GError *err = conscience_remote_get_namespace(NULL, cs, &ni,
			oio_ext_get_deadline());
	if (err) {
		gchar *tmp = g_strjoinv("/", cs);
		STRING_STACKIFY(tmp);
		GRID_WARN ("NSINFO reload error [%s] from [%s]: (%d) %s",
			ns_name, tmp, err->code, err->message);
		g_clear_error (&err);
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(nsinfo_refresh_delay);
		NSINFO_WRITE(namespace_info_copy (ni, &nsinfo));
		namespace_info_free (ni);
	}
}

static void
_task_reload_srvtypes (gpointer p UNUSED)
{
	ADAPTIVE_PERIOD_DECLARE ();

	CSURL(cs);
	if (!cs)
		return;

	if (ADAPTIVE_PERIOD_SKIP ())
		return;

	gchar **types = NULL;
	oio_ext_set_prefixed_random_reqid("task-reload-typ-");
	GError *err = conscience_remote_get_types(NULL, cs, &types,
			oio_ext_get_deadline());
	EXTRA_ASSERT((err != NULL) ^ (types != NULL));

	if (err != NULL) {
		gchar *tmp = g_strjoinv("/", cs);
		STRING_STACKIFY(tmp);
		GRID_WARN("SRVTYPES reload error [%s] from [%s]: (%d) %s",
			ns_name, tmp, err->code, err->message);
		g_clear_error (&err);
		return;
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(srvtypes_refresh_delay);
		GRID_DEBUG("SRVTYPES reloaded %u for [%s]",
				g_strv_length(types), ns_name);
	}

	NSINFO_WRITE(gchar **tmp = srvtypes; srvtypes = types; types = tmp);

	if (types)
		g_strfreev (types);
}

static void
_task_push (gpointer p UNUSED)
{
	struct lru_tree_s *lru = NULL;
	GSList *tmp = NULL;
	gboolean _list (gpointer k, gpointer v, gpointer u) {
		(void) k, (void) u;
		tmp = g_slist_prepend(tmp, v);
		return FALSE;
	}

	PUSH_WRITE(lru = push_queue; push_queue = _push_queue_create());
	lru_tree_foreach(lru, _list, NULL);

	if (!tmp) {
		GRID_TRACE("Push: no service to be pushed");
	} else {
		CSURL(cs);
		if (!cs) {
			GRID_ERROR("Push error: %s", "No/Invalid conscience for namespace NS");
		} else {
			oio_ext_set_prefixed_random_reqid("task-push-srv-");
			GError *err = conscience_remote_push_services(NULL, cs, tmp,
					oio_ext_get_deadline());
			if (err != NULL) {
				GRID_WARN("Push error: (%d) %s", err->code, err->message);
				g_clear_error(&err);
			}
		}
	}

	g_slist_free(tmp);
	lru_tree_destroy(lru);
}

static void
_patch_configuration_fd(void)
{
	if (server_fd_max_passive <= 0) {
		const guint maxfd = metautils_syscall_count_maxfd();

		/* The purpose of the oio-proxy is ... to proxy connections to the
		 * backend. It seems a good idea to reserve several connections for the
		 * background tasks and the internals, then to reserve 2 FD for each
		 * cnx. */
		server_fd_max_passive = (maxfd -20) / 2;
	}

}

static void
_patch_and_apply_configuration(void)
{
	_patch_configuration_fd();
	oio_resolver_cache_enabled = BOOL(flag_cache_enabled);
	network_server_reconfigure(server);

	location_num = oio_proxy_location[0]
		? location_from_dotted_string(oio_proxy_location) : 0;
}

static void
_reconfigure_on_SIGHUP(void)
{
	GRID_NOTICE("SIGHUP! Reconfiguring...");
	oio_var_reset_all();
	oio_var_value_with_files(ns_name, config_system, config_paths);
	_patch_and_apply_configuration();
}

static void
_seamless_restart_on_SIGHUP(void)
{
	const gint64 stop_delay = 50 * G_TIME_SPAN_MILLISECOND;
	GRID_NOTICE("[Seamless restart] Forking and executing the new binary");
	gboolean success = grid_main_seamless_restart(
			(postfork_cleanup_cb) network_server_postfork_clean, server);
	if (success) {
		GRID_NOTICE("[Seamless restart] Fork succeeded, "
				"stopping once all connections are closed");
		/* Continue service requests for a few milliseconds. */
		g_usleep(stop_delay);
		/* Stop accepting new connections. */
		grid_main_stop();
		network_server_close_servers(server);
		/* Wait for pending connections. */
		gint64 deadline = oio_ext_monotonic_time() + proxy_request_max_delay;
		while (network_server_has_connections(server)
				&& oio_ext_monotonic_time() < deadline) {
			g_usleep(stop_delay);
		}
		if (network_server_has_connections(server)) {
			GRID_WARN("[Seamless restart] Some connections still open after %"
					G_GINT64_FORMAT"s",
					proxy_request_max_delay / G_TIME_SPAN_SECOND);
		}
		GRID_NOTICE("[Seamless restart] Stopping main thread");
	} else {
		GRID_WARN("[Seamless restart] Fork failed, "
				"just reload configuration the old way");
		_reconfigure_on_SIGHUP();
	}
}

// MAIN callbacks --------------------------------------------------------------

static void
_main_error (GError * err)
{
	GRID_ERROR("Action failure: (%d) %s", err->code, err->message);
	g_clear_error (&err);
	grid_main_set_status (1);
}

static void
grid_main_action (void)
{
	GError *err = NULL;

	if ((err = network_server_open_servers(server))) {
		_main_error (err);
		return;
	}

	grid_task_queue_fire (admin_gtq);
	grid_task_queue_fire (upstream_gtq);
	grid_task_queue_fire (downstream_gtq);

	if (!(admin_thread = grid_task_queue_run (admin_gtq, &err))) {
		g_prefix_error (&err, "Admin thread startup failure: ");
		_main_error (err);
		return;
	}

	if (!(upstream_thread = grid_task_queue_run (upstream_gtq, &err))) {
		g_prefix_error (&err, "Upstream thread startup failure: ");
		_main_error (err);
		return;
	}

	if (!(downstream_thread = grid_task_queue_run (downstream_gtq, &err))) {
		g_prefix_error (&err, "Downstream thread startup failure: ");
		_main_error (err);
		return;
	}

	if ((err = network_server_run (server, _seamless_restart_on_SIGHUP))) {
		_main_error (err);
		return;
	}
}

static struct grid_main_option_s *
grid_main_get_options (void)
{
	static struct grid_main_option_s options[] = {

		{"Bind", OT_LIST, {.lst = &config_urlv},
			"An additional URL to bind to (might be used several time).\n"
			"\t\tAccepts UNIX and INET sockets." },

		{"SysConfig", OT_BOOL, {.b = &config_system},
			"Load the system configuration and overload the central variables"},

		{"Config", OT_LIST, {.lst = &config_paths},
			"Load the given file and overload the central variables"},

		{NULL, 0, {.i = 0}, NULL}
	};

	return options;
}

static void
grid_main_set_defaults (void)
{
}

static void
_stop_queue (struct grid_task_queue_s **gtq, GThread **gth)
{
	if (*gth) {
		grid_task_queue_stop (*gtq);
		g_thread_join (*gth);
		*gth = NULL;
	}
	if (*gtq) {
		grid_task_queue_destroy (*gtq);
		*gtq = NULL;
	}
}

static void
grid_main_specific_fini (void)
{
	_stop_queue (&admin_gtq, &admin_thread);
	_stop_queue (&upstream_gtq, &upstream_thread);
	_stop_queue (&downstream_gtq, &downstream_thread);

	if (server) {
		network_server_close_servers (server);
		network_server_stop (server);
		network_server_clean (server);
		server = NULL;
	}
	if (path_parser) {
		path_parser_clean (path_parser);
		path_parser = NULL;
	}
	if (lb_rawx) {
		oio_lb__clear(&lb_rawx);
	}
	if (lb) {
		oio_lb__clear(&lb);
	}
	if (lb_world_rawx) {
		oio_lb_world__destroy(lb_world_rawx);
		lb_world_rawx = NULL;
	}
	if (lb_world) {
		oio_lb_world__destroy(lb_world);
		lb_world = NULL;
	}
	if (resolver) {
		hc_resolver_destroy (resolver);
		resolver = NULL;
	}
	if (shard_resolver) {
		shard_resolver_destroy(shard_resolver);
		shard_resolver = NULL;
	}
	if (srv_down) {
		lru_tree_destroy (srv_down);
		srv_down = NULL;
	}
	if (srv_known) {
		lru_tree_destroy (srv_known);
		srv_known = NULL;
	}
	if (srv_master) {
		lru_tree_destroy (srv_master);
		srv_master = NULL;
	}
	if (push_queue) {
		lru_tree_destroy (push_queue);
		push_queue = NULL;
	}
	if (wanted_srvtypes) {
		g_strfreev (wanted_srvtypes);
		wanted_srvtypes = NULL;
	}
	if (wanted_prepared) {
		for (GBytes **gb=wanted_prepared; *gb ;++gb) {
			g_bytes_unref (*gb);
			*gb = NULL;
		}
		g_free (wanted_prepared);
		wanted_prepared = NULL;
	}
	if (srv_registered) {
		lru_tree_destroy (srv_registered);
		srv_registered = NULL;
	}
	namespace_info_clear (&nsinfo);
	oio_str_clean (&ns_name);
	g_rw_lock_clear(&nsinfo_rwlock);
	g_rw_lock_clear(&reg_rwlock);
	g_rw_lock_clear(&push_rwlock);
	g_rw_lock_clear(&csurl_rwlock);
	g_rw_lock_clear(&srv_rwlock);
	g_rw_lock_clear(&wanted_rwlock);
	g_rw_lock_clear(&master_rwlock);

	if (csurl)
		g_strfreev(csurl);
	csurl = NULL;
	csurl_count = 0;

	g_slist_free_full (config_urlv, g_free);
	config_urlv = NULL;

	g_slist_free_full (config_paths, g_free);
	config_paths = NULL;

	oio_cfg_set_handle(NULL);
}

static void
configure_request_handlers (void)
{
#define SET(Url,Cb) path_parser_configure (path_parser, PROXYD_PREFIX Url, Cb)

	SET("/status/#GET", action_status);
	SET("/config/#GET", action_get_config);
	SET("/config/#POST", action_set_config);

	SET("/forward/config/#POST", action_forward_set_config);
	SET("/forward/config/#GET", action_forward_get_config);

	/* Get the version of the service. */
	SET("/forward/version/#GET", action_forward_get_version);

	/* Get information about the (sqliterepo-based) service, like the number
	 * of bases currently open, the number of managed elections. */
	SET("/forward/info/#GET", action_forward_get_info);

	/* Get request statistics for the specified service. */
	SET("/forward/stats/#GET", action_forward_stats);

	/* TODO(jfs): remove in a further release, present for the sake of backward
	 * compliance and smooth transition */
	SET("/forward/stats/#POST", action_forward_stats);

	SET("/forward/ping/#GET", action_forward_get_ping);

	/* Reload the internal load balancer of the specified sqliterepo
	 * service. */
	SET("/forward/reload/#POST", action_forward_reload);

	/* Flush the high and low caches of the specified sqliterepo service. */
	SET("/forward/flush/#POST", action_forward_flush);

	/* Ask a service to release memory to the system. */
	SET("/forward/lean-glib/#POST", action_forward_lean_glib);
	/* Ask sqlite3 to release memory. */
	SET("/forward/lean-sqlx/#POST", action_forward_lean_sqlx);
	SET("/forward/balance-masters/#POST", action_forward_balance_masters);

	/* Get a status of the high (conscience and meta0) and low (meta1)
	 * cache, including the current number of entries. */
	SET("/cache/status/#GET", action_cache_status);
	/* Get the list of all services known to the internal load balancer,
	 * with their ID and their network location. */
	SET("/cache/show/#GET", action_cache_show);
	/* Flush high and low caches and the internal load balancer.
	 * DANGEROUS, LB requests will fail during the next few seconds! */
	SET("/cache/flush/local/#POST", action_cache_flush_local);
	/* Flush "high" cache, i.e. the list of all meta0 services
	 * and the prefix/meta1 association (content of meta0 DB). */
	SET("/cache/flush/high/#POST", action_cache_flush_high);
	/* Flush "low" cache, i.e the reference/service association
	 * (content of meta1 DB). A type can be specified in the query string
	 * to flush services of that type only. */
	SET("/cache/flush/low/#POST", action_cache_flush_low);

	// New routes

	// Load Balancing
	SET("/$NS/lb/reload/#POST", action_lb_reload);
	SET("/$NS/lb/choose/#GET", action_lb_choose);
	SET("/$NS/lb/poll/#POST", action_lb_poll);
	SET("/$NS/lb/create_pool/#POST", action_lb_create_pool);

	// Local services
	SET ("/$NS/local/list/#GET", action_local_list);

	// Conscience
	SET("/$NS/conscience/info/#GET", action_conscience_info);
	SET("/$NS/conscience/list/#GET", action_conscience_list);
	SET("/$NS/conscience/register/#POST", action_conscience_register);
	SET("/$NS/conscience/deregister/#POST", action_conscience_deregister);
	SET("/$NS/conscience/flush/#POST", action_conscience_flush);
	SET("/$NS/conscience/lock/#POST", action_conscience_lock);
	SET("/$NS/conscience/unlock/#POST", action_conscience_unlock);
	SET("/$NS/conscience/resolve/#GET", action_conscience_resolve_service_id);

	// Directory
	SET("/$NS/reference/create/#POST", action_ref_create);
	SET("/$NS/reference/destroy/#POST", action_ref_destroy);
	SET("/$NS/reference/show/#GET", action_ref_show);
	SET("/$NS/reference/get_properties/#POST", action_ref_prop_get);
	SET("/$NS/reference/set_properties/#POST", action_ref_prop_set);
	SET("/$NS/reference/del_properties/#POST", action_ref_prop_del);
	SET("/$NS/reference/link/#POST", action_ref_link);
	SET("/$NS/reference/relink/#POST", action_ref_relink);
	SET("/$NS/reference/unlink/#POST", action_ref_unlink);
	SET("/$NS/reference/force/#POST", action_ref_force);
	SET("/$NS/reference/renew/#POST", action_ref_renew);

	// Meta2
	// Container
	SET("/$NS/container/snapshot/#POST", action_container_snapshot);
	SET("/$NS/container/create/#POST", action_container_create);
	SET("/$NS/container/create_many/#POST", action_container_create_many);
	SET("/$NS/container/destroy/#POST", action_container_destroy);
	SET("/$NS/container/drain/#POST", action_container_drain);
	SET("/$NS/container/show/#GET", action_container_show);
	SET("/$NS/container/list/#GET", action_container_list);
	SET("/$NS/container/get_properties/#POST", action_container_prop_get);
	SET("/$NS/container/set_properties/#POST", action_container_prop_set);
	SET("/$NS/container/del_properties/#POST", action_container_prop_del);
	SET("/$NS/container/touch/#POST", action_container_touch);
	SET("/$NS/container/dedup/#POST", action_container_dedup);
	SET("/$NS/container/purge/#POST", action_container_purge);
	SET("/$NS/container/flush/#POST", action_container_flush);
	SET("/$NS/container/raw_insert/#POST", action_container_raw_insert);
	SET("/$NS/container/raw_update/#POST", action_container_raw_update);
	SET("/$NS/container/raw_delete/#POST", action_container_raw_delete);
	SET("/$NS/container/checkpoint/#POST", action_container_checkpoint);

	// Lifecycle
	SET("/$NS/container/lifecycle/views/create/#POST", action_container_lifecycle_create_views);
	SET("/$NS/container/lifecycle/apply/#POST", action_container_lifecycle_apply);

	// Sharding
	SET("/$NS/container/sharding/find/#GET", action_container_sharding_find);
	SET("/$NS/container/sharding/prepare/#POST", action_container_sharding_prepare);
	SET("/$NS/container/sharding/create_shard/#POST", action_container_sharding_create_shard);
	SET("/$NS/container/sharding/merge/#POST", action_container_sharding_merge);
	SET("/$NS/container/sharding/update_shard/#POST", action_container_sharding_update_shard);
	SET("/$NS/container/sharding/lock/#POST", action_container_sharding_lock);
	SET("/$NS/container/sharding/replace/#POST", action_container_sharding_replace);
	SET("/$NS/container/sharding/clean/#POST", action_container_sharding_clean);
	SET("/$NS/container/sharding/show/#GET", action_container_sharding_show);
	SET("/$NS/container/sharding/abort/#POST", action_container_sharding_abort);
	SET("/$NS/container/sharding/get_range/#GET", action_container_sharding_get_in_range);

	// Content
	SET("/$NS/content/create/#POST", action_content_put);
	SET("/$NS/content/drain/#POST", action_content_drain);
	SET("/$NS/content/delete/#POST", action_content_delete);
	SET("/$NS/content/delete_many/#POST", action_content_delete_many);
	SET("/$NS/content/show/#GET", action_content_show);
	SET("/$NS/content/locate/#GET", action_content_show);
	/* Prepare chunks addresses (returns a list) */
	SET("/$NS/content/prepare/#POST", action_content_prepare);
	/* Prepare chunks addresses (returns a dictionary) */
	SET("/$NS/content/prepare2/#POST", action_content_prepare_v2);
	SET("/$NS/content/get_properties/#POST", action_content_prop_get);
	SET("/$NS/content/set_properties/#POST", action_content_prop_set);
	SET("/$NS/content/del_properties/#POST", action_content_prop_del);
	SET("/$NS/content/touch/#POST", action_content_touch);
	SET("/$NS/content/spare/#POST", action_content_spare);
	SET("/$NS/content/update/#POST", action_content_update);
	SET("/$NS/content/truncate/#POST", action_content_truncate);
	SET("/$NS/content/purge/#POST", action_content_purge);
	SET("/$NS/content/transition/#POST", action_content_policy_transition);

	// Admin
	/* Ask each peer to trigger or update the election ("DB_USE"). */
	SET("/$NS/admin/ping/#POST", action_admin_ping);

	/* Ask each peer if base exists ("DB_HAS"). */
	SET("/$NS/admin/has/#POST", action_admin_has);

	/* Get information about one of the services hosting the specified
	 * container. Requires a CID and a service type.
	 * Same as calling forward/info on the service hosting the CID. */
	SET("/$NS/admin/info/#POST", action_admin_info);

	/* Ask each peer for the status of the election.
	 * 200 -> master, 303 -> slave. */
	SET("/$NS/admin/status/#POST", action_admin_status);

	/* Ask sqlite3 to release memory. Requires a CID and a service type.
	 * Same as calling POST forward/lean-sqlx on the service
	 * hosting the CID. */
	SET("/$NS/admin/drop_cache/#POST", action_admin_drop_cache);

	/* Ask the slaves to copy the database from the master.*/
	SET("/$NS/admin/sync/#POST", action_admin_sync);

	/* Defragment the database on the master,
	 * then resynchronize it on the slaves. */
	SET("/$NS/admin/vacuum/#POST", action_admin_vacuum);

	/* Ask each peer to exit the election ("DB_LEAVE"). */
	SET("/$NS/admin/leave/#POST", action_admin_leave);

	/* Ask each peer for debugging information about an election.
	 * Current state, zookeeper node, transition history... */
	SET("/$NS/admin/debug/#POST", action_admin_debug);

	/* Copy a base from one service to another. The body must be a json
	 * object with 'to' and 'from' service ids. If 'from' is provided,
	 * DB_PIPEFROM will be called on the destination service,
	 * otherwise the source services will be located from the directory
	 * and DB_PIPETO will be used. */
	SET("/$NS/admin/copy/#POST", action_admin_copy);

	/* Remove specific base ("DB_REMOVE") */
	SET("/$NS/admin/remove/#POST", action_admin_remove);

	/* Get, set or delete properties from the admin table
	 * of any sqliterepo service. */
	SET("/$NS/admin/get_properties/#POST", action_admin_prop_get);
	SET("/$NS/admin/set_properties/#POST", action_admin_prop_set);
	SET("/$NS/admin/del_properties/#POST", action_admin_prop_del);

	/* Freeze a database (disable writes, reads are still enabled). */
	SET("/$NS/admin/freeze/#POST", action_admin_freeze);
	/* Enable a database that has previously been frozen. */
	SET("/$NS/admin/enable/#POST", action_admin_enable);
	/* Disable a database. */
	SET("/$NS/admin/disable/#POST", action_admin_disable);

	/* Fill the meta0. The first call must contain all prefixes.
	 * Subsequent calls can contain only the prefixes to update. */
	SET("/$NS/admin/meta0_force/#POST", action_admin_meta0_force);
	/* Get the whole content of the meta0. */
	SET("/$NS/admin/meta0_list/#GET", action_admin_meta0_list);
}

static gboolean
grid_main_configure (int argc, char **argv)
{
	if (argc < 2) {
		GRID_ERROR("Invalid parameter count (%d), expected: IP:PORT NS",
				argc);
		return FALSE;
	}

	const char *cfg_main_url = argv[0];
	const char *cfg_namespace = argv[1];

	g_rw_lock_init (&csurl_rwlock);
	g_rw_lock_init (&push_rwlock);
	g_rw_lock_init (&reg_rwlock);
	g_rw_lock_init (&nsinfo_rwlock);
	g_rw_lock_init (&srv_rwlock);
	g_rw_lock_init (&wanted_rwlock);
	g_rw_lock_init (&master_rwlock);

	g_strlcpy(nsinfo.name, cfg_namespace, sizeof(nsinfo.name));
	ns_name = g_strdup(cfg_namespace);

	/* Load the central configuration facility, it will tell us our
	 * NS is locally known. */
	if (!oio_var_value_with_files(ns_name, config_system, config_paths)) {
		GRID_ERROR("NS [%s] unknown in the configuration", ns_name);
		return FALSE;
	}

	/* Ensure we will cache the system config */
	struct oio_cfg_handle_s *ns_conf = oio_cfg_cache_create();
	oio_cfg_set_handle(ns_conf);

	/* To work properly, the PROXY needs to know the URL of the conscience */
	_task_reload_csurl(NULL);
	if (!csurl || !csurl_count) {
		GRID_ERROR("No conscience URL configured");
		return FALSE;
	}

	_patch_and_apply_configuration();

	/* init the networking capability of the processus. The server will use
	 * the actual value of `server_fd_max_passive` that we (maybe) patched
	 * earlier. */
	server = network_server_init ();
	path_parser = path_parser_init ();
	configure_request_handlers ();

	/* ensure each Route as a pair of count/time stats */
	void _runner (const struct trie_node_s *n) {
		oio_stats_set(n->gq_count, 0, n->gq_time, 0,
					  0, 0, 0, 0);
	}
	path_parser_foreach (path_parser, _runner);
	oio_stats_set(
			gq_count_all, 0, gq_count_unexpected, 0,
			gq_time_all, 0, gq_time_unexpected, 0);

	/* Load statsd conf and init statsd client*/
	if (oio_str_is_set(server_statsd_host)) {
		network_server_configure_statsd(
				server, "openio.oioproxy",
				server_statsd_host, server_statsd_port);
	}

	lb_world_rawx = oio_lb_local__create_world();
	lb_rawx = oio_lb__create();

	lb_world = oio_lb_local__create_world();
	lb = oio_lb__create();

	srv_down = lru_tree_create((GCompareFunc)g_strcmp0, g_free, NULL, LTO_NOATIME);
	srv_known = lru_tree_create((GCompareFunc)g_strcmp0, g_free, NULL, LTO_NOATIME);
	srv_master = lru_tree_create((GCompareFunc)g_strcmp0, g_free, g_free, LTO_NOATIME);

	oio_resolver_cache_enabled = BOOL(flag_cache_enabled);

	resolver = hc_resolver_create (proxy_locate_meta0);
	hc_resolver_qualify (resolver, service_is_ok);
	hc_resolver_notify (resolver, service_invalidate);
	shard_resolver = shard_resolver_create();

	srv_registered = _push_queue_create ();

	upstream_gtq = grid_task_queue_create ("upstream");

	// Prepare a queue responsible for upstream to the conscience
	push_queue = _push_queue_create();

	grid_task_queue_register(upstream_gtq, (guint) lb_upstream_delay,
			(GDestroyNotify) _task_push, NULL, NULL);

	grid_task_queue_register(upstream_gtq, 2,
			(GDestroyNotify) _task_expire_local, NULL, NULL);

	// Prepare a queue responsible for the downstream from the conscience
	downstream_gtq = grid_task_queue_create ("downstream");

	grid_task_queue_register (downstream_gtq, 1,
		(GDestroyNotify) _task_reload_lb, NULL, NULL);

	// Now prepare a queue for administrative tasks, such as cache expiration,
	// configuration reloadings, etc.
	admin_gtq = grid_task_queue_create ("admin");

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_known, NULL, NULL);
	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_down, NULL, NULL);
	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_master, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_resolver, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_csurl, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_srvtypes, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_nsinfo, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_malloc_trim, NULL, NULL);

	network_server_bind_host (server, cfg_main_url, handler_action,
			(network_transport_factory) transport_http_factory0);
	for (GSList *lu=config_urlv; lu ;lu=lu->next)
		network_server_bind_host (server, lu->data, handler_action,
				(network_transport_factory) transport_http_factory0);

	/* Quick abstract of the meaningful options */
	GRID_NOTICE("Faulty peers avoidance: %s", oio_client_cache_errors ? "ON" : "OFF");
	GRID_NOTICE("TCP_FASTOPEN %s", oio_socket_fastopen ? "ON" : "OFF");

	return TRUE;
}

static const char *
grid_main_get_usage (void)
{
	return "IP:PORT NS";
}

static void
grid_main_specific_stop (void)
{
	if (admin_gtq)
		grid_task_queue_stop (admin_gtq);
	if (server)
		network_server_stop (server);
}

static struct grid_main_callbacks main_callbacks =
{
	.options = grid_main_get_options,
	.action = grid_main_action,
	.set_defaults = grid_main_set_defaults,
	.specific_fini = grid_main_specific_fini,
	.configure = grid_main_configure,
	.usage = grid_main_get_usage,
	.specific_stop = grid_main_specific_stop,
};

int
main (int argc, char **argv)
{
	return grid_main (argc, argv, &main_callbacks);
}
