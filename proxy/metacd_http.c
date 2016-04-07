/*
OpenIO SDS proxy
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

guint csurl_refresh_delay = PROXYD_PERIOD_RELOAD_CSURL;
guint srvtypes_refresh_delay = PROXYD_PERIOD_RELOAD_SRVTYPES;
guint nsinfo_refresh_delay = PROXYD_PERIOD_RELOAD_NSINFO;
time_t nsinfo_refresh_m0 = PROXYD_PERIOD_RELOAD_M0INFO;
time_t cs_expire_local_services = PROXYD_TTL_DEAD_LOCAL_SERVICES;
time_t cs_down_services = PROXYD_TTL_DOWN_SERVICES;
time_t cs_known_services = PROXYD_TTL_KNOWN_SERVICES;

// Configuration

static GSList *config_urlv = NULL;

static guint lb_downstream_delay = PROXYD_DEFAULT_PERIOD_DOWNSTREAM;
static guint lb_upstream_delay = PROXYD_DEFAULT_PERIOD_UPSTREAM;
static guint dir_low_ttl = PROXYD_DEFAULT_TTL_SERVICES;
static guint dir_low_max = PROXYD_DEFAULT_MAX_SERVICES;
static guint dir_high_ttl = PROXYD_DEFAULT_TTL_CSM0;
static guint dir_high_max = PROXYD_DEFAULT_MAX_CSM0;
gboolean flag_cache_enabled = TRUE;
gboolean flag_local_scores = FALSE;

struct grid_lbpool_s *lbpool = NULL;
struct hc_resolver_s *resolver = NULL;
gchar *nsname = NULL;

GRWLock csurl_rwlock = {0};
gchar **csurl = NULL;
gsize csurl_count = 0;

GMutex push_mutex = {0};
struct lru_tree_s *push_queue = NULL;
struct lru_tree_s *srv_registered = NULL;

GRWLock nsinfo_rwlock = {0};
struct namespace_info_s nsinfo = {{0}};
gchar **srvtypes = NULL;
gint64 ns_chunk_size = 10*1024*1024;

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
	if (0 == strcasecmp("HEAD", args->rq->cmd))
		return _reply_success_json(args, NULL);
	if (0 != strcasecmp("GET", args->rq->cmd))
		return _reply_method_error(args);

	GString *gstr = g_string_sized_new (128);

	/* first, the stats about all the requests received */
	GArray *array = network_server_stat_getall(args->rq->client->server);
	for (guint i=0; i<array->len ;++i) {
		struct server_stat_s *st = &g_array_index (array, struct server_stat_s, i);
		g_string_append_printf (gstr, "%s = %"G_GUINT64_FORMAT"\n",
				g_quark_to_string (st->which), st->value);
	}
	g_array_free (array, TRUE);

	/* some stats about the internal cache */
	struct hc_resolver_stats_s s = {0};
	hc_resolver_info(resolver, &s);

	g_string_append_printf(gstr, "gauge cache.dir.count = %"G_GINT64_FORMAT"\n", s.csm0.count);
	g_string_append_printf(gstr, "gauge cache.dir.max = %u\n", s.csm0.max);
	g_string_append_printf(gstr, "gauge cache.dir.ttl = %lu\n", s.csm0.ttl);
	g_string_append_printf(gstr, "gauge cache.dir.clock = %lu\n", s.clock);

	g_string_append_printf(gstr, "gauge cache.srv.count = %"G_GINT64_FORMAT"\n", s.services.count);
	g_string_append_printf(gstr, "gauge cache.srv.max = %u\n", s.services.max);
	g_string_append_printf(gstr, "gauge cache.srv.ttl = %lu\n", s.services.ttl);
	g_string_append_printf(gstr, "gauge cache.srv.clock = %lu\n", s.clock);

	gint64 cd, ck;
	SRV_READ(cd = lru_tree_count(srv_down); ck = lru_tree_count(srv_known));
	g_string_append_printf(gstr, "gauge down.srv = %"G_GINT64_FORMAT"\n", cd);
	g_string_append_printf(gstr, "gauge known.srv = %"G_GINT64_FORMAT"\n", ck);

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
	if (lp > PROXYD_PATH_MAXLEN || lm > 64)
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
	if (*(pk-1) != '/')
		*(pk++) = '/';
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

static struct oio_url_s *
_metacd_load_url (struct req_args_s *args)
{
	const gchar *s;
	struct oio_url_s *url = oio_url_empty();

	if (NULL != (s = NS()))
		oio_url_set (url, OIOURL_NS, s);

	if (NULL != (s = ACCOUNT()))
		oio_url_set (url, OIOURL_ACCOUNT, s);

	if (NULL != (s = REF()))
		oio_url_set (url, OIOURL_USER, s);

	if (NULL != (s = TYPE()))
		oio_url_set (url, OIOURL_TYPE, s);

	if (NULL != (s = PATH())) {
		oio_url_set (url, OIOURL_PATH, s);
		if (NULL != (s = VERSION()))
			oio_url_set (url, OIOURL_VERSION, s);
	}

	if (NULL != (s = CID()))
		oio_url_set (url, OIOURL_HEXID, s);

	if (NULL != (s = CONTENT()))
		oio_url_set (url, OIOURL_CONTENTID, s);

	return url;
}

static enum http_rc_e
handler_action (struct http_request_s *rq, struct http_reply_ctx_s *rp)
{
	gboolean _boolhdr (const gchar * n) {
		return metautils_cfg_get_bool (
			(gchar *) g_tree_lookup (rq->tree_headers, n), FALSE);
	}

	// Get a request id for the current request
	const gchar *reqid = g_tree_lookup (rq->tree_headers, PROXYD_HEADER_REQID);
	if (reqid)
		oio_ext_set_reqid(reqid);
	else
		oio_ext_set_random_reqid();

	// Then parse the request to find a handler
	struct oio_url_s *url = NULL;
	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};
	oio_requri_parse (rq->req_uri, &ruri);

	struct path_matching_s **matchings = _metacd_match (rq->cmd, ruri.path);

	GRID_TRACE2("URI path[%s] query[%s] fragment[%s] matches[%u]",
			ruri.path, ruri.query, ruri.fragment,
			g_strv_length((gchar**)matchings));

	GQuark gq_count = gq_count_unexpected;
	GQuark gq_time = gq_time_unexpected;

	enum http_rc_e rc;
	if (!*matchings) {
		rp->set_content_type ("application/json");
		rp->set_body_gstr (g_string_new("{\"status\":404,\"message\":\"No handler found\"}"));
		rp->set_status (HTTP_CODE_NOT_FOUND, "No handler found");
		rp->finalize ();
		rc = HTTPRC_DONE;
	} else {
		struct req_args_s args = {NULL,NULL,NULL, NULL,NULL, 0};
		args.req_uri = &ruri;
		args.matchings = matchings;
		args.rq = rq;
		args.rp = rp;

		if (_boolhdr (PROXYD_HEADER_NOEMPTY))
			args.flags |= FLAG_NOEMPTY;

		args.url = url = _metacd_load_url (&args);
		rp->subject(oio_url_get(url, OIOURL_HEXID));
		gq_count = (*matchings)->last->gq_count;
		gq_time = (*matchings)->last->gq_time;
		GRID_TRACE("%s %s URL %s", __FUNCTION__, ruri.path, oio_url_get(args.url, OIOURL_WHOLE));
		req_handler_f handler = (*matchings)->last->u;
		rc = (*handler) (&args);
	}

	gint64 spent = oio_ext_monotonic_time () - rq->client->time.evt_in;

	network_server_stat_push4 (rq->client->server, TRUE,
			gq_count, 1, gq_count_all, 1,
			gq_time, spent, gq_time_all, spent);

	path_matching_cleanv (matchings);
	oio_requri_clear (&ruri);
	oio_url_pclean (&url);
	oio_ext_set_reqid (NULL);
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
_expire_services (struct lru_tree_s *lru, time_t delay)
{
	gchar *k = NULL;
	gpointer v = NULL;
	guint count = 0;

	g_assert (delay >= 0);
	gulong oldest = oio_ext_monotonic_seconds();
	oldest = (oldest > (gulong)delay) ? oldest - (gulong)delay : 0;

	SRV_WRITE(while (lru_tree_get_last(lru, (void**)&k, &v)) {
		EXTRA_ASSERT(k != NULL);
		EXTRA_ASSERT(v != NULL);
		gulong when = (gulong)v;
		if (when >= oldest)
			break;
		lru_tree_steal_last(lru, (void**)&k, &v);
		g_free(k);
		++ count;
	});

	return count;
}

static void
_task_expire_services_known (gpointer p)
{
	(void) p;
	guint count = _expire_services (srv_known, cs_known_services);
	if (count)
		GRID_INFO("Forgot %u services", count);
}

static void
_task_expire_services_down (gpointer p)
{
	(void) p;
	guint count = _expire_services (srv_down, cs_down_services);
	if (count)
		GRID_INFO("re-enabled %u services", count);
}

static void
_task_expire_resolver (gpointer p)
{
	(void) p;
	hc_resolver_set_now (resolver, oio_ext_monotonic_seconds());
	guint count = hc_resolver_expire (resolver);
	if (count)
		GRID_DEBUG ("Expired %u resolver entries", count);
	count = hc_resolver_purge (resolver);
	if (count)
		GRID_DEBUG ("Purged %u resolver ", count);
}

static void
_local_score_update (const struct service_info_s *si0)
{
	gchar *k = service_info_key (si0);
	STRING_STACKIFY(k);
	/* XXX(jfs): requires LTO_NOATIME to be set on <srv_registered> to avoid
	   disturbing the sequence */
	struct service_info_s *si = lru_tree_get (srv_registered, k);
	if (si) si->score.value = si0->score.value;
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
	GString *encoded = g_string_new(type);
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
_reload_srvtype(const char *type)
{
	CSURL(cs);

	GSList *list = NULL;
	GError *err = conscience_remote_get_services (cs, type, FALSE, &list);
	if (err) {
		GRID_WARN("Services listing error for type[%s]: code=%d %s",
				type, err->code, err->message);
		g_clear_error(&err);
		return;
	}

	if (GRID_TRACE_ENABLED()) {
		GRID_TRACE ("SRV loaded %u [%s]", g_slist_length(list), type);
	}

	/* reloads the known services */
	gulong now = oio_ext_monotonic_seconds ();
	SRV_WRITE(for (GSList *l=list; l ;l=l->next) {
		gchar *k = service_info_key (l->data);
		lru_tree_insert (srv_known, k, (void*)now);
	});

	/* updates the score of the local services */
	if (flag_local_scores && NULL != list) {
		for (GSList *l=list; l ;l=l->next)
			PUSH_DO(_local_score_update(l->data));
	}

	/* prepares a cache of services wanted by the clients */
	if (flag_cache_enabled && NULL != list) {
		GBytes *encoded = _encode_wanted_services (type, list);
		WANTED_WRITE (encoded = _NOLOCK_precache_list_of_services (type, encoded));
		g_bytes_unref (encoded);
	}

	/* reload the LB */
	if (NULL != list) {
		GSList *l = list;
		gboolean provide(struct service_info_s **p_si) {
			if (!l) return FALSE;
			*p_si = l->data;
			l->data = NULL;
			l = l->next;
			return TRUE;
		}
		grid_lbpool_reload(lbpool, type, provide);
		g_slist_free(list);
	}
}

static void
_task_reload_lbpool (gpointer p)
{
	ADAPTIVE_PERIOD_DECLARE();
	(void) p;

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	CSURL(cs);
	if (!cs) return;

	ADAPTIVE_PERIOD_ONSUCCESS(lb_downstream_delay);
	gchar **tt = NULL;
	NSINFO_READ(tt = g_strdupv_inline(srvtypes));

	if (tt) {
		for (gchar **t=tt; *t ;++t)
			_reload_srvtype (*t);
		g_free (tt);
	}

	grid_lbpool_reconfigure(lbpool, &nsinfo);
}

static void
_task_reload_csurl (gpointer p)
{
	ADAPTIVE_PERIOD_DECLARE ();
	(void) p;

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	gchar *s = oio_cfg_get_value(nsname, OIO_CFG_CONSCIENCE);
	STRING_STACKIFY(s);
	if (s) {
		ADAPTIVE_PERIOD_ONSUCCESS(csurl_refresh_delay);
		gchar **newcs = g_strsplit(s, ",", -1);
		if (newcs) {
			g_rw_lock_writer_lock (&csurl_rwlock);
			do {
				gchar **tmp = csurl;
				csurl = newcs;
				newcs = tmp;
				csurl_count = g_strv_length (csurl);
			} while (0);
			g_rw_lock_writer_unlock (&csurl_rwlock);
			g_strfreev (newcs);
		}
	}
}

static void
_task_reload_nsinfo (gpointer p)
{
	ADAPTIVE_PERIOD_DECLARE ();
	(void) p;

	CSURL(cs);
	if (!cs)
		return;

	if (ADAPTIVE_PERIOD_SKIP())
		return;

	struct namespace_info_s *ni = NULL;
	GError *err = conscience_remote_get_namespace (cs, &ni);
	if (err) {
		GRID_WARN ("NSINFO reload error [%s] from [%s]: (%d) %s",
			nsname, cs, err->code, err->message);
		g_clear_error (&err);
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(nsinfo_refresh_delay);
		NSINFO_WRITE(namespace_info_copy (ni, &nsinfo);
					 ns_chunk_size = nsinfo.chunk_size);
		namespace_info_free (ni);
	}
}

static void
_task_reload_srvtypes (gpointer p)
{
	ADAPTIVE_PERIOD_DECLARE ();
	(void) p;

	CSURL(cs);
	if (!cs)
		return;

	if (ADAPTIVE_PERIOD_SKIP ())
		return;

	GSList *list = NULL;
	GError *err = conscience_remote_get_types (cs, &list);
	if (err != NULL) {
		GRID_WARN ("SRVTYPES reload error [%s] from [%s] : (%d) %s",
			nsname, cs, err->code, err->message);
		g_clear_error (&err);
		return;
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(srvtypes_refresh_delay);
		GRID_DEBUG("SRVTYPES reloaded %u for [%s]",
				g_slist_length(list), nsname);
	}

	gchar **newset = (gchar **) metautils_list_to_array (list);
	g_slist_free (list);
	list = NULL;

	NSINFO_WRITE(gchar **tmp = srvtypes;
	srvtypes = newset;
	newset = tmp);

	if (newset)
		g_strfreev (newset);
}

static guint
_expire_local (time_t pivot, GString *dbg)
{
	guint count = 0;
	gchar *k = NULL;
	struct service_info_s *si = NULL;

	while (lru_tree_get_last (srv_registered, (void**)&k, (void**)&si)) {
		if (si->score.timestamp > pivot)
			break;
		lru_tree_steal_last (srv_registered, (void**)&k, (void**)&si);
		if (dbg->len < 128) {
			if (dbg->len > 0) g_string_append_c (dbg, ',');
			g_string_append (dbg, k);
		}
		g_free (k);
		service_info_clean (si);
		++ count;
	}
	return count;
}

static void
_task_expire_local (gpointer p)
{
	(void) p;
	time_t pivot = oio_ext_monotonic_seconds () - cs_expire_local_services;
	GString *dbg = g_string_new ("");
	guint count;
	PUSH_DO(count = _expire_local (pivot, dbg));
	if (count)
		GRID_INFO("%u local services expired: %s", count, dbg->str);
	g_string_free (dbg, TRUE);
}

static void
_task_push (gpointer p)
{
	(void) p;
	struct lru_tree_s *lru = NULL;
	GSList *tmp = NULL;
	gboolean _list (gpointer k, gpointer v, gpointer u) {
		(void) k, (void) u;
		tmp = g_slist_prepend(tmp, v);
		return FALSE;
	}

	PUSH_DO(lru = push_queue; push_queue = _push_queue_create());
	lru_tree_foreach_DEQ(lru, _list, NULL);

	if (!tmp) {
		GRID_TRACE("Push: no service to be pushed");
	} else {
		CSURL(cs);
		if (!cs) {
			GRID_ERROR("Push error: %s", "No/Invalid conscience for namespace NS");
		} else {
			GError *err = conscience_remote_push_services (cs, tmp);
			if (err != NULL) {
				GRID_WARN("Push error: (%d) %s", err->code, err->message);
				g_clear_error(&err);
			}
		}
	}

	g_slist_free(tmp);
	lru_tree_destroy(lru);
}

// MAIN callbacks --------------------------------------------------------------

static void
_main_error (GError * err)
{
	GRID_ERROR ("Action failure : (%d) %s", err->code, err->message);
	g_clear_error (&err);
	grid_main_set_status (1);
}

static void
grid_main_action (void)
{
	GError *err = NULL;

	if (NULL != (err = network_server_open_servers (server))) {
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

	if (NULL != (err = network_server_run (server))) {
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

		{"LbRefresh", OT_INT, {.u = &lb_downstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"},

		{"RefreshNamespace", OT_TIME, {.u = &nsinfo_refresh_delay},
			"Interval between NS configuration's refreshes (seconds)"},
		{"RefreshConscience", OT_TIME, {.u = &csurl_refresh_delay},
			"Interval between CS urls refreshes (seconds)"},
		{"RefreshTypes", OT_TIME, {.u = &srvtypes_refresh_delay},
			"Interval between service types refreshes (seconds)"},

		{"SrvPush", OT_INT, {.u = &lb_upstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"
			"\t\tMust be >= 1"},

		{"Cache", OT_BOOL, {.b = &flag_cache_enabled},
			"Disable caching for the conscience: services are pushed\n"
			"synchronously and no cache is kept on a GET."},

		{"LocalScores", OT_BOOL, {.b = &flag_local_scores},
			"Enables the updates of the list of local services, so that\n"
			"their score is displayed. This gives a pretty output but\n"
			"requires CPU spent in critical sections."},

		{"DirLowTtl", OT_UINT, {.u = &dir_low_ttl},
			"Directory 'low' (meta1) TTL for cache elements"},
		{"DirLowMax", OT_UINT, {.u = &dir_low_max},
			"Directory 'low' (meta1) MAX cached elements"},
		{"DirHighTtl", OT_UINT, {.u = &dir_high_ttl},
			"Directory 'high' (cs+meta0) TTL for cache elements"},
		{"DirHighMax", OT_UINT, {.u = &dir_high_max},
			"Directory 'high' (cs+meta0) MAX cached elements"},
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
	if (lbpool) {
		grid_lbpool_destroy (lbpool);
		lbpool = NULL;
	}
	if (resolver) {
		hc_resolver_destroy (resolver);
		resolver = NULL;
	}
	if (srv_down) {
		lru_tree_destroy (srv_down);
		srv_down = NULL;
	}
	if (srv_known) {
		lru_tree_destroy (srv_known);
		srv_known = NULL;
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
	oio_str_clean (&nsname);
	g_rw_lock_clear(&nsinfo_rwlock);
	g_mutex_clear(&push_mutex);
	g_rw_lock_clear(&csurl_rwlock);
	g_rw_lock_clear(&srv_rwlock);
	g_rw_lock_clear(&wanted_rwlock);

	if (csurl) g_strfreev (csurl);
	csurl = NULL;
	csurl_count = 0;

	g_slist_free_full (config_urlv, g_free);
	config_urlv = NULL;
}

static void
configure_request_handlers (void)
{
#define SET(Url,Cb) path_parser_configure (path_parser, PROXYD_PREFIX Url, Cb)

	SET("/status/#GET", action_status);

	SET("/forward/stats/#POST", action_forward_stats);
	SET("/forward/$ACTION/#POST", action_forward);

	SET("/cache/status/#GET", action_cache_status);
	SET("/cache/flush/local/#POST", action_cache_flush_local);
	SET("/cache/flush/high/#POST", action_cache_flush_high);
	SET("/cache/flush/low/#POST", action_cache_flush_low);
	SET("/cache/ttl/low/$COUNT/#POST", action_cache_set_ttl_low);
	SET("/cache/ttl/high/$COUNT/#POST", action_cache_set_ttl_high);
	SET("/cache/max/low/$COUNT/#POST", action_cache_set_max_low);
	SET("/cache/max/high/$COUNT/#POST", action_cache_set_max_high);

    // New routes

	// Load Balancing
	SET("/$NS/lb/choose/#GET", action_lb_choose);

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

    // Directory
    SET("/$NS/reference/create/#POST", action_ref_create);
    SET("/$NS/reference/destroy/#POST", action_ref_destroy);
    SET("/$NS/reference/show/#GET", action_ref_show);
    SET("/$NS/reference/get_properties/#POST", action_ref_prop_get);
    SET("/$NS/reference/set_properties/#POST", action_ref_prop_set);
    SET("/$NS/reference/del_properties/#POST", action_ref_prop_del);
    SET("/$NS/reference/link/#POST", action_ref_link);
    SET("/$NS/reference/unlink/#POST", action_ref_unlink);
    SET("/$NS/reference/force/#POST", action_ref_force);
    SET("/$NS/reference/renew/#POST", action_ref_renew);

    // Meta2
    // Container
    SET("/$NS/container/create/#POST", action_container_create);
    SET("/$NS/container/destroy/#POST", action_container_destroy);
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

    // Content
    SET("/$NS/content/create/#POST", action_content_put);
    SET("/$NS/content/link/#POST", action_content_link);
    SET("/$NS/content/delete/#POST", action_content_delete);
    SET("/$NS/content/show/#GET", action_content_show);
    SET("/$NS/content/prepare/#POST", action_content_prepare);
    SET("/$NS/content/get_properties/#POST", action_content_prop_get);
    SET("/$NS/content/set_properties/#POST", action_content_prop_set);
    SET("/$NS/content/del_properties/#POST", action_content_prop_del);
    SET("/$NS/content/touch/#POST", action_content_touch);
    SET("/$NS/content/spare/#POST", action_content_spare);
    SET("/$NS/content/copy/#POST", action_content_copy);

    // Admin
	SET("/$NS/admin/ping/#POST", action_admin_ping);
	SET("/$NS/admin/info/#POST", action_admin_info);
	SET("/$NS/admin/status/#POST", action_admin_status);
	SET("/$NS/admin/drop_cache/#POST", action_admin_drop_cache);
	SET("/$NS/admin/sync/#POST", action_admin_sync);
	SET("/$NS/admin/leave/#POST", action_admin_leave);
	SET("/$NS/admin/debug/#POST", action_admin_debug);
	SET("/$NS/admin/copy/#POST", action_admin_copy);
	SET("/$NS/admin/get_properties/#POST", action_admin_prop_get);
	SET("/$NS/admin/set_properties/#POST", action_admin_prop_set);
	SET("/$NS/admin/del_properties/#POST", action_admin_prop_del);
	SET("/$NS/admin/freeze/#POST", action_admin_freeze);
	SET("/$NS/admin/enable/#POST", action_admin_enable);
	SET("/$NS/admin/disable/#POST", action_admin_disable);
}

static gboolean
grid_main_configure (int argc, char **argv)
{
	if (argc != 2) {
		GRID_ERROR ("Invalid parameter, expected : IP:PORT NS");
		return FALSE;
	}

	const char *cfg_main_url = argv[0];
	const char *cfg_namespace = argv[1];

	g_rw_lock_init (&csurl_rwlock);
	g_mutex_init (&push_mutex);
	g_rw_lock_init (&nsinfo_rwlock);
	g_rw_lock_init (&srv_rwlock);
	g_rw_lock_init (&wanted_rwlock);

	nsname = g_strdup (cfg_namespace);
	g_strlcpy (nsinfo.name, cfg_namespace, sizeof (nsinfo.name));
	nsinfo.chunk_size = 1;

	_task_reload_csurl (NULL);
	if (!csurl || !csurl_count) {
		GRID_ERROR("No conscience URL configured");
		return FALSE;
	}

	path_parser = path_parser_init ();
	configure_request_handlers ();

	server = network_server_init ();

	/* ensure each Route as a pair of count/time stats */
	void _runner (const struct trie_node_s *n) {
		network_server_stat_push2 (server, FALSE,
				n->gq_count, 0, n->gq_time, 0);
	}
	path_parser_foreach (path_parser, _runner);
	network_server_stat_push4 (server, FALSE,
			gq_count_all, 0, gq_count_unexpected, 0,
			gq_time_all, 0, gq_time_unexpected, 0);

	lbpool = grid_lbpool_create (nsname);
	srv_down = lru_tree_create((GCompareFunc)g_strcmp0, g_free, NULL, LTO_NOATIME);
	srv_known = lru_tree_create((GCompareFunc)g_strcmp0, g_free, NULL, LTO_NOATIME);

	resolver = hc_resolver_create1 (oio_ext_monotonic_seconds());
	enum hc_resolver_flags_e f = 0;
	if (!flag_cache_enabled)
		f |= HC_RESOLVER_NOCACHE;
	hc_resolver_configure (resolver, f);
	hc_resolver_qualify (resolver, service_is_ok);
	hc_resolver_notify (resolver, service_invalidate);
	hc_resolver_set_ttl_csm0 (resolver, dir_high_ttl);
	hc_resolver_set_max_csm0 (resolver, dir_high_max);
	hc_resolver_set_ttl_services (resolver, dir_low_ttl);
	hc_resolver_set_max_services (resolver, dir_low_max);
	GRID_INFO ("RESOLVER limits HIGH[%u/%u] LOW[%u/%u]",
		dir_high_max, dir_high_ttl, dir_low_max, dir_low_ttl);

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

	grid_task_queue_register (downstream_gtq, (guint) 1,
		(GDestroyNotify) _task_reload_lbpool, NULL, NULL);

	// Now prepare a queue for administrative tasks, such as cache expiration,
	// configuration reloadings, etc.
	admin_gtq = grid_task_queue_create ("admin");

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_known, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_down, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_resolver, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_csurl, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_srvtypes, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_reload_nsinfo, NULL, NULL);

	network_server_bind_host (server, cfg_main_url, handler_action,
			(network_transport_factory) transport_http_factory0);
	for (GSList *lu=config_urlv; lu ;lu=lu->next)
		network_server_bind_host (server, lu->data, handler_action,
				(network_transport_factory) transport_http_factory0);

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
