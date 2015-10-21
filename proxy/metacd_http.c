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
static struct http_request_dispatcher_s *dispatcher = NULL;
static struct network_server_s *server = NULL;

static struct grid_task_queue_s *admin_gtq = NULL;
static struct grid_task_queue_s *upstream_gtq = NULL;
static struct grid_task_queue_s *downstream_gtq = NULL;

static GThread *admin_thread = NULL;
static GThread *upstream_thread = NULL;
static GThread *downstream_thread = NULL;

// Configuration

static GSList *config_urlv = NULL;

static gint lb_downstream_delay = PROXYD_DEFAULT_PERIOD_DOWNSTREAM;
static guint lb_upstream_delay = PROXYD_DEFAULT_PERIOD_UPSTREAM;
static guint nsinfo_refresh_delay = 5;
static guint dir_low_ttl = PROXYD_DEFAULT_TTL_SERVICES;
static guint dir_low_max = PROXYD_DEFAULT_MAX_SERVICES;
static guint dir_high_ttl = PROXYD_DEFAULT_TTL_CSM0;
static guint dir_high_max = PROXYD_DEFAULT_MAX_CSM0;
gdouble m2_timeout_all = PROXYD_M2_TIMEOUT_SINGLE;
gboolean flag_cache_enabled = TRUE;

struct grid_lbpool_s *lbpool = NULL;
struct hc_resolver_s *resolver = NULL;
gchar *nsname = NULL;

GMutex csurl_mutex;
gchar *csurl = NULL;

GMutex push_mutex;
struct lru_tree_s *push_queue = NULL;

GMutex nsinfo_mutex;
struct namespace_info_s nsinfo;
gchar **srvtypes = NULL;

GMutex srv_mutex;
struct lru_tree_s *srv_down = NULL;

// Misc. handlers --------------------------------------------------------------

static enum http_rc_e
action_status(struct req_args_s *args)
{
	if (0 == strcasecmp("HEAD", args->rq->cmd))
		return _reply_success_json(args, NULL);
	if (0 != strcasecmp("GET", args->rq->cmd))
		return _reply_method_error(args);

	GString *gstr = g_string_sized_new (128);
	gboolean runner (const gchar *n, guint64 v) {
		g_string_append_printf(gstr, "%s = %"G_GINT64_FORMAT"\n", n, v);
		return TRUE;
	}
	grid_stats_holder_foreach(args->rq->client->main_stats, runner);

	struct hc_resolver_stats_s s;
	memset(&s, 0, sizeof(s));
	hc_resolver_info(resolver, &s);

	g_string_append_printf(gstr, "cache.dir.count = %"G_GINT64_FORMAT"\n", s.csm0.count);
	g_string_append_printf(gstr, "cache.dir.max = %u\n", s.csm0.max);
	g_string_append_printf(gstr, "cache.dir.ttl = %lu\n", s.csm0.ttl);
	g_string_append_printf(gstr, "cache.dir.clock = %lu\n", s.clock);

	g_string_append_printf(gstr, "cache.srv.count = %"G_GINT64_FORMAT"\n", s.services.count);
	g_string_append_printf(gstr, "cache.srv.max = %u\n", s.services.max);
	g_string_append_printf(gstr, "cache.srv.ttl = %lu\n", s.services.ttl);
	g_string_append_printf(gstr, "cache.srv.clock = %lu\n", s.clock);

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
		//slash = ('/' == (*(pk++) = *p));
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

static struct hc_url_s *
_metacd_load_url (struct req_args_s *args)
{
	const gchar *s;
	struct hc_url_s *url = hc_url_empty();

	if (NULL != (s = NS()))
		hc_url_set_oldns (url, s);

	if (NULL != (s = ACCOUNT()))
		hc_url_set (url, HCURL_ACCOUNT, s);

	if (NULL != (s = REF())) {
		hc_url_set (url, HCURL_USER, s);
		hc_url_set (url, HCURL_TYPE, HCURL_DEFAULT_TYPE);
	}
	if (NULL != (s = PATH())) {
		hc_url_set (url, HCURL_PATH, s);
		if (NULL != (s = VERSION()))
			hc_url_set (url, HCURL_VERSION, s);
	}

	if (NULL != (s = CID()))
		hc_url_set (url, HCURL_HEXID, s);

	return url;
}

static enum http_rc_e
handler_action (gpointer u, struct http_request_s *rq,
	struct http_reply_ctx_s *rp)
{
	(void) u;

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
	struct hc_url_s *url = NULL;
	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};
	oio_requri_parse (rq->req_uri, &ruri);

	struct path_matching_s **matchings = _metacd_match (rq->cmd, ruri.path);

	GRID_TRACE2("URI path[%s] query[%s] fragment[%s] matches[%u]",
			ruri.path, ruri.query, ruri.fragment,
			g_strv_length((gchar**)matchings));

	enum http_rc_e rc;
	if (!*matchings) {
		rp->set_body (NULL, 0);
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
		req_handler_f handler = path_matching_get_udata (*matchings);
		rc = (*handler) (&args);
	}

	path_matching_cleanv (matchings);
	oio_requri_clear (&ruri);
	hc_url_pclean (&url);
	return rc;
}

static struct lru_tree_s *
_push_queue_create (void)
{
	return lru_tree_create((GCompareFunc)g_strcmp0, g_free,
			(GDestroyNotify) service_info_clean, LTO_NOATIME);
}

// Administrative tasks --------------------------------------------------------

static void
_task_expire_services_down (gpointer p)
{
	(void) p;
	gchar *k = NULL;
	gpointer v = NULL;
	guint count = 0;

	gulong oldest = time(0) - 8;

	SRV_DO(while (lru_tree_get_last(srv_down, (void**)&k, &v)) {
		EXTRA_ASSERT(k != NULL);
		EXTRA_ASSERT(v != NULL);
		gulong when = (gulong)v;
		if (when >= oldest)
			break;
		lru_tree_steal_last(srv_down, (void**)&k, &v);
		g_free(k);
		++ count;
	});

	if (count)
		GRID_INFO("re-enabled %u services", count);
}

static void
_task_expire_resolver (gpointer p)
{
	(void) p;
	hc_resolver_set_now (resolver, time (0));
	guint count = hc_resolver_expire (resolver);
	if (count)
		GRID_DEBUG ("Expired %u resolver entries", count);
	count = hc_resolver_purge (resolver);
	if (count)
		GRID_DEBUG ("Purged %u resolver ", count);
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

	if (list) {
		GSList *l = list;

		gboolean provide(struct service_info_s **p_si) {
			if (!l)
				return 0;
			*p_si = l->data;
			l->data = NULL;
			l = l->next;
			return 1;
		}
		grid_lbpool_reload(lbpool, type, provide);
		g_slist_free(list);
	}
}

static void
_task_reload_lbpool (gpointer p)
{
	(void) p;
	CSURL(cs);
	if (!cs) return;

	gchar **tt = NULL;
	NSINFO_DO(tt = g_strdupv(srvtypes));

	if (tt) {
		for (gchar **t=tt; *t ;++t)
			_reload_srvtype (*t);
		g_strfreev (tt);
	}

	grid_lbpool_reconfigure(lbpool, &nsinfo);
}

static void
_task_reload_csurl (gpointer p)
{
	(void) p;
	gchar *cs = gridcluster_get_conscience(nsname);
	CSURL_DO(oio_str_reuse (&csurl, cs));
}

static void
_task_reload_nsinfo (gpointer p)
{
	(void) p;
	CSURL(cs);
	if (!cs) return;

	struct namespace_info_s *ni = NULL;
	GError *err = conscience_remote_get_namespace (cs, &ni);
	if (err) {
		GRID_WARN ("NSINFO reload error [%s] from [%s]: (%d) %s",
			nsname, cs, err->code, err->message);
		g_clear_error (&err);
	} else {
		NSINFO_DO(namespace_info_copy (ni, &nsinfo, NULL));
		namespace_info_free (ni);
	}
}

static void
_task_reload_srvtypes (gpointer p)
{
	(void) p;
	CSURL(cs);
	if (!cs) return;

	GSList *list = NULL;
	GError *err = conscience_remote_get_types (cs, &list);
	if (err != NULL) {
		GRID_WARN ("SRVTYPES reload error [%s] from [%s] : (%d) %s",
			nsname, cs, err->code, err->message);
		return;
	}

	gchar **newset = (gchar **) metautils_list_to_array (list);
	g_slist_free (list);
	list = NULL;

	NSINFO_DO(gchar **tmp = srvtypes;
	srvtypes = newset;
	newset = tmp;);

	if (newset)
		g_strfreev (newset);
}

// Poll some elements and forward them
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

		{"LbRefresh", OT_INT, {.i = &lb_downstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"
			"\t\t-1 to disable, 0 to never refresh"},
		{"NsinfoRefresh", OT_UINT, {.u = &nsinfo_refresh_delay},
			"Interval between NS configuration's refreshes (seconds)"},

		{"SrvPush", OT_INT, {.u = &lb_upstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"
			"\t\t-1 to disable, 0 to never refresh"},

		{"Cache", OT_BOOL, {.b = &flag_cache_enabled},
			"Disable caching for the conscience: services are pushed\n"
			"synchronously and no cache is kept on a GET."},

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
	if (dispatcher) {
		http_request_dispatcher_clean (dispatcher);
		dispatcher = NULL;
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
	if (push_queue) {
		lru_tree_destroy (push_queue);
		push_queue = NULL;
	}
	namespace_info_clear (&nsinfo);
	oio_str_clean (&nsname);
	g_mutex_clear(&nsinfo_mutex);
	g_mutex_clear(&push_mutex);
	g_mutex_clear(&csurl_mutex);
	g_mutex_clear(&srv_mutex);
	oio_str_clean (&csurl);

	g_slist_free_full (config_urlv, g_free);
	config_urlv = NULL;
}

static void
configure_request_handlers (void)
{
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/status/#GET", action_status);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/forward/$SRVID/#POST", action_forward);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/status/#GET", action_cache_status);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/flush/local/#POST", action_cache_flush_local);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/flush/high/#POST", action_cache_flush_high);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/flush/low/#POST", action_cache_flush_low);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/ttl/low/$COUNT/#POST", action_cache_set_ttl_low);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/ttl/high/$COUNT/#POST", action_cache_set_ttl_high);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/max/low/$COUNT/#POST", action_cache_set_max_low);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cache/max/high/$COUNT/#POST", action_cache_set_max_high);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/lb/$NS/$POOL/$KEY/#GET", action_lb_hash);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/lb/$NS/$POOL/#GET", action_lb_def);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/#HEAD", action_cs_nscheck);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/#GET", action_cs_info);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/$TYPE/#HEAD", action_cs_srvcheck);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/$TYPE/#GET", action_cs_get);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/$TYPE/#PUT", action_cs_put);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/$TYPE/#DELETE", action_cs_del);
	// TODO maybe it should be interesting to provide "per-service" URL instead
	// of "per pool". Especially to manage the actions below.
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/cs/$NS/$TYPE/action/#POST", action_cs_action);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/#HEAD", action_dir_ref_has);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/#GET", action_dir_ref_list);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/#PUT", action_dir_ref_create);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/#DELETE", action_dir_ref_destroy);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/action/#POST", action_dir_ref_action);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/$TYPE/#HEAD", action_dir_srv_list);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/$TYPE/#GET", action_dir_srv_list);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/$TYPE/#DELETE", action_dir_srv_unlink);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$ACCOUNT/$REF/$TYPE/action/#POST", action_dir_srv_action);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/dir/$NS/$CID/#GET", action_dir_resolve);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/#HEAD", action_m2_container_check);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/#GET", action_m2_container_list);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/#PUT", action_m2_container_create);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/#DELETE", action_m2_container_destroy);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/action/#POST", action_m2_container_action);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/#HEAD", action_m2_content_check);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/#GET", action_m2_content_get);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/#PUT", action_m2_content_put);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/#COPY", action_m2_content_copy);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/#DELETE", action_m2_content_delete);
	path_parser_configure (path_parser, PROXYD_PREFIX2 "/m2/$NS/$ACCOUNT/$REF/$PATH/action/#POST", action_m2_content_action);

	path_parser_configure (path_parser, PROXYD_PREFIX2 "/sqlx/$NS/$ACCOUNT/$REF/$TYPE/$SEQ/action/#POST", action_sqlx_action);

    // New routes
    //
	// Load Balancing
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/lb/choose/#GET", action_lb_choose);

	// Conscience
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/check/#HEAD", action_conscience_check);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/info/#GET", action_conscience_info);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/list/#GET", action_conscience_list);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/register/#POST", action_conscience_register);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/deregister/#POST", action_conscience_deregister);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/lock/#POST", action_conscience_lock);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/conscience/unlock/#POST", action_conscience_unlock);

    // Directory
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/create/#POST", action_ref_create);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/destroy/#POST", action_ref_destroy);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/show/#GET", action_ref_show);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/get_properties/#POST", action_ref_prop_get);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/set_properties/#POST", action_ref_prop_set);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/del_properties/#POST", action_ref_prop_del);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/link/#POST", action_ref_link);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/unlink/#POST", action_ref_unlink);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/force/#POST", action_ref_force);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/reference/renew/#POST", action_ref_renew);


    // Meta2
    // Container
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/create/#POST", action_container_create);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/destroy/#POST", action_container_destroy);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/show/#GET", action_container_show);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/list/#GET", action_container_list);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/get_properties/#POST", action_container_prop_get);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/set_properties/#POST", action_container_prop_set);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/del_properties/#POST", action_container_prop_del);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/touch/#POST", action_container_touch);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/dedup/#POST", action_container_dedup);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/purge/#POST", action_container_purge);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/raw_insert/#POST", action_container_raw_insert);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/raw_update/#POST", action_container_raw_update);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/container/raw_delete/#POST", action_container_raw_delete);

    // Content
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/create/#POST", action_content_put);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/delete/#POST", action_content_delete);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/show/#GET", action_content_show);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/prepare/#POST", action_content_prepare);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/get_properties/#POST", action_content_prop_get);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/set_properties/#POST", action_content_prop_set);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/del_properties/#POST", action_content_prop_del);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/touch/#POST", action_content_touch);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/spare/#POST", action_content_spare);
    path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/content/copy/#POST", action_content_copy);

    // Admin
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/ping/#POST", action_admin_ping);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/status/#POST", action_admin_status);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/drop_cache/#POST", action_admin_drop_cache);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/sync/#POST", action_admin_sync);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/leave/#POST", action_admin_leave);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/debug/#POST", action_admin_debug);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/copy/#POST", action_admin_copy);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/get_properties/#POST", action_admin_prop_get);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/set_properties/#POST", action_admin_prop_set);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/del_properties/#POST", action_admin_prop_del);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/freeze/#POST", action_admin_freeze);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/enable/#POST", action_admin_enable);
	path_parser_configure (path_parser, PROXYD_PREFIX "/$NS/admin/disable/#POST", action_admin_disable);

}

static gboolean
grid_main_configure (int argc, char **argv)
{
	static struct http_request_descr_s all_requests[] = {
		{"action", handler_action},
		{NULL, NULL}
	};

	if (argc != 2) {
		GRID_ERROR ("Invalid parameter, expected : IP:PORT NS");
		return FALSE;
	}

	const char *cfg_main_url = argv[0];
	const char *cfg_namespace = argv[1];

	g_mutex_init (&csurl_mutex);
	g_mutex_init (&push_mutex);
	g_mutex_init (&nsinfo_mutex);
	g_mutex_init (&srv_mutex);

	nsname = g_strdup (cfg_namespace);
	csurl = gridcluster_get_conscience (nsname);
	metautils_strlcpy_physical_ns (nsname, cfg_namespace, strlen (nsname) + 1);

	memset (&nsinfo, 0, sizeof (nsinfo));
	metautils_strlcpy_physical_ns (nsinfo.name, cfg_namespace, sizeof (nsinfo.name));
	nsinfo.chunk_size = 1;

	path_parser = path_parser_init ();
	configure_request_handlers ();

	dispatcher = transport_http_build_dispatcher (path_parser, all_requests);
	server = network_server_init ();
	lbpool = grid_lbpool_create (nsname);
	srv_down = lru_tree_create((GCompareFunc)g_strcmp0, g_free,
			NULL, LTO_NOATIME);

	resolver = hc_resolver_create ();
	enum hc_resolver_flags_e f = 0;
	if (flag_cache_enabled)
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

	// Prepare a queue responsible for upstream to the conscience
	if (lb_upstream_delay > 0) {
		push_queue = _push_queue_create();
		upstream_gtq = grid_task_queue_create ("upstream");
		grid_task_queue_register(upstream_gtq, (guint) lb_upstream_delay,
				(GDestroyNotify) _task_push, NULL, NULL);
	}

	// Prepare a queue responsible for the downstream from the conscience
	downstream_gtq = grid_task_queue_create ("downstream");

	grid_task_queue_register (downstream_gtq, (guint) lb_downstream_delay,
		(GDestroyNotify) _task_reload_lbpool, NULL, NULL);

	// Now prepare a queue for administrative tasks, such as cache expiration,
	// configuration reloadings, etc.
	admin_gtq = grid_task_queue_create ("admin");

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_services_down, NULL, NULL);

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_resolver, NULL, NULL);

	grid_task_queue_register (admin_gtq, nsinfo_refresh_delay,
		(GDestroyNotify) _task_reload_csurl, NULL, NULL);

	grid_task_queue_register (admin_gtq, nsinfo_refresh_delay,
		(GDestroyNotify) _task_reload_nsinfo, NULL, NULL);

	grid_task_queue_register (admin_gtq, nsinfo_refresh_delay,
		(GDestroyNotify) _task_reload_srvtypes, NULL, NULL);

	network_server_bind_host (server, cfg_main_url, dispatcher, transport_http_factory);
	for (GSList *lu=config_urlv; lu ;lu=lu->next)
		network_server_bind_host (server, lu->data, dispatcher, transport_http_factory);

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
