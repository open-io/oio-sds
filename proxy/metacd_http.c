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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacd.http"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <glib.h>
#include <json.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <cluster/remote/gridcluster_remote.h>
#include <server/network_server.h>
#include <server/stats_holder.h>
#include <resolver/hc_resolver.h>
#include <meta1v2/meta1_remote.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <meta2/remote/meta2_services_remote.h>

#include "macros.h"
#include "path_parser.h"
#include "transport_http.h"

#define BADREQ(M,...) NEWERROR(CODE_BAD_REQUEST,M,##__VA_ARGS__)

#define OPT(N)    _req_get_option(args,(N))
#define TOK(N)    _req_get_token(args,(N))
#define NS()      TOK("NS")
#define POOL()    TOK("POOL")
#define TYPE()    TOK("TYPE")
#define REF()     TOK("REF")
#define PATH()    TOK("PATH")
#define SEQ()     TOK("SEQ")

#define PUSH_DO(Action) do { \
	g_mutex_lock(&push_mutex); \
	Action ; \
	g_mutex_unlock(&push_mutex); \
} while (0)

#define NSINFO_DO(Action) do { \
	g_mutex_lock(&nsinfo_mutex); \
	Action ; \
	g_mutex_unlock(&nsinfo_mutex); \
} while (0)

static struct path_parser_s *path_parser = NULL;
static struct http_request_dispatcher_s *dispatcher = NULL;
static struct network_server_s *server = NULL;

static gchar *nsname = NULL;
static struct hc_resolver_s *resolver = NULL;
static struct grid_lbpool_s *lbpool = NULL;

static struct lru_tree_s *push_queue = NULL;
static GMutex push_mutex;

static struct grid_task_queue_s *admin_gtq = NULL;
static struct grid_task_queue_s *upstream_gtq = NULL;
static struct grid_task_queue_s *downstream_gtq = NULL;

static GThread *admin_thread = NULL;
static GThread *upstream_thread = NULL;
static GThread *downstream_thread = NULL;

static struct namespace_info_s nsinfo;
static gchar **srvtypes = NULL;
static GMutex nsinfo_mutex;

// Configuration
static gint timeout_cs_push = PROXYD_DEFAULT_TIMEOUT_CONSCIENCE;
static gint lb_downstream_delay = PROXYD_DEFAULT_PERIOD_DOWNSTREAM;
static guint lb_upstream_delay = PROXYD_DEFAULT_PERIOD_UPSTREAM;
static guint nsinfo_refresh_delay = 5;

static guint dir_low_ttl = PROXYD_DEFAULT_TTL_SERVICES;
static guint dir_low_max = PROXYD_DEFAULT_MAX_SERVICES;
static guint dir_high_ttl = PROXYD_DEFAULT_TTL_CSM0;
static guint dir_high_max = PROXYD_DEFAULT_MAX_CSM0;

static gdouble dir_timeout_req = PROXYD_DIR_TIMEOUT_SINGLE;
static gdouble dir_timeout_all = PROXYD_DIR_TIMEOUT_SINGLE;

static gdouble m2_timeout_req = PROXYD_M2_TIMEOUT_SINGLE;
static gdouble m2_timeout_all = PROXYD_M2_TIMEOUT_SINGLE;

static gboolean validate_namespace (const gchar * ns);
static gboolean validate_srvtype (const gchar * n);

#include "url.c"
#include "reply.c"
#include "common.c"

#include "dir_actions.c"
#include "lb_actions.c"
#include "cs_actions.c"
#include "sqlx_actions.c"
#include "m2_actions.c"
#include "cache_actions.c"

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
	grid_stats_holder_foreach(args->rq->client->main_stats, NULL, runner);

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

	// Purify the path
	register int slash = 1;
	for (register const gchar *p = path; *p ;++p) {
		if (slash && *p == '/')
			continue;
		slash = ('/' == (*(pk++) = *p));
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
		metautils_str_reuse(p, unescaped);
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
		hc_url_set (url, HCURL_NS, s);
	if (NULL != (s = REF()))
		hc_url_set (url, HCURL_REFERENCE, s);
	if (NULL != (s = PATH()))
		hc_url_set (url, HCURL_PATH, s);

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
		gridd_set_reqid(reqid);
	else
		gridd_set_random_reqid();

	// Then parse the request to find a handler
	struct hc_url_s *url = NULL;
	struct req_uri_s ruri = {NULL, NULL, NULL, NULL, NULL};
	_req_uri_extract_components (rq->req_uri, &ruri);

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
	_req_uri_free_components (&ruri);
	hc_url_pclean (&url);
	return rc;
}

static gboolean
validate_namespace (const gchar * ns)
{
	return 0 == strcmp (ns, nsname);
}

static gboolean
validate_srvtype (const gchar * n)
{
	gboolean rc = FALSE;
	NSINFO_DO(if (srvtypes) {
		for (gchar ** p = srvtypes; !rc && *p; ++p)
			rc = !strcmp (*p, n);
	});
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
_task_expire_resolver (struct hc_resolver_s *r)
{
	hc_resolver_set_now (r, time (0));
	guint count = hc_resolver_expire (r);
	if (count)
		GRID_DEBUG ("Expired %u resolver entries", count);
	count = hc_resolver_purge (r);
	if (count)
		GRID_DEBUG ("Purged %u resolver ", count);
}

static void
_task_reload_lbpool (struct grid_lbpool_s *p)
{
	GError *err;

	if (NULL != (err = gridcluster_reconfigure_lbpool (p))) {
		GRID_NOTICE ("LBPOOL : reconfigure error : (%d) %s", err->code,
			err->message);
		g_clear_error (&err);
	}

	if (NULL != (err = gridcluster_reload_lbpool (p))) {
		GRID_NOTICE ("LBPOOL : reload error : (%d) %s", err->code,
			err->message);
		g_clear_error (&err);
	}
}

static void
_task_reload_nsinfo (gpointer p)
{
	(void) p;
	GError *err = NULL;
	struct namespace_info_s *ni;

	if (!(ni = get_namespace_info (nsname, &err))) {
		GRID_WARN ("NSINFO reload error [%s] : (%d) %s",
			nsname, err->code, err->message);
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
	GError *err = NULL;

	GSList *_l = list_namespace_service_types (nsname, &err);
	if (err != NULL) {
		GRID_WARN ("SRVTYPES reload error [%s] : (%d) %s",
			nsname, err->code, err->message);
		return;
	}

	gchar **newset = (gchar **) metautils_list_to_array (_l);
	g_slist_free (_l);
	_l = NULL;

	NSINFO_DO(register gchar **tmp = srvtypes;
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

	struct addr_info_s *csaddr = gridcluster_get_conscience_addr(nsname);
	if (!csaddr) {
		GRID_ERROR("Push error: %s", "No/Invalid conscience for namespace NS");
	} else {
		GError *err = NULL;
		gcluster_push_services (csaddr, timeout_cs_push, tmp, TRUE, &err);
		if (err != NULL) {
			GRID_WARN("Push error: (%d) %s", err->code, err->message);
			g_clear_error(&err);
		}
		g_free(csaddr);
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

		{"LbRefresh", OT_INT, {.i = &lb_downstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"
			"\t\t-1 to disable, 0 to never refresh"},
		{"NsinfoRefresh", OT_UINT, {.u = &nsinfo_refresh_delay},
			"Interval between NS configuration's refreshes (seconds)"},
		{"SrvPush", OT_INT, {.u = &lb_upstream_delay},
			"Interval between load-balancer service refreshes (seconds)\n"
			"\t\t-1 to disable, 0 to never refresh"},

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
	namespace_info_clear (&nsinfo);
	metautils_str_clean (&nsname);
	g_mutex_clear(&nsinfo_mutex);
	g_mutex_clear(&push_mutex);
}

static void
configure_request_handlers (void)
{
	path_parser_configure (path_parser, PROXYD_PREFIX "/status/#GET", action_status);

	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/status/#GET", action_cache_status);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/flush/high/#POST", action_cache_flush_high);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/flush/low/#POST", action_cache_flush_low);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/ttl/low/$COUNT/#POST", action_cache_set_ttl_low);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/ttl/high/$COUNT/#POST", action_cache_set_ttl_high);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/max/low/$COUNT/#POST", action_cache_set_max_low);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cache/max/high/$COUNT/#POST", action_cache_set_max_high);

	path_parser_configure (path_parser, PROXYD_PREFIX "/lb/$NS/$POOL/$KEY/#GET", action_lb_hash);
	path_parser_configure (path_parser, PROXYD_PREFIX "/lb/$NS/$POOL/#GET", action_lb_def);

	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/types/$NS/#GET", action_cs_srvtypes);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/#HEAD", action_cs_nscheck);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/#GET", action_cs_info);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/$TYPE/#HEAD", action_cs_srvcheck);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/$TYPE/#GET", action_cs_get);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/$TYPE/#PUT", action_cs_put);
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/$TYPE/#DELETE", action_cs_del);
	// TODO maybe it should be interesting to provide "per-service" URL instead
	// of "per pool". Especially to manage the actions below.
	path_parser_configure (path_parser, PROXYD_PREFIX "/cs/$NS/$TYPE/action/#POST", action_cs_action);

	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/#HEAD", action_dir_ref_has);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/#GET", action_dir_ref_list);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/#PUT", action_dir_ref_create);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/#DELETE", action_dir_ref_destroy);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/action/#POST", action_dir_ref_action);

	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/$TYPE/#HEAD", action_dir_srv_list);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/$TYPE/#GET", action_dir_srv_list);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/$TYPE/#DELETE", action_dir_srv_unlink);
	path_parser_configure (path_parser, PROXYD_PREFIX "/dir/$NS/$REF/$TYPE/action/#POST", action_dir_srv_action);

	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/#HEAD", action_m2_container_check);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/#GET", action_m2_container_list);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/#PUT", action_m2_container_create);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/#DELETE", action_m2_container_destroy);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/action/#POST", action_m2_container_action);

	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/#HEAD", action_m2_content_check);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/#GET", action_m2_content_get);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/#PUT", action_m2_content_put);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/#COPY", action_m2_content_copy);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/#DELETE", action_m2_content_delete);
	path_parser_configure (path_parser, PROXYD_PREFIX "/m2/$NS/$REF/$PATH/action/#POST", action_m2_content_action);

	path_parser_configure (path_parser, PROXYD_PREFIX "/sqlx/$NS/$REF/$TYPE/$SEQ/action/#POST", action_sqlx_action);
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

	g_mutex_init (&push_mutex);
	g_mutex_init (&nsinfo_mutex);

	nsname = g_strdup (argv[1]);
	metautils_strlcpy_physical_ns (nsname, argv[1], strlen (nsname) + 1);

	memset (&nsinfo, 0, sizeof (nsinfo));
	metautils_strlcpy_physical_ns (nsinfo.name, argv[1], sizeof (nsinfo.name));
	nsinfo.chunk_size = 1;

	path_parser = path_parser_init ();
	configure_request_handlers ();

	dispatcher = transport_http_build_dispatcher (path_parser, all_requests);
	server = network_server_init ();
	resolver = hc_resolver_create ();
	lbpool = grid_lbpool_create (nsname);

	if (resolver) {
		hc_resolver_set_ttl_csm0 (resolver, dir_high_ttl);
		hc_resolver_set_max_csm0 (resolver, dir_high_max);
		hc_resolver_set_ttl_services (resolver, dir_low_ttl);
		hc_resolver_set_max_services (resolver, dir_low_max);
		GRID_INFO ("RESOLVER limits HIGH[%u/%u] LOW[%u/%u]",
			dir_high_max, dir_high_ttl, dir_low_max, dir_low_ttl);
	}

	// Prepare a queue responsible for upstream to the conscience
	push_queue = _push_queue_create();

	upstream_gtq = grid_task_queue_create ("upstream");

	grid_task_queue_register(upstream_gtq, (guint) lb_upstream_delay,
			(GDestroyNotify) _task_push, NULL, NULL);

	// Prepare a queue responsible for the downstream from the conscience
	downstream_gtq = grid_task_queue_create ("downstream");

	grid_task_queue_register (downstream_gtq, (guint) lb_downstream_delay,
		(GDestroyNotify) _task_reload_lbpool, NULL, lbpool);

	// Now prepare a queue for administrative tasks, such as cache expiration,
	// configuration reloadings, etc.
	admin_gtq = grid_task_queue_create ("admin");

	grid_task_queue_register (admin_gtq, 1,
		(GDestroyNotify) _task_expire_resolver, NULL, resolver);

	grid_task_queue_register (admin_gtq, nsinfo_refresh_delay,
		(GDestroyNotify) _task_reload_nsinfo, NULL, lbpool);

	grid_task_queue_register (admin_gtq, nsinfo_refresh_delay,
		(GDestroyNotify) _task_reload_srvtypes, NULL, NULL);

	network_server_bind_host (server, argv[0],
		dispatcher, transport_http_factory);

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
