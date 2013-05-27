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
# define G_LOG_DOMAIN "grid.meta2.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <glib.h>

#include "../metautils/lib/metautils.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/common_main.h"
#include "../server/network_server.h"
#include "../server/grid_daemon.h"
#include "../server/stats_holder.h"
#include "../server/transport_gridd.h"
#include "../cluster/lib/gridcluster.h"
#include "../resolver/hc_resolver.h"
#include "../sqliterepo/sqliterepo.h"
#include "../sqliterepo/replication_dispatcher.h"
#include "../sqliterepo/upgrade.h"


#include "./meta2_gridd_dispatcher.h"
#include "./meta2_backend.h"
#include "./meta2_backend_dbconvert.h"

#include "./internals.h"

struct lb_slot_s {
	gchar *name;
	struct grid_lb_s *lb;
	struct grid_lb_iterator_s *iter;
};

struct replication_config_s replication_config;

static GSList *custom_tags;

static gchar volume[1024];

static gchar ns_name[1024];

static GString *url = NULL;

static struct network_server_s *server = NULL;

static struct gridd_request_dispatcher_s *dispatcher = NULL;

static guint period_register = 1;
static guint period_reload_nsinfo = 5;
static guint period_reload_lb = 5;

static GThread *reload_thread = NULL;
static GThread *clients_thread = NULL;

static GHashTable *lb_ht = NULL;

static struct meta2_backend_s *m2 = NULL;
static struct sqlx_repository_s *repo = NULL;

static gchar *zk_url = NULL;

static struct grid_single_rrd_s *gsr_reqcounter = NULL;
static struct grid_single_rrd_s *gsr_reqtime = NULL;

static struct hc_resolver_s *resolver = NULL;

static struct sqlx_upgrader_s *upgrader = NULL;

static guint max_bases = 0;
static guint max_connections = 0;

static struct grid_main_option_s options[] =
{
	{"Endpoint", OT_STRING, {.str=&url},
		"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
	{"Tag", OT_LIST, {.lst=&custom_tags},
                "Tag to associate to the service (multiple custom tags are supported)"},
	{NULL, 0, {.i=0}, NULL}
};

static void
lb_slot_free(gpointer p)
{
	struct lb_slot_s *slot;
	if (!(slot = p))
		return;
	grid_lb_iterator_clean(slot->iter);
	grid_lb_clean(slot->lb);
	g_free(slot->name);
	g_free(slot);
}

static const char *
meta2_usage(void)
{
	return "NS VOLUME";
}

static struct grid_main_option_s *
meta2_get_options(void)
{
	return options;
}

static void
meta2_specific_fini(void)
{
	if (clients_thread) {
		g_thread_join(clients_thread);
	}
	if (reload_thread) {
		g_thread_join(reload_thread);
	}

	if (server) {
		network_server_stop(server);
		network_server_close_servers(server);
		network_server_clean(server);
	}

	if (dispatcher) {
		gridd_request_dispatcher_clean(dispatcher);
	}
	if (m2) {
		meta2_backend_clean(m2);
	}
	if (repo) {
		sqlx_repository_clean(repo);
	}
	if (url) {
		g_string_free(url, TRUE);
	}
	if (custom_tags) {
		g_slist_free_full(custom_tags, g_free);
	}
	if (resolver) {
		hc_resolver_destroy(resolver);
	}
	if (lb_ht) {
		g_hash_table_destroy(lb_ht);
	}

	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));

	if (gsr_reqtime) {
		grid_single_rrd_destroy(gsr_reqtime);
	}
	if (gsr_reqcounter) {
		grid_single_rrd_destroy(gsr_reqcounter);
	}
	m2v2_clean_db();
}

static void
configure_max_descriptors(void)
{
	struct rlimit limit;

	if (0 != getrlimit(RLIMIT_NOFILE, &limit)) {
		GRID_ERROR("Max file descriptor unknown : getrlimit erorr (errno=%d) %s", errno, strerror(errno));
		abort();
	}
	else {
		guint cur100, cur95;
		cur100 = limit.rlim_cur;
		if (cur100 < 64) {
			GRID_ERROR("Not enough file descriptors allowed [%u], minimum 64 required", cur100);
			abort();
		}
		cur95 = cur100 - 50;
		max_bases = cur95 / 2;
		max_connections = cur95 / 2;
		GRID_INFO("MAXFD[%u/%u] CNX[%u] BASES[%u]", cur95, cur100, max_connections, max_bases);
	}
}

static void
meta2_set_defaults(void)
{
	memset(&replication_config, 0, sizeof(replication_config));
	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));
	url = NULL;

	lb_ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, lb_slot_free);

	gsr_reqtime = grid_single_rrd_create(8);
	gsr_reqcounter = grid_single_rrd_create(8);
}

static gboolean
meta2_configure(int argc, char **argv)
{
	gsize s;

	if (!url) {
		GRID_WARN("No URL provided");
		return FALSE;
	}

	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	s = g_strlcpy(ns_name, argv[0], sizeof(ns_name)-1);
	if (s >= sizeof(ns_name)) {
		GRID_WARN("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(ns_name));
		return FALSE;
	}

	s = g_strlcpy(volume, argv[1], sizeof(volume)-1);
	if (s >= sizeof(volume)) {
		GRID_WARN("Volume name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(volume));
		return FALSE;
	}

	GRID_INFO("META2 NS configured to [%s]", ns_name);
	GRID_INFO("META2 Volume configured to [%s]", volume);

	zk_url = gridcluster_get_config(ns_name, "zookeeper",
			GCLUSTER_CFG_NS|GCLUSTER_CFG_LOCAL);

	if (!zk_url) {
		GRID_INFO("No replication : no ZooKeeper URL configured");
	} else {
		GRID_INFO("Got zookeeper URL [%s]", zk_url);
	}

	resolver = hc_resolver_create();
	configure_max_descriptors();
	return TRUE;
}

static void
meta2_specific_stop(void)
{
	GRID_TRACE("STOP!");
	if (server)
		network_server_stop(server);
}

static gboolean
lb_reload_srvtype(const gchar *srvtype)
{
	GError *err = NULL;
	GSList *list_srv = NULL;

	list_srv = list_namespace_services(ns_name, srvtype, &err);
	if (err) {
		GRID_WARN("Gridagent error : Failed to list the services "
				"of type [%s] : code=%d %s", srvtype, err->code,
				err->message);
		g_clear_error(&err);
		return FALSE;
	}

	struct lb_slot_s *slot = g_hash_table_lookup(lb_ht, srvtype);

	if (!slot) {
		slot = g_malloc0(sizeof(*slot));
		slot->lb = grid_lb_init(ns_name, srvtype);
		slot->iter = grid_lb_iterator_weighted_round_robin(slot->lb);
		g_hash_table_insert(lb_ht, g_strdup(srvtype), slot);
	}

	if (NULL != list_srv) {
		GSList *l;
		auto gboolean provide(struct service_info_s **p_si);

		gboolean provide(struct service_info_s **p_si) {
			if (!l)
				return FALSE;
			*p_si = l->data;
			l->data = NULL;
			l = l->next;
			return TRUE;
		}

		GRID_TRACE("Reloading srvtype=[%s] with %u services", srvtype,
				g_slist_length(list_srv));

		l = list_srv;
		grid_lb_reload(slot->lb, provide);

		g_slist_foreach(list_srv, service_info_gclean, NULL);
		g_slist_free(list_srv);
	}

	meta2_backend_configure_type(m2, srvtype, slot->iter);
	return TRUE;
}

static void
_reload_lb(void)
{
	guint errors = 0;
	GError *err = NULL;
	GSList *l, *list_srvtypes = NULL;

	list_srvtypes = list_namespace_service_types(ns_name, &err);
	if (err) {
		GRID_WARN("Gridagent error : Failed to list the service types : "
				"code=%d\n\t%s", err->code, err->message);
		g_clear_error(&err);
		return ;
	}

	for (l=list_srvtypes; l ;l=l->next) {
		if (!lb_reload_srvtype(l->data))
			++ errors;
	}

	if (errors) {
		GRID_TRACE("Reloaded %u service types, with %u errors",
				g_slist_length(list_srvtypes), errors);
		
	}
	if (list_srvtypes) {
		g_slist_foreach(list_srvtypes, g_free1, NULL);
		g_slist_free(list_srvtypes);
	}
}

static void
meta2_reload_nsinfo(void)
{
	GError *err = NULL;
	struct namespace_info_s *ns_info;

	ns_info = get_namespace_info(ns_name, &err);
	if (!ns_info) {
		ASSERT_EXTRA(err != NULL);
		GRID_WARN("Failed to reload the NS info : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
	else {
		meta2_backend_configure_nsinfo(m2, ns_info);
		namespace_info_free(ns_info);
	}
}

/* -------------------------------------------------------------------------- */

static void
_register_service(void)
{
	GError *err = NULL;
	struct service_info_s *si;
	guint64 avg_counter, avg_time;

	metautils_ignore_signals();

	si = g_malloc0(sizeof(*si));
	si->tags = g_ptr_array_new();
	g_strlcpy(si->ns_name, ns_name, sizeof(si->ns_name)-1);
	g_strlcpy(si->type, "meta2", sizeof(si->type)-1);
	if (!grid_string_to_addrinfo(url->str, NULL, &(si->addr))) {
		GRID_WARN("Invalid URL [%s] : code=%d message=%s", url->str,
				errno, strerror(errno));
		grid_main_stop();
		return ;
	}

	unsigned int i;
	for (i = 0; i < g_slist_length(custom_tags); i++) {
		gchar* full_tag = g_slist_nth_data(custom_tags, i);

		gchar** full_tag_tok = g_strsplit(full_tag, "=", -1);
		int j = 0;
		while (full_tag_tok[j]) {
                        j++;
                }

		if (j == 2) {
			gchar* custom_tag_full_name = g_strconcat("tag.", full_tag_tok[0], NULL);

			gchar buf_tag_value[64];
			g_strlcpy(buf_tag_value, full_tag_tok[1], 64);
			service_tag_set_value_string(
                                        service_info_ensure_tag(si->tags, custom_tag_full_name),
                                        buf_tag_value);

			if (custom_tag_full_name) {
                                g_free(custom_tag_full_name);
                        }
		}

		if (full_tag_tok) {
                        g_strfreev(full_tag_tok);
                }
	}

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.type"),
			"m2v2");

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.vol"),
			volume);
	service_tag_set_value_float(
			service_info_ensure_tag(si->tags, "stat.req_idle"),
			1.234);

	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.cpu"),
			"cpu", NULL);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.space"),
			"space", volume);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.io"),
			"io", volume);

	grid_single_rrd_feed(network_server_get_stats(server),
			INNER_STAT_NAME_REQ_COUNTER, gsr_reqcounter,
			INNER_STAT_NAME_REQ_TIME, gsr_reqtime,
			NULL);
	avg_counter = grid_single_rrd_get_delta(gsr_reqcounter, 4);
	avg_time = grid_single_rrd_get_delta(gsr_reqtime, 4);

	service_tag_set_value_i64(service_info_ensure_tag(
				si->tags, "stat.total_reqpersec"), avg_counter / 4);
	service_tag_set_value_i64(service_info_ensure_tag(
				si->tags, "stat.total_avreqtime"), (avg_time+1)/(avg_counter+1));

	if (!register_namespace_service(si, &err)) {
		GRID_ERROR("Failed to register the META2 in the gridagent : "
				"code=%d message=%s", err->code, err->message);
	}
	if (err) {
		g_clear_error(&err);
	}

	service_info_clean(si);
}

static gpointer
reload_thread_worker(gpointer p)
{
	guint64 lastreg = 0, jiffies = 0;
	time_t now, last = 0;

	metautils_ignore_signals();

	while (grid_main_is_running()) {

		if (!(jiffies % period_reload_nsinfo)) {
			meta2_reload_nsinfo();
		}

		if (!(jiffies % period_reload_lb)) {
			_reload_lb();
		}

		if (!(jiffies % period_register) && (lastreg != jiffies)) {
			_register_service();
			lastreg = jiffies;
		}

		sleep(1);

		if ((now = time(0)) != last) {
			++ jiffies;
			last = now;
		}
	}

	return p;
}

static gpointer
clients_thread_worker(gpointer p)
{
	metautils_ignore_signals();

	while (grid_main_is_running()) {
		if (!sqlx_repository_replication_configured(repo))
			sleep(1);
		else {
			GError *err = sqlx_repository_clients_round(repo, 1);
			if (err != NULL) {
				GRID_ERROR("Clients error : (%d) %s", err->code, err->message);
				g_clear_error(&err);
				grid_main_stop();
			}
		}
	}

	return p;
}

static inline gchar **
filter_services(gchar **s, const gchar *t)
{
	GPtrArray *tmp;
	gint64 ownerSeq=1;

	gchar **tab_serv = s;

	//retreive the owner sequence
	for (; *tab_serv ;tab_serv++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*tab_serv);
		if (!strcmp(t, u->srvtype) && !strcmp(u->host, url->str)) {
			ownerSeq = u->seq;
			meta1_service_url_clean(u);
			break;
		}
		else {
			meta1_service_url_clean(u);
		}
	}

	tmp = g_ptr_array_new();
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		if ( u->seq == ownerSeq && 0 == strcmp(t, u->srvtype)
				&& 0 != strcmp(u->host, url->str))
			g_ptr_array_add(tmp, g_strdup(u->host));
		meta1_service_url_clean(u);
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**)g_ptr_array_free(tmp, FALSE);
}

static gchar **
filter_services_and_clean(gchar **src, const gchar *type)
{
	gchar **result = filter_services(src, type);
	g_strfreev(src);
	return result;
}

static gchar **
_get_peers(gpointer ctx, const gchar *n, const gchar *t)
{
	GError *err = NULL;
	gchar **result = NULL;
	struct hc_url_s *u = NULL;

	(void) ctx;

	u = hc_url_empty();
	hc_url_set(u, HCURL_NS, ns_name);
	if (!hc_url_set(u, HCURL_HEXID, n)) {
		GRID_ERROR("Invalid HEXID [%s]", n);
		return NULL;
	}

	err = hc_resolve_reference_service(resolver, u, t, &result);
	hc_url_clean(u);

	if (NULL != err) {
		GRID_ERROR("Peer resolution error on [%s]", n);
		g_clear_error(&err);
		return NULL;
	}

	return filter_services_and_clean(result, t);
}

static const gchar *
_get_zk(gpointer ctx)
{
	(void) ctx;
	return zk_url;
}

static const gchar *
_get_url(gpointer ctx)
{
	(void) ctx;
	return url->str;
}

static const gchar *
_get_ns(gpointer ctx)
{
	(void) ctx;
	return ns_name;
}

static GError*
_upgrade_to_18(struct sqlx_sqlite3_s *sq3, gpointer cb_data)
{
	(void) cb_data;
	g_assert(sq3->db != NULL);
	return m2_convert_db(sq3->db);
}

static GError*
meta2_on_open(struct sqlx_sqlite3_s *sq3, gpointer cb_data)
{
	GRID_TRACE2("%s", __FUNCTION__);
	return sqlx_upgrade_do((struct sqlx_upgrader_s *)cb_data, sq3);
}

static void
meta2_action(void)
{
	GError *err;
	struct sqlx_repo_config_s cfg;

	GRID_DEBUG("initializing repository in directory : %s", volume);
	GRID_DEBUG("initializing backend for ns name : %s", ns_name);

	/* Configures the backend part */
	cfg.flags = SQLX_REPO_DELETEON;
	cfg.lock.ns = ns_name;
	cfg.lock.type = META2_TYPE_NAME;
	cfg.lock.srv = url->str;
	err = sqlx_repository_init(volume, &cfg, &repo);
	if (err) {
		GRID_WARN("META2 repository init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}
	if (max_bases)
		sqlx_repository_configure_maxbases(repo, max_bases);

	/* let bases auto-update after open */
	upgrader = sqlx_upgrader_create();
	sqlx_upgrader_register(upgrader, "!1.8", "1.8", _upgrade_to_18, NULL);
	sqlx_repository_configure_open_callback(repo, meta2_on_open, upgrader);

	err = meta2_backend_init(&m2, repo, ns_name);
	if (err) {
		GRID_WARN("META2 backend init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	meta2_reload_nsinfo();

	/* Configures the replication */
	if (zk_url) {
		replication_config.mode = ELECTION_MODE_QUORUM;
		replication_config.ctx = m2;
		replication_config.get_peers = _get_peers;
		replication_config.get_manager_url = _get_zk;
		replication_config.get_ns_name = _get_ns;
		replication_config.get_local_url = _get_url;
		replication_config.subpath = "el/meta2";
		replication_config.hash_width = 2;
		replication_config.hash_depth = 2;

		err = sqlx_repository_configure_replication(repo, &replication_config);
		if (err != NULL) {
			GRID_WARN("SQLX replication init failure : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return;
		}
	}

	/* Configures the NETWORK management */
	if (!(server = network_server_init())) {
		GRID_WARN("SERVER init failure : code=%d message=%s", errno, strerror(errno));
		return;
	}
	if (max_connections)
		network_server_set_maxcnx(server, max_connections);

	dispatcher = transport_gridd_build_empty_dispatcher();
	transport_gridd_dispatcher_add_requests(dispatcher, meta2_gridd_get_v1_requests(), m2);
	transport_gridd_dispatcher_add_requests(dispatcher, meta2_gridd_get_v2_requests(), m2);
	transport_gridd_dispatcher_add_requests(dispatcher, sqlx_repli_gridd_get_requests(), repo);
	grid_daemon_bind_host(server, url->str, dispatcher);

	if (NULL != (err = network_server_open_servers(server))) {
		GRID_WARN("Failed to start some server sockets : code=%d message=%s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* Now start the administrative threads */

	reload_thread = g_thread_create(reload_thread_worker, url->str, TRUE, &err);
	clients_thread = g_thread_create(clients_thread_worker, url->str, TRUE, &err);
	if (!clients_thread || !reload_thread) {
		GRID_WARN("Failed to start the REGISTER tread : code=%d message=%s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* SERVER/GRIDD main run loop */
	if (NULL != (err = network_server_run(server))) {
		GRID_WARN("GRIDD run failure : code=%d message=%s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	GRID_INFO("Normally exiting.");
}

static struct grid_main_callbacks meta2_callbacks =
{
	.options = meta2_get_options,
	.action = meta2_action,
	.set_defaults = meta2_set_defaults,
	.specific_fini = meta2_specific_fini,
	.configure = meta2_configure,
	.usage = meta2_usage,
	.specific_stop = meta2_specific_stop,
};

int
main(int argc, char **argv)
{
	return grid_main(argc, argv, &meta2_callbacks);
}

