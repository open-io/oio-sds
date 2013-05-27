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
# define G_LOG_DOMAIN "grid.meta0.server"
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
#include "../metautils/lib/common_main.h"
#include "../cluster/lib/gridcluster.h"
#include "../sqliterepo/sqliterepo.h"
#include "../sqliterepo/replication_dispatcher.h"
#include "../sqliterepo/zk_manager.h"

#include "../server/network_server.h"
#include "../server/grid_daemon.h"
#include "../server/stats_holder.h"
#include "../server/transport_gridd.h"

#include "./internals.h"
#include "./meta0_backend.h"
#include "./meta0_gridd_dispatcher.h"

static gboolean flag_noregister = FALSE;

static gchar volume[1024];

static gchar ns_name[1024];

static GString *url = NULL;

static GQuark gquark_log = 0;

static gchar *zk_url = NULL;

static struct meta0_backend_s *m0 = NULL;

static struct meta0_disp_s *m0disp = NULL;

static struct network_server_s *server = NULL;

static struct gridd_request_dispatcher_s *dispatcher = NULL;

static GThread *register_thread = NULL;

static guint max_bases = 0;

static guint max_connections = 0;

static struct grid_single_rrd_s *gsr_reqcounter = NULL;
static struct grid_single_rrd_s *gsr_reqtime = NULL;

static struct grid_main_option_s meta0_options[] =
{
	{"NoRegister", OT_BOOL, {.b=&flag_noregister},
		"If enabled, the meta0 won't register in the conscience"},
	{"Endpoint", OT_STRING, {.str=&url},
		"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
	{NULL, 0, {.i=0}, NULL}
};

static struct replication_config_s replication_config;

static struct zk_manager_s *m0zkmanager = NULL;

static gboolean _register_to_zookeeper(void);

static const char *
meta0_usage(void)
{
	return "NS VOLUME";
}

static struct grid_main_option_s *
meta0_get_options(void)
{
	return meta0_options;
}

static void
meta0_specific_fini(void)
{
	if (server) {
		network_server_stop(server);
		network_server_close_servers(server);
	}

	if (register_thread) {
		g_thread_join(register_thread);
		register_thread = NULL;
	}

	if(m0)
		sqlx_repository_exit_elections(meta0_backend_get_repository(m0),NULL);

	if (m0zkmanager)
		zk_manager_clean(m0zkmanager);
	if (server)
		network_server_clean(server);
	if (dispatcher)
		gridd_request_dispatcher_clean(dispatcher);
	if (m0disp)
		meta0_gridd_free_dispatcher(m0disp);
	if (m0)
		meta0_backend_clean(m0);
	if (url)
		g_string_free(url, TRUE);

	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));

	if (gsr_reqtime)
		grid_single_rrd_destroy(gsr_reqtime);
	if (gsr_reqcounter)
		grid_single_rrd_destroy(gsr_reqcounter);
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
meta0_set_defaults(void)
{
	if (!gquark_log)
		gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));
	memset(&replication_config, 0, sizeof(replication_config));
	url = NULL;

	gsr_reqtime = grid_single_rrd_create(8);
	gsr_reqcounter = grid_single_rrd_create(8);
}

static gboolean
meta0_configure(int argc, char **argv)
{
	gsize s;

	if (!url) {
		GRID_WARN("No service URL!");
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

	zk_url = gridcluster_get_config(ns_name, "zookeeper",
			GCLUSTER_CFG_NS|GCLUSTER_CFG_LOCAL);
	if (!zk_url) {
		GRID_INFO("No replication : no ZooKeeper URL configured");
	} else {
		GRID_INFO("Got zookeeper URL [%s]", zk_url);
	}

	GRID_DEBUG("META0 NS configured to [%s]", ns_name);
	GRID_DEBUG("META0 Volume configured to [%s]", volume);

	configure_max_descriptors();
	return TRUE;
}

static void
meta0_specific_stop(void)
{
	GRID_TRACE("STOP!");
	if (server)
		network_server_stop(server);
}

/* -------------------------------------------------------------------------- */

static gpointer
register_thread_worker(gpointer p)
{
	guint lastreg = 0, jiffies = 0;
	time_t now, last = 0;

	gchar *straddr = p;
	GError *err = NULL;
	struct service_info_s *si;
	gboolean zkregister=FALSE;

	metautils_ignore_signals();

	si = g_malloc0(sizeof(*si));
	si->tags = g_ptr_array_new();
	g_strlcpy(si->ns_name, ns_name, sizeof(si->ns_name)-1);
	g_strlcpy(si->type, "meta0", sizeof(si->type)-1);
	if (!grid_string_to_addrinfo(straddr, straddr+strlen(straddr), &(si->addr))) {
		GRID_WARN("Invalid URL [%s] : (%d) %s",
				straddr, errno, strerror(errno));
		grid_main_stop();
		return p;
	}

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

	while (grid_main_is_running()) {
		guint64 avg_counter, avg_time;

		/* Computes the avg requests rate/time */
		grid_single_rrd_feed(network_server_get_stats(server),
				INNER_STAT_NAME_REQ_COUNTER, gsr_reqcounter,
				INNER_STAT_NAME_REQ_TIME, gsr_reqtime,
				NULL);
		avg_counter = grid_single_rrd_get_delta(gsr_reqcounter, 4);
		avg_time = grid_single_rrd_get_delta(gsr_reqtime, 4);

		service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.total_reqpersec"), avg_counter / 4);
		service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.total_avreqtime"), (avg_time+1)/(avg_counter+1));

		if (!zkregister)
			zkregister = _register_to_zookeeper();
		else if (lastreg != jiffies) {
			if (!register_namespace_service(si, &err))
				g_message("Failed to register the META0 in the gridagent : (%d) %s",
					err->code, err->message);
			if (err)
				g_clear_error(&err);
			lastreg = jiffies;
		}

		if (!sqlx_repository_replication_configured(meta0_backend_get_repository(m0)))
			sleep(1);
		else {
			err = sqlx_repository_clients_round(meta0_backend_get_repository(m0), 1);
			if (err != NULL) {
				GRID_ERROR("Clients error : (%d) %s", err->code, err->message);
				g_clear_error(&err);
				grid_main_stop();
			}
		}

		if ((now = time(0)) != last) {
			++ jiffies;
			last = now;
		}
	}

	service_info_clean(si);
	return p;
}

static gchar **
strv_filter(GSList *src) {
	gchar **result;
	guint max;

	GSList *tmp;
	addr_info_t *addr;
	GError *err;
	struct zk_node_s *zknode;

	max=0;
	result = g_malloc0(sizeof(gchar*) * (max+1));

	tmp=src;
	for ( ;tmp;tmp=tmp->next) {
		zknode = tmp->data;
		if ( zknode->content != NULL) {
			if (g_ascii_strcasecmp(url->str,zknode->content) != 0 )
			{
				addr = g_malloc0(sizeof(addr_info_t));
				if (!l4_address_init_with_url(addr, zknode->content, &err)) {
					g_clear_error(&err);
					g_free(addr);
				} else {
					max ++;
					result = g_realloc(result, sizeof(gchar*) * (max+1));
					result[max-1] = g_strdup(zknode->content);
					result[max] = NULL;
					g_free(addr);
				}
			}
		}
	}

	return result;
}



static gchar **
_get_peers(gpointer ctx, const gchar *n, const gchar *t)
{
	(void) ctx; 
	GSList *peers;
	GError *err;
	gchar **result=NULL;

	if (g_ascii_strcasecmp(t, META0_TYPE_NAME))
		return g_malloc0(sizeof(void*));

	if (g_ascii_strcasecmp(n, ns_name))
		return g_malloc0(sizeof(void*));

	err = list_zk_children_node(m0zkmanager,NULL,&peers);
	if (err ) {
		g_slist_foreach(peers,free_zknode, NULL);
		g_slist_free(peers);
		result = g_malloc0(sizeof(void*));
	} else {
		result = strv_filter(peers);
	}
	return result;
	/* @todo FIXME TODO contacts the conscience to learn the meta0 list */
	//return g_malloc0(sizeof(void*));
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

static void
_callback_reload(sqlx_repository_t *repo, const gchar *n, const gchar *t,
		gpointer u)
{
	(void) repo;
	(void) n;
	(void) t;
	(void) u;
	meta0_gridd_requested_reload(m0disp);
}

static gboolean
_register_to_zookeeper(void) {
	struct sqlx_repository_s *repo;
	GError *err;

	// register to zookeeper
	if (m0zkmanager) {
		err = create_zk_node(m0zkmanager, NULL, url->str, url->str);
		if ( err ) {
			GRID_WARN("Failed to register meta0 [%s] to zookeeper",url->str);
			g_clear_error(&err);
			return FALSE;
		}
	}

	repo = meta0_backend_get_repository(m0);
	if (!sqlx_repository_replication_configured(repo)) {
		GRID_DEBUG("Replication disabled, no election warmup necessary");
	} else {
		sqlx_repository_configure_close_callback(repo, _callback_reload, NULL);
		
		err = sqlx_repository_use_base(repo, META0_TYPE_NAME, ns_name);
		if ( err ) {
			GRID_WARN("Failed to prepare meta0 election : (%d) %s", err->code, err->message);
			g_clear_error(&err);
		} else {
			sleep(1);
		}
	}
	return TRUE;
}


static void
meta0_action(void)
{
	GError *err;

	/* Configures the backend part */
	err = meta0_backend_init(&m0, ns_name, url->str, volume);
	if (err) {
		GRID_WARN("META0 backend init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}
	if (max_bases) {
		sqlx_repository_configure_maxbases(meta0_backend_get_repository(m0),
				max_bases);
	}
	GRID_TRACE("META0 backend initiated!");

	if (zk_url) {
		err = zk_srv_manager_create(ns_name,zk_url,META0_TYPE_NAME,&m0zkmanager);
		if ( err ) {
			GRID_WARN("Zk manager init failed : (%d) %s",err->code, err->message);
			g_clear_error(&err);
			return;
		}

		replication_config.mode = ELECTION_MODE_QUORUM;
		replication_config.ctx = m0;
		replication_config.get_peers = _get_peers;
		replication_config.get_manager_url = _get_zk;
		replication_config.get_ns_name = _get_ns;
		replication_config.get_local_url = _get_url;
		replication_config.subpath = "el/meta0";
		replication_config.hash_width = 0;
		replication_config.hash_depth = 0;

		err = sqlx_repository_configure_replication(
				meta0_backend_get_repository(m0), &replication_config);
		if (err != NULL) {
			GRID_WARN("SQLX replication init failure : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return;
		}
	}

	//migrate meta0 DB
	meta0_backend_migrate(m0);

	/* Configures the network part */
	if (!(server = network_server_init())) {
		GRID_WARN("SERVER init failure : (%d) %s", errno, strerror(errno));
		return;
	}
	if (max_connections)
		network_server_set_maxcnx(server, max_connections);

	dispatcher = transport_gridd_build_empty_dispatcher();
	m0disp = meta0_gridd_get_dispatcher(m0,m0zkmanager,ns_name);
	transport_gridd_dispatcher_add_requests(dispatcher, meta0_gridd_get_requests(), m0disp);
	transport_gridd_dispatcher_add_requests(dispatcher, sqlx_repli_gridd_get_requests(), meta0_backend_get_repository(m0));
	grid_daemon_bind_host(server, url->str, dispatcher);

	if (NULL != (err = network_server_open_servers(server))) {
		GRID_WARN("Failed to start some server sockets : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* Start the administrative threads */
	if (!flag_noregister) {
		register_thread = g_thread_create(register_thread_worker, url->str, TRUE, &err);
		if (!register_thread) {
			GRID_WARN("Failed to start the REGISTER tread : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return;
		}
	}

	/* SERVER/GRIDD main run loop */
	if (NULL != (err = network_server_run(server))) {
		GRID_WARN("GRIDD run failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	GRID_INFO("Normally exiting.");
}

static struct grid_main_callbacks meta0_callbacks =
{
	.options = meta0_get_options,
	.action = meta0_action,
	.set_defaults = meta0_set_defaults,
	.specific_fini = meta0_specific_fini,
	.configure = meta0_configure,
	.usage = meta0_usage,
	.specific_stop = meta0_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &meta0_callbacks);
}

