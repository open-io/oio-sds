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
# define G_LOG_DOMAIN "grid.sqlx.server"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <glib.h>

#include "../metautils/lib/hc_url.h"
#include "../metautils/lib/metautils.h"
#include "../metautils/lib/common_main.h"
#include "../metautils/lib/resolv.h"
#include "../metautils/lib/lb.h"
#include "../metautils/lib/svc_policy.h"
#include "../cluster/lib/gridcluster.h"
#include "../server/network_server.h"
#include "../server/grid_daemon.h"
#include "../server/stats_holder.h"
#include "../server/transport_gridd.h"
#include "../sqliterepo/sqliterepo.h"
#include "../sqliterepo/replication_dispatcher.h"
#include "../resolver/hc_resolver.h"

#define SQLX_TYPE "sqlx"

#define SQLX_SCHEMA \
	"INSERT INTO admin(k,v) VALUES (\"schema_version\",\"1.7\");"\
	"INSERT INTO admin(k,v) VALUES (\"version:main.admin\",\"1:0\");"\
	"VACUUM"


struct replication_config_s replication_config;

/*static GQuark gquark_log = 0;*/

static gchar volume[1024];
static gchar ns_name[1024];

static GString *url = NULL;

static gchar *zk_url = NULL;
static struct sqlx_repository_s *repository = NULL;
static struct network_server_s *server = NULL;
static struct gridd_request_dispatcher_s *dispatcher = NULL;

static GThread *register_thread = NULL;

static guint period_register = 1;

static guint max_bases = 0;
static guint max_connections = 0;

static struct grid_single_rrd_s *gsr_reqcounter = NULL;
static struct grid_single_rrd_s *gsr_reqtime = NULL;

static struct hc_resolver_s *resolver = NULL;

/* ------------------------------------------------------------------------- */

static const char *
sqlx_usage(void)
{
	return "NS VOLUME";
}

static struct grid_main_option_s *
sqlx_get_options(void)
{
	static struct grid_main_option_s sqlx_options[] =
	{
		{"Endpoint", OT_STRING, {.str=&url},
			"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
		{NULL, 0, {.i=0}, NULL}
	};

	return sqlx_options;
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
sqlx_specific_fini(void)
{
	if (server) {
		network_server_close_servers(server);
		network_server_stop(server);
	}
	if (register_thread)
		g_thread_join(register_thread);

	if (repository)
		sqlx_repository_exit_elections(repository, NULL);

	if (server)
		network_server_clean(server);
	if (dispatcher)
		gridd_request_dispatcher_clean(dispatcher);
	if (repository)
		sqlx_repository_clean(repository);
	if (url)
		g_string_free(url, TRUE);
	if (resolver)
		hc_resolver_destroy(resolver);

	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));

	if (gsr_reqtime)
		grid_single_rrd_destroy(gsr_reqtime);
	if (gsr_reqcounter)
		grid_single_rrd_destroy(gsr_reqcounter);
}

static void
sqlx_set_defaults(void)
{
	memset(&replication_config, 0, sizeof(replication_config));
	memset(volume, 0, sizeof(volume));
	memset(ns_name, 0, sizeof(ns_name));
	url = NULL;

	gsr_reqtime = grid_single_rrd_create(8);
	gsr_reqcounter = grid_single_rrd_create(8);
}

static gboolean
sqlx_configure(int argc, char **argv)
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
	if (zk_url) {
		GRID_INFO("No replication : no ZooKeeper URL configured");
	} else {
		GRID_INFO("Got zookeeper URL [%s]", zk_url);
	}

	GRID_DEBUG("META1 NS configured to [%s]", ns_name);
	GRID_DEBUG("META1 Volume configured to [%s]", volume);

	resolver = hc_resolver_create();
	configure_max_descriptors();
	return TRUE;
}

static void
sqlx_specific_stop(void)
{
	GRID_TRACE("STOP!");
	if (server)
		network_server_stop(server);
}

/* -------------------------------------------------------------------------- */

static gpointer
register_worker(gpointer p)
{
	guint lastreg = 0, jiffies = 0;
	time_t now, last = 0;

	gchar *straddr = p;
	GError *err = NULL;
	struct service_info_s *si;

	metautils_ignore_signals();

	si = g_malloc0(sizeof(*si));
	si->tags = g_ptr_array_new();
	g_strlcpy(si->ns_name, ns_name, sizeof(si->ns_name)-1);
	g_strlcpy(si->type, "sqlx", sizeof(si->type)-1);
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

		if (!(jiffies % period_register) && (lastreg != jiffies)) {
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

			/* Register now */
			err = NULL;
			if (!register_namespace_service(si, &err))
				g_message("Service registration failed: (%d) %s", err->code, err->message);
			if (err)
				g_clear_error(&err);

			lastreg = jiffies;
		}

		err = sqlx_repository_clients_round(repository, 1);
		if (err != NULL) {
			GRID_ERROR("Clients error : (%d) %s", err->code, err->message);
			g_clear_error(&err);
			grid_main_stop();
		}

		if ((now = time(0)) != last) {
			++ jiffies;
			last = now;
		}
	}

	service_info_clean(si);
	return p;
}

static inline gchar **
filter_services(gchar **s, gint64 seq, const gchar *t)
{
	GPtrArray *tmp;

	tmp = g_ptr_array_new();
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		if (seq == u->seq && 0 == strcmp(t, u->srvtype)
				&& 0 != strcmp(u->host, url->str))
			g_ptr_array_add(tmp, g_strdup(u->host));
		meta1_service_url_clean(u);
	}

	g_ptr_array_add(tmp, NULL);
	return (gchar**)g_ptr_array_free(tmp, FALSE);
}

static gchar **
filter_services_and_clean(gchar **src, gint64 seq, const gchar *type)
{
	gchar **result = filter_services(src, seq, type);
	g_strfreev(src);
	return result;
}

static gchar **
_get_peers(gpointer ctx, const gchar *n, const gchar *t)
{
	gint64 seq;
	GError *err = NULL;
	gchar **result = NULL;
	struct hc_url_s *u = NULL;
	const gchar *sep = strchr(n, '@');

	(void) ctx;

	if (!sep)
		return g_malloc0(sizeof(gchar*));

	seq = g_ascii_strtoll(n, NULL, 10);
	u = hc_url_empty();
	hc_url_set(u, HCURL_NS, ns_name);
	if (!hc_url_set(u, HCURL_HEXID, sep+1)) {
		GRID_ERROR("Invalid HEXID [%s]", sep+1);
		return NULL;
	}

	err = hc_resolve_reference_service(resolver, u, t, &result);
	hc_url_clean(u);

	if (NULL != err) {
		GRID_ERROR("Peer resolution error on [%s]", sep+1);
		g_clear_error(&err);
		return NULL;
	}

	return filter_services_and_clean(result, seq, t);
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
sqlx_action(void)
{
	GError *err;
	struct sqlx_repo_config_s cfg;

	/* Configures the backend part */
	cfg.flags = SQLX_REPO_NOCACHE|SQLX_REPO_AUTOCREATE;
	cfg.lock.ns = ns_name;
	cfg.lock.type = SQLX_TYPE;
	cfg.lock.srv = url->str;
	err = sqlx_repository_init(volume, &cfg, &repository);
	if (err) {
		GRID_WARN("SQLX repository init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	if (max_bases)
		sqlx_repository_configure_maxbases(repository, max_bases);

	err = sqlx_repository_configure_type(repository, SQLX_TYPE, NULL, SQLX_SCHEMA);
	if (err) {
		GRID_ERROR("SQLX schema init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}
	GRID_TRACE("SQLX repository initiated");

	/* Configures the replication */
	if (zk_url) {
		replication_config.mode = ELECTION_MODE_GROUP;
		replication_config.ctx = NULL;
		replication_config.get_peers = _get_peers;
		replication_config.get_manager_url = _get_zk;
		replication_config.get_ns_name = _get_ns;
		replication_config.get_local_url = _get_url;
		replication_config.subpath = "el/sqlx";
		replication_config.hash_width = 2;
		replication_config.hash_depth = 2;

		err = sqlx_repository_configure_replication(repository, &replication_config);
		if (err != NULL) {
			GRID_WARN("SQLX replication init failure : (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			return;
		}
	}

	/* Configures the network part */
	if (!(server = network_server_init())) {
		GRID_WARN("SERVER init failure : (%d) %s", errno, strerror(errno));
		return;
	}
	if (max_connections)
		network_server_set_maxcnx(server, max_connections);

	dispatcher = transport_gridd_build_empty_dispatcher();
	transport_gridd_dispatcher_add_requests(dispatcher, sqlx_sql_gridd_get_requests(), repository);
	transport_gridd_dispatcher_add_requests(dispatcher, sqlx_repli_gridd_get_requests(), repository);
	grid_daemon_bind_host(server, url->str, dispatcher);

	if (NULL != (err = network_server_open_servers(server))) {
		GRID_WARN("Failed to start some server sockets : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* Start the administrative threads */
	register_thread = g_thread_create(register_worker, url->str, TRUE, &err);
	if (!register_thread) {
		GRID_WARN("Failed to start the REGISTER thread : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	/* SERVER/GRIDD main run loop */
	if (NULL != (err = network_server_run(server))) {
		GRID_WARN("GRIDD run failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}

	GRID_INFO("Normally exiting.");
}

static struct grid_main_callbacks sqlx_callbacks =
{
	.options = sqlx_get_options,
	.action = sqlx_action,
	.set_defaults = sqlx_set_defaults,
	.specific_fini = sqlx_specific_fini,
	.configure = sqlx_configure,
	.usage = sqlx_usage,
	.specific_stop = sqlx_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &sqlx_callbacks);
}


