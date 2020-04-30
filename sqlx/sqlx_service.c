/*
OpenIO SDS sqlx
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/common_variables.h>
#include <server/server_variables.h>
#include <sqliterepo/sqliterepo_variables.h>

#include <cluster/lib/gridcluster.h>
#include <events/oio_events_queue.h>
#include <server/network_server.h>
#include <server/internals.h>
#include <server/transport_gridd.h>
#include <sqliterepo/sqlx_macros.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/election.h>
#include <sqliterepo/synchro.h>
#include <sqliterepo/replication_dispatcher.h>
#include <sqliterepo/gridd_client_pool.h>
#include <sqliterepo/internals.h>
#include <sqliterepo/hash.h>
#include <resolver/hc_resolver.h>

#include <core/oiolb.h>

#include <glib.h>

#include "sqlx_service.h"

// common_main hooks
static struct grid_main_option_s * sqlx_service_get_options(void);
static const char * sqlx_service_usage(void);
static gboolean sqlx_service_configure(int argc, char **argv);
static void sqlx_service_action(void);
static void sqlx_service_set_defaults(void);
static void sqlx_service_specific_fini(void);
static void sqlx_service_specific_stop(void);

// Periodic tasks & thread's workers
static void _task_probe_repository(gpointer p);
static void _task_malloc_trim(gpointer p);
static void _task_expire_bases(gpointer p);
static void _task_expire_resolver(gpointer p);
static void _task_reload_nsinfo(gpointer p);
static void _task_reload_peers(gpointer p);
static GQuark gq_events_health = 0;

static gpointer _worker_timers(gpointer p);
static gpointer _worker_clients(gpointer p);

static const struct gridd_request_descr_s * _get_service_requests (void);

static GError* _reload_lb_world(
		struct oio_lb_world_s *lbw, struct oio_lb_s *lb);

// Static variables
static struct sqlx_service_s SRV = {{0}};
static struct replication_config_s replication_config = {0};
static struct grid_main_callbacks sqlx_service_callbacks =
{
	.options = sqlx_service_get_options,
	.action = sqlx_service_action,
	.set_defaults = sqlx_service_set_defaults,
	.specific_fini = sqlx_service_specific_fini,
	.configure = sqlx_service_configure,
	.usage = sqlx_service_usage,
	.specific_stop = sqlx_service_specific_stop,
};

static struct grid_main_option_s *custom_options = NULL;
static struct grid_main_option_s *all_options = NULL;
static struct grid_main_option_s common_options[] =
{
	{"Endpoint", OT_STRING, {.str = &SRV.url},
		"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
	{"Announce", OT_STRING, {.str = &SRV.announce},
		"Announce this IP:PORT couple instead of the TCP endpoint"},

	{"SysConfig", OT_BOOL, {.b = &SRV.config_system},
		"Load the system configuration and overload the central variables"},
	{"Config", OT_LIST, {.lst = &SRV.config_paths},
		"Load the given file and overload the central variables"},

	{"Replicate", OT_BOOL, {.b = &SRV.flag_replicable},
		"DO NOT USE THIS. This might disable the replication"},

	{"NoXattrLock", OT_BOOL, {.b = &SRV.flag_nolock},
		"Set to TRUE to avoid any xattr operation on the repository root."},

	{"CacheEnabled", OT_BOOL, {.b = &SRV.flag_cached_bases},
		"If set, each base will be cached in a way it won't be accessed"
			" by several requests in the same time."},
	{"DeleteEnabled", OT_BOOL, {.b = &SRV.flag_delete_on},
		"If not set, prevents deleting database files from disk"},

	{"ServiceId", OT_STRING, {.str = &SRV.service_id},
		"Set Service Id of the service"},

	{NULL, 0, {.any=0}, NULL}
};

// repository hooks ------------------------------------------------------------

static const gchar *
_get_url(gpointer ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	struct sqlx_service_s *ptr = ctx;
	return ptr->service_id ?  ptr->service_id->str : ptr->announce->str;
}

static GError*
_get_version(gpointer ctx, const struct sqlx_name_s *n, GTree **result)
{
	EXTRA_ASSERT(ctx != NULL);
	return sqlx_repository_get_version2(PSRV(ctx)->repository, n, result);
}

// sqlite_service configuration steps ------------------------------------------

static gboolean
_configure_with_arguments(struct sqlx_service_s *ss, int argc, char **argv)
{
	// Sanity checks
	if (!ss->url) {
		GRID_WARN("No URL!");
		return FALSE;
	}
	if (!ss->announce) {
		ss->announce = g_string_new(ss->url->str);
		GRID_DEBUG("No announce set, using endpoint [%s]", ss->announce->str);
	}
	if (!metautils_url_valid_for_bind(ss->url->str)) {
		GRID_ERROR("Invalid URL as a endpoint [%s]", ss->url->str);
		return FALSE;
	}
	if (!metautils_url_valid_for_connect(ss->announce->str)) {
		GRID_ERROR("Invalid URL to be announced [%s]", ss->announce->str);
		return FALSE;
	}

	/* Positional argument: NS */

	if (argc < 2) {
		GRID_ERROR("Not enough options, see usage.");
		return FALSE;
	}
	gsize s = g_strlcpy(ss->ns_name, argv[0], sizeof(ss->ns_name));
	if (s >= sizeof(ss->ns_name)) {
		GRID_WARN("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%u)",
				s, (unsigned int)sizeof(ss->ns_name));
		return FALSE;
	}
	GRID_DEBUG("NS configured to [%s]", ss->ns_name);

	/* Positional argument: VOLUME */

	s = g_strlcpy(ss->volume, argv[1], sizeof(ss->volume));
	if (s >= sizeof(ss->volume)) {
		GRID_WARN("Volume name too long (given=%"G_GSIZE_FORMAT" max=%u)",
				s, (unsigned int) sizeof(ss->volume));
		return FALSE;
	}
	GRID_DEBUG("Volume configured to [%s]", ss->volume);

	/* Before loading what remains, first populate the central configuration
	 * facility. This is a pure side effect but the value might have an impact
	 * even on the subsequent structure creations. */
	if (!oio_var_value_with_files(SRV.ns_name, SRV.config_system, SRV.config_paths)) {
		GRID_ERROR("Unknown NS [%s]", SRV.ns_name);
		return FALSE;
	}

	/* Ensure we cache the NS configuration */
	struct oio_cfg_handle_s *ns_conf = oio_cfg_cache_create();
	oio_cfg_set_handle(ns_conf);

	/* Load the ZK url.
	 * We first look for an URL common to all the services, and we will maybe
	 * override it with a value specific for the file. */
	ss->zk_url = oio_cfg_get_value(ss->ns_name, OIO_CFG_ZOOKEEPER);

	do {
		gchar k[sizeof(OIO_CFG_ZOOKEEPER)+2+LIMIT_LENGTH_SRVTYPE];
		g_snprintf(k, sizeof(k), "%s.%s", OIO_CFG_ZOOKEEPER, ss->service_config->srvtype);
		gchar *str = oio_cfg_get_value(ss->ns_name, k);
		if (str)
			GRID_NOTICE("ZK [%s] <- [%s] (at %s)", ss->zk_url, str, k);
		else
			GRID_DEBUG("ZK [%s] (nothing at %s)", ss->zk_url, k);
		if (str) oio_str_reuse(&ss->zk_url, str);
	} while (0);

#define BSTR(B) (BOOL(B) ? "on" : "off")
	GRID_NOTICE("TFO[%d] UDP[%d] OUT[%d]",
			oio_socket_fastopen, oio_udp_allowed, oio_log_outgoing);
	return TRUE;
}

static void
_patch_configuration_maxrss(void)
{
	const gint64 pre = sqliterepo_max_rss;
	if (sqliterepo_max_rss <= 0) {
		struct rlimit rl = {};
		int rc = getrlimit(RLIMIT_DATA, &rl);
		if (rc == 0) {
			gint64 maxrss = rl.rlim_cur;
			if (maxrss <= 0)
				maxrss = G_MAXINT64;
			sqliterepo_max_rss = maxrss;
		}
	}
	if (pre != sqliterepo_max_rss)
		GRID_NOTICE("RSS limit set to %" G_GINT64_FORMAT, sqliterepo_max_rss);
}

static void
_patch_configuration_fd(void)
{
	/* By design, this function never returns less than 1024. */
	const guint maxfd = metautils_syscall_count_maxfd();
	EXTRA_ASSERT(maxfd >= 1024);

	// We keep some FDs for unexpected cases (sqlite sometimes uses
	// temporary files, even when we ask for memory journals) and for
	// internal mechanics (notifications, epoll, etc).
	const guint total = maxfd - 32;

	const guint reserved = sqliterepo_repo_max_bases_hard
		+ server_fd_max_passive + sqliterepo_fd_max_active;

	// The operator already reserved to many connections, and we cannot
	// promise these numbers. we hope he/she is aware of his/her job.
	if (reserved > total) {
		GRID_WARN("Too many descriptors have been reserved (%u), "
				"please reconfigure the service or extend the system limit "
				"(currently set to %u).", reserved, maxfd);
		if (!sqliterepo_repo_max_bases_hard) {
			sqliterepo_repo_max_bases_hard = 1024;
			GRID_WARN("maximum # of bases not set, arbitrarily set to %u",
					sqliterepo_repo_max_bases_hard);
		}
		if (!server_fd_max_passive) {
			server_fd_max_passive = 64;
			GRID_WARN("maximum # of incoming cnx not set, arbitrarily set to %u",
					server_fd_max_passive);
		}
		if (!sqliterepo_fd_max_active) {
			sqliterepo_fd_max_active = 64;
			GRID_WARN("maximum # of outgoing cnx not set, arbitrarily set to %u",
					sqliterepo_fd_max_active);
		}
	} else {
		guint available = total - reserved;
		guint *to_be_set[4] = {NULL, NULL, NULL, NULL};
		guint limits[3] = {G_MAXUINT, G_MAXUINT, G_MAXUINT};
		do {
			guint i = 0;
			/* When automatically set, keep it low to avoid DoS. */
			if (!sqliterepo_fd_max_active) {
				to_be_set[i] = &sqliterepo_fd_max_active;
				limits[i] = (2 * total) / 100;
				i++;
			}
			if (sqliterepo_repo_max_bases_hard <= 0) {
				to_be_set[i] = &sqliterepo_repo_max_bases_hard;
				limits[i] = (48 * total) / 100;
				i++;
			}
			if (!server_fd_max_passive) {
				to_be_set[i] = &server_fd_max_passive;
				limits[i] = (50 * total) / 100;
				i++;
			}
		} while (0);

		// Fan out all the available FD on each slot that has not
		// reached its maximum.
		while (available > 0) {
			gboolean any = FALSE;
			for (guint i = 0; to_be_set[i] && available > 0; i++) {
				if (*to_be_set[i] < limits[i]) {
					(*to_be_set[i]) ++;
					available--;
					any = TRUE;
				}
			}
			if (!any)
				break;
		}
	}

	GRID_INFO("FD limits set to ACTIVES[%u] PASSIVES[%u] BASES[%u/%u] SYS[%u]",
			sqliterepo_fd_max_active, server_fd_max_passive,
			sqliterepo_repo_max_bases_soft, sqliterepo_repo_max_bases_hard,
			maxfd);
}

static gboolean
_patch_and_apply_configuration(void)
{
	_patch_configuration_fd();
	_patch_configuration_maxrss();

	if (SRV.server)
		network_server_reconfigure(SRV.server);
	if (SRV.repository)
		sqlx_cache_reconfigure(sqlx_repository_get_cache(SRV.repository));
	if (SRV.clients_pool)
		gridd_client_pool_reconfigure(SRV.clients_pool);

	return TRUE;
}

static void
_reconfigure_on_SIGHUP(void)
{
	GRID_NOTICE("SIGHUP! Reconfiguring...");
	oio_var_reset_all();
	oio_var_value_with_files(SRV.ns_name, SRV.config_system, SRV.config_paths);
	_patch_and_apply_configuration();
}

static gboolean
_init_configless_structures(struct sqlx_service_s *ss)
{
	if (!(ss->lb_world = oio_lb_local__create_world())
			|| !(ss->lb = oio_lb__create())
			|| !(ss->server = network_server_init())
			|| !(ss->dispatcher = transport_gridd_build_empty_dispatcher())
			|| !(ss->clients_pool = gridd_client_pool_create())
			|| !(ss->resolver = hc_resolver_create(conscience_locate_meta0))
			|| !(ss->gtq_admin = grid_task_queue_create("admin"))
			|| !(ss->gtq_reload = grid_task_queue_create("reload"))) {
		GRID_WARN("SERVICE init error: memory allocation failure");
		return FALSE;
	}

	/* JFS: It was a good idea initially, to turn caching of and avoid
	 * many decache orders to have predictive movers and rebuilders...
	 * But it turns so slow without that cache :/ */
	//oio_var_fix_one("resolver.cache.enabled", "false");

	return TRUE;
}

static gboolean
_configure_peering (struct sqlx_service_s *ss)
{
	ss->peering = sqlx_peering_factory__create_direct(ss->clients_pool);
	return TRUE;
}

static gboolean
_configure_zk_shard(struct sqlx_service_s *ss,
		const char *realprefix, const char *zk_url)
{
	struct sqlx_sync_s *ssync = sqlx_sync_create(zk_url);
	if (!ssync)
		return FALSE;

	g_ptr_array_add(ss->sync_tab, ssync);

	sqlx_sync_set_prefix(ssync, realprefix);

	sqlx_sync_set_hash(ssync,
										 ss->service_config->zk_hash_width,
										 ss->service_config->zk_hash_depth);

	GError *err = sqlx_sync_open(ssync);
	if (err != NULL) {
		GRID_WARN("SYNC init error [%s]: (%d) %s",
							zk_url, err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static gboolean
_configure_zk_shard_muxed(struct sqlx_service_s *ss,
		guint mux_factor, const char *realprefix, const char *zk_url)
{
	if (mux_factor <= 0)
		return FALSE;

	for (guint i=0; i<mux_factor ;++i) {
		if (!_configure_zk_shard(ss, realprefix, zk_url))
			return FALSE;
	}
	return TRUE;
}

static gboolean
_configure_multi_zk(struct sqlx_service_s *ss,
		guint mux_factor, const char *realprefix, const char *zk_url)
{
	if (mux_factor <= 0)
		return FALSE;

	gchar **shards = g_strsplit(zk_url, OIO_CSV_SEP2, -1);
	STRINGV_STACKIFY(shards);
	for (gchar **shard=shards; shards && *shard ;++shard) {
		if (!oio_str_is_set(*shard))
			continue;
		if (!_configure_zk_shard_muxed(ss, mux_factor, realprefix, *shard))
			return FALSE;
	}
	return TRUE;
}

static gboolean
_configure_synchronism(struct sqlx_service_s *ss)
{
	if (!ss->zk_url) {
		GRID_NOTICE("SYNC off (no zookeeper)");
		return TRUE;
	}

	ss->sync_tab = g_ptr_array_new();

	gchar *realprefix = g_strdup_printf("/hc/ns/%s/%s", ss->ns_name,
			ss->service_config->zk_prefix);
	STRING_STACKIFY(realprefix);

	return _configure_multi_zk(ss, sqliterepo_zk_mux_factor,
																	 realprefix, ss->zk_url);
}

static gchar **
filter_services(struct sqlx_service_s *ss, gchar **s, const gchar *type)
{
	gboolean matched = FALSE;
	GPtrArray *tmp = g_ptr_array_new();
	for (; *s ;s++) {
		struct meta1_service_url_s *u = meta1_unpack_url(*s);
		gboolean srvtype_matched;
		gchar *host;
		if (u) {
			srvtype_matched = !strcmp(type, u->srvtype);
			host = u->host;
		} else {
			srvtype_matched = TRUE;
			host = *s;
		}
		if (srvtype_matched) {
			const char *hid = (ss->service_id && ss->service_id->str) ? ss->service_id->str
				: ss->url->str;
			if (!g_ascii_strcasecmp(host, hid)) {
				matched = TRUE;
			} else {
				g_ptr_array_add(tmp, g_strdup(host));
			}
		}
		meta1_service_url_clean(u);
	}

	gchar **out = (gchar**)metautils_gpa_to_array (tmp, TRUE);
	if (matched)
		return out;
	g_strfreev (out);
	return NULL;
}

// TODO: replace `nocache` by flags
static GError *
_get_peers_wrapper(struct sqlx_service_s *ss, const struct sqlx_name_s *name,
		gboolean nocache, gchar ***result)
{
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(result != NULL);

	gchar **peers = NULL;
	GError *err = NULL;

	*result = NULL;

	// Try to read peers from the database
	if (!nocache) {
		err = sqlx_repository_get_peers2(ss->repository, name, &peers);
		if (err) {
			if (err->code != CODE_CONTAINER_NOTFOUND) {
				GRID_INFO("Failed to get_peers() from local database: (%d) %s",
						err->code, err->message);
			}
			g_clear_error(&err);
			EXTRA_ASSERT(peers == NULL);
		}
	}

label_retry:
	// Try to read peers from the upper-level service
	if (!peers || !oio_str_is_set(*peers)) {
		oio_str_cleanv(&peers);
		if (err) g_clear_error(&err);
		err = ss->service_config->get_peers(ss, name, nocache, &peers);
	}

	if (!err) {
		EXTRA_ASSERT(peers != NULL);
		*result = filter_services(ss, peers, name->type);
		oio_str_cleanv(&peers);
		if (!*result) {
			// If cache was enabled, we can retry without cache
			if (!nocache) {
				nocache = TRUE;
				goto label_retry;
			} else {
				err = NEWERROR(CODE_CONTAINER_NOTFOUND, "Base not managed");
			}
		}
	} else {
		EXTRA_ASSERT(peers == NULL);
		if (err->code == CODE_RANGE_NOTFOUND && !nocache) {
			// We may have asked the wrong upper-level service
			// TODO: call hc_decache_reference(ss->resolver, url);
			// and remove the retry loop from meta2
			nocache = TRUE;
			goto label_retry;
		}
	}

	EXTRA_ASSERT((err != NULL) ^ (*result != NULL));
	return err;
}

static gboolean
_configure_replication(struct sqlx_service_s *ss)
{
	GRID_DEBUG("Got zookeeper URL [%s]", ss->zk_url);
	replication_config.mode = (ss->flag_replicable && ss->zk_url != NULL)
		? ELECTION_MODE_QUORUM : ELECTION_MODE_NONE;
	replication_config.ctx = ss;
	replication_config.get_local_url = _get_url;
	replication_config.get_version = _get_version;
	replication_config.get_peers = (GError* (*)(gpointer,
			const struct sqlx_name_s*, gboolean, gchar ***))
			_get_peers_wrapper;

	GError *err = election_manager_create(&replication_config,
			&ss->election_manager);
	if (err != NULL) {
		GRID_WARN("Replication init failure: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	election_manager_dump_delays();
	return TRUE;
}

static gboolean
_configure_backend(struct sqlx_service_s *ss)
{
	struct sqlx_repo_config_s repository_config = {0};
	repository_config.flags = 0;
	repository_config.flags |= ss->flag_delete_on ? SQLX_REPO_DELETEON : 0;
	repository_config.flags |= ss->flag_cached_bases ? 0 : SQLX_REPO_NOCACHE;

	GError *err = sqlx_repository_init(ss->volume, &repository_config,
			&ss->repository);
	if (err) {
		GRID_ERROR("SQLX repository init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	err = sqlx_repository_configure_type(ss->repository,
			ss->service_config->srvtype, ss->service_config->schema);

	if (err) {
		GRID_ERROR("SQLX schema init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	sqlx_repository_configure_hash (ss->repository,
			ss->service_config->repo_hash_width,
			ss->service_config->repo_hash_depth);

	GRID_TRACE("SQLX repository initiated");
	return TRUE;
}

static gboolean
_configure_tasks(struct sqlx_service_s *ss)
{
	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_nsinfo, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_peers, NULL, ss);

	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_bases, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_resolver, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_malloc_trim, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 5, _task_probe_repository, NULL, ss);

	return TRUE;
}

static gboolean
_configure_network(struct sqlx_service_s *ss)
{
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			sqlx_repli_gridd_get_requests(), ss->repository);
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			_get_service_requests(), ss);
	return TRUE;
}

static void
_sqlite3_log(void *udata UNUSED, int err_code, const char *msg)
{
	switch (err_code) {
	case SQLITE_WARNING:
		GRID_WARN("sqlite3: (%d) %s", err_code, msg);
		break;
	default:
		GRID_NOTICE("sqlite3: (%d) %s", err_code, msg);
	}
}

static gboolean
_configure_logging(struct sqlx_service_s *ss UNUSED)
{
	sqlite3_config(SQLITE_CONFIG_LOG, _sqlite3_log, NULL);
	return TRUE;
}

// common_main hooks -----------------------------------------------------------

static void
_action_report_error(GError *err, const gchar *msg)
{
	GRID_ERROR("%s: (%d) %s", msg, !err?0:err->code, !err?"":err->message);
	if (err)
		g_clear_error(&err);
	grid_main_stop();
	return;
}

static void
sqlx_service_action(void)
{
	GError *err = NULL;

	if (oio_client_cache_errors)
		GRID_NOTICE("Faulty peers avoidance: ENABLED");

	if (!SRV.flag_nolock) {
		err = volume_service_lock(SRV.volume, SRV.service_config->srvtype,
				_get_url(&SRV), SRV.ns_name, oio_volume_lock_lazy);
		if (err)
			return _action_report_error(err, "Volume lock failed");
	}

	oio_server_volume = SRV.volume;

	election_manager_set_peering(SRV.election_manager, SRV.peering);
	if (SRV.sync_tab && SRV.sync_tab->len > 0) {
		for (guint i=0; i<SRV.sync_tab->len ;++i)
			election_manager_add_sync(SRV.election_manager, SRV.sync_tab->pdata[i]);
	}
	sqlx_repository_set_elections(SRV.repository, SRV.election_manager);

	grid_task_queue_fire(SRV.gtq_reload);
	grid_task_queue_fire(SRV.gtq_admin);
	GRID_DEBUG("All tasks now fired once");

	/* Start the administrative threads */
	SRV.thread_admin = grid_task_queue_run(SRV.gtq_admin, &err);
	if (!SRV.thread_admin)
		return _action_report_error(err, "Failed to start the ADMIN thread");

	SRV.thread_reload = grid_task_queue_run(SRV.gtq_reload, &err);
	if (!SRV.thread_reload)
		return _action_report_error(err, "Failed to start the RELOAD thread");

	SRV.thread_client = g_thread_try_new("clients", _worker_clients, &SRV, &err);
	if (!SRV.thread_client)
		return _action_report_error(err, "Failed to start the CLIENT thread");


	if (SRV.election_manager) {
		SRV.thread_timers = g_thread_try_new("timers", _worker_timers, &SRV, &err);
		if (!SRV.thread_timers)
			return _action_report_error(err, "Failed to start the TIMER thread");
	}

	/* open all the sockets */
	if (!grid_main_is_running())
		return;
	network_server_allow_udp(SRV.server);
	grid_daemon_bind_host(SRV.server, SRV.url->str, SRV.dispatcher);
	err = network_server_open_servers(SRV.server);
	if (NULL != err)
		return _action_report_error(err, "GRIDD bind failure");
	if (!grid_main_is_running())
		return;

	if (oio_udp_allowed) {
		int fd_udp = network_server_first_udp(SRV.server);
		GRID_DEBUG("UDP socket fd=%d", fd_udp);
		sqlx_peering_direct__set_udp(SRV.peering, fd_udp);
	}

	sqlx_repository_initial_cleanup(SRV.repository);

	/* SERVER/GRIDD main run loop */
	if (NULL != (err = network_server_run(SRV.server, _reconfigure_on_SIGHUP)))
		return _action_report_error(err, "GRIDD run failure");
}

static void
sqlx_service_specific_stop(void)
{
	if (SRV.server)
		network_server_stop(SRV.server);

	if (SRV.gtq_admin)
		grid_task_queue_stop(SRV.gtq_admin);
	if (SRV.gtq_reload)
		grid_task_queue_stop(SRV.gtq_reload);
}

static gboolean
sqlx_service_configure(int argc, char **argv)
{
	const gboolean rc = _init_configless_structures(&SRV)
		&& _configure_with_arguments(&SRV, argc, argv)
		/* NS now known! */
		&& _patch_and_apply_configuration()
		&& _configure_synchronism(&SRV)
		&& _configure_peering(&SRV)
		&& _configure_replication(&SRV)
		&& _configure_backend(&SRV)
		&& _configure_tasks(&SRV)
		&& _configure_network(&SRV)
		&& _configure_logging(&SRV)
		&& (!SRV.service_config->post_config
				|| SRV.service_config->post_config(&SRV));
	_patch_and_apply_configuration();
	return rc;
}

static void
sqlx_service_set_defaults(void)
{
	SRV.config_system = TRUE;
	SRV.flag_replicable = TRUE;
	SRV.flag_delete_on = TRUE;
	SRV.flag_cached_bases = TRUE;

	SRV.service_id = NULL;

	if (SRV.service_config->set_defaults)
		SRV.service_config->set_defaults(&SRV);

	gq_events_health = g_quark_from_static_string("gauge event.health");
}

static void
sqlx_service_specific_fini(void)
{
	// soft stop
	if (SRV.gtq_reload)
		grid_task_queue_stop(SRV.gtq_reload);
	if (SRV.gtq_admin)
		grid_task_queue_stop(SRV.gtq_admin);

	if (SRV.server) {
		network_server_close_servers(SRV.server);
	}

	if (SRV.thread_reload)
		g_thread_join(SRV.thread_reload);
	if (SRV.thread_admin)
		g_thread_join(SRV.thread_admin);
	if (SRV.thread_client)
		g_thread_join(SRV.thread_client);
	if (SRV.thread_timers)
		g_thread_join(SRV.thread_timers);

	if (SRV.repository) {
		sqlx_repository_stop(SRV.repository);
		struct sqlx_cache_s *cache = sqlx_repository_get_cache(SRV.repository);
		if (cache)
			sqlx_cache_expire(cache, G_MAXUINT, 0);
	}
	if (election_manager_is_operational(SRV.election_manager))
		election_manager_exit_all(SRV.election_manager,
				sqliterepo_server_exit_ttl);
	if (SRV.sync_tab) {
		for (guint i=0; i<SRV.sync_tab->len ;++i)
			sqlx_sync_close(SRV.sync_tab->pdata[i]);
	}
	if (SRV.peering)
		sqlx_peering__destroy(SRV.peering);

	// Stop the server AFTER cleaning all elections
	if (SRV.server)
		network_server_stop(SRV.server);

	// Cleanup
	if (SRV.gtq_admin) {
		grid_task_queue_destroy(SRV.gtq_admin);
		SRV.gtq_admin = NULL;
	}
	if (SRV.gtq_reload) {
		grid_task_queue_destroy(SRV.gtq_reload);
		SRV.gtq_reload = NULL;
	}

	if (SRV.server) {
		network_server_clean(SRV.server);
		SRV.server = NULL;
	}
	if (SRV.dispatcher) {
		gridd_request_dispatcher_clean(SRV.dispatcher);
		SRV.dispatcher = NULL;
	}
	if (SRV.repository) {
		sqlx_repository_clean(SRV.repository);
		SRV.repository = NULL;
	}
	if (SRV.resolver) {
		hc_resolver_destroy(SRV.resolver);
		SRV.resolver = NULL;
	}

	if (SRV.announce) {
		g_string_free(SRV.announce, TRUE);
		SRV.announce = NULL;
	}
	if (SRV.url) {
		g_string_free(SRV.url, TRUE);
		SRV.url = NULL;
	}
	if (SRV.zk_url)
		oio_str_clean(&SRV.zk_url);

	if (SRV.clients_pool) {
		gridd_client_pool_destroy (SRV.clients_pool);
		SRV.clients_pool = NULL;
	}

	// Must be freed after SRV.clients_pool
	if (SRV.election_manager) {
		election_manager_clean(SRV.election_manager);
		SRV.election_manager = NULL;
	}
	if (SRV.sync_tab) {
		for (guint i=0; i<SRV.sync_tab->len ;++i)
			sqlx_sync_clear(SRV.sync_tab->pdata[i]);
		g_ptr_array_free(SRV.sync_tab, TRUE);
		SRV.sync_tab = NULL;
	}

	if (SRV.lb)
		oio_lb__clear(&SRV.lb);

	if (SRV.lb_world) {
		oio_lb_world__destroy(SRV.lb_world);
		SRV.lb_world = NULL;
	}

	if (SRV.nsinfo) {
		namespace_info_free(SRV.nsinfo);
		SRV.nsinfo = NULL;
	}
	if (all_options) {
		g_free (all_options);
		all_options = NULL;
	}

	oio_cfg_set_handle(NULL);
}

static guint
_count_options (struct grid_main_option_s const * tab)
{
	guint count = 0;
	if (tab)
		for (; tab->name; ++tab, ++count)
			;
	return count;
}

static struct grid_main_option_s *
sqlx_service_get_options(void)
{
	if (!all_options) {
		const guint count_common = _count_options (common_options);
		const guint count_custom = _count_options (custom_options);
		const guint count_total = count_custom + count_common;
		all_options = g_malloc0 (
				(1+count_total) * sizeof(struct grid_main_option_s));
		if (count_common)
			memcpy (all_options, common_options,
					count_common * sizeof(struct grid_main_option_s));
		if (count_custom)
			memcpy (all_options + count_common, custom_options,
					count_custom * sizeof(struct grid_main_option_s));
	}
	return all_options;
}

static const char *
sqlx_service_usage(void)
{
	return "NS VOLUME";
}

int
sqlite_service_main(int argc, char **argv,
		const struct sqlx_service_config_s *cfg)
{
	SRV.replication_config = &replication_config;
	SRV.service_config = cfg;
	int rc = grid_main(argc, argv, &sqlx_service_callbacks);
	return rc;
}

/* Tasks -------------------------------------------------------------------- */

static gpointer
_worker_timers(gpointer p)
{
	metautils_ignore_signals();

	struct election_manager_s *M = PSRV(p)->election_manager;
	if (!election_manager_configured(M))
		return p;

	while (grid_main_is_running()) {
		/* A little bias avoids looping too often */
		const gint64 bias = G_TIME_SPAN_MILLISECOND;
		election_manager_play_timers(M, oio_ext_monotonic_time() + bias);
		election_manager_play_expirations(M, oio_ext_monotonic_time() + bias);

		/* wait for the next timer */
		const gint64 now = oio_ext_monotonic_time();
		gint64 next = election_manager_next_timer(M);
		if (next <= 0)
			next = now + 500 * G_TIME_SPAN_MILLISECOND;
		else if (now > next)
			next = now + 10 * G_TIME_SPAN_MILLISECOND;
		else if (next - now > G_TIME_SPAN_SECOND)
			next = now + 500 * G_TIME_SPAN_MILLISECOND;
		g_usleep(next - now);
	}

	return p;
}

static gpointer
_worker_clients(gpointer p)
{
	metautils_ignore_signals();
	while (grid_main_is_running()) {
		GError *err = gridd_client_pool_round(PSRV(p)->clients_pool, 1);
		if (err != NULL) {
			GRID_ERROR("Clients error : (%d) %s", err->code, err->message);
			g_clear_error(&err);
			grid_main_stop();
		}
	}
	return p;
}

#define HEXA "0123456789ABCDEF"

static void
_task_probe_repository(gpointer p)
{
	struct sqlx_service_s *ss = PSRV(p);
	int rc, errsav;
	GError *err = NULL;
	gchar path[PATH_MAX], subdir[16], filename[16];

	oio_str_randomize(subdir, sizeof(subdir), HEXA);
	oio_str_randomize(filename, sizeof(filename), HEXA);

	/* Try a directory creation */
	g_strlcpy(path, ss->volume, sizeof(path));
	g_strlcat(path, "/probe-", sizeof(path));
	g_strlcat(path, subdir, sizeof(path));
	GRID_DEBUG("Probing directory %s", path);
	rc = g_mkdir(path, 0755);
	errsav = errno;
	(void) g_rmdir(path);
	if (rc != 0) {
		gchar *msg = g_strdup_printf("IO error on %s %s: (%d) %s",
				ss->service_id->str, path, errsav, strerror(errsav));
		GRID_WARN("%s", msg);
		grid_daemon_notify_io_status(ss->dispatcher, FALSE, msg);
		g_free(msg);
		return;
	}

	/* Try a file creation */
	g_strlcpy(path, ss->volume, sizeof(path));
	g_strlcat(path, "/probe-", sizeof(path));
	g_strlcat(path, filename, sizeof(path));
	GRID_DEBUG("Probing file %s", path);
	rc = g_file_set_contents(path, "", 0, &err);
	(void) g_unlink(path);
	if (!rc) {
		gchar *msg = g_strdup_printf("IO error on %s %s: (%d) %s",
				ss->service_id->str, path, err->code, err->message);
		GRID_WARN("%s", msg);
		g_clear_error(&err);
		grid_daemon_notify_io_status(ss->dispatcher, FALSE, msg);
		return;
	}

	grid_daemon_notify_io_status(ss->dispatcher, TRUE, NULL);
}

static void
_task_malloc_trim(gpointer p UNUSED)
{
	VARIABLE_PERIOD_DECLARE();
	if (VARIABLE_PERIOD_SKIP(sqlx_periodic_malloctrim_period))
		return;

	malloc_trim (sqlx_periodic_malloctrim_size);
}

static void
_task_expire_bases(gpointer p)
{
	if (!grid_main_is_running ())
		return;

	struct sqlx_cache_s *cache = sqlx_repository_get_cache(PSRV(p)->repository);
	if (cache != NULL) {

		VARIABLE_PERIOD_DECLARE();
		if (VARIABLE_PERIOD_SKIP(sqlx_periodic_decache_period))
			return;

		guint count = sqlx_cache_expire(cache,
				sqlx_periodic_decache_max_bases, sqlx_periodic_decache_max_delay);
		if (count)
			GRID_DEBUG("Expired %u bases", count);
	}
}

static void
_task_expire_resolver(gpointer p)
{
	if (!grid_main_is_running ())
		return;

	guint nb_expire = hc_resolver_expire(PSRV(p)->resolver);
	guint nb_purge = hc_resolver_purge (PSRV(p)->resolver);
	if (nb_expire || nb_purge) {
		GRID_DEBUG("Resolver: expired %u, purged %u", nb_expire, nb_purge);
	}
}

static void
_task_reload_nsinfo(gpointer p)
{
	if (!grid_main_is_running ())
		return;

	struct namespace_info_s *ni = NULL, *old = NULL;
	GError *err = conscience_get_namespace(PSRV(p)->ns_name, &ni);
	EXTRA_ASSERT ((err != NULL) ^ (ni != NULL));

	if (err) {
		GRID_WARN("NSINFO reload error [%s]: (%d) %s",
				PSRV(p)->ns_name, err->code, err->message);
		g_clear_error(&err);
	} else {
		old = PSRV(p)->nsinfo;
		PSRV(p)->nsinfo = ni;
		namespace_info_free(old);
	}
}

static gboolean
_srv_is_down(struct service_info_s *si)
{
	EXTRA_ASSERT(si != NULL);

	if (!si->tags)
		return FALSE;

	struct service_tag_s *tag =
		service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_UP);
	if (!tag)
		return FALSE;

	gboolean up = TRUE;
	service_tag_get_value_boolean(tag, &up, NULL);
	return !up;
}

static gchar *
_srv_url (struct service_info_s *si)
{
	EXTRA_ASSERT(si != NULL);
	gchar tmp[STRLEN_ADDRINFO];
	grid_addrinfo_to_string(&si->addr, tmp, sizeof(tmp));
	return g_strdup(tmp);
}

static gchar **
_filter_down_hosts(GSList *l)
{
	GPtrArray *tmp = g_ptr_array_new();
	for (; l ;l=l->next) {
		if (_srv_is_down(l->data))
			g_ptr_array_add(tmp, _srv_url(l->data));
	}
	g_ptr_array_add(tmp, NULL);
	return (gchar**) g_ptr_array_free(tmp, FALSE);
}

static void
_task_reload_peers(gpointer p)
{
	VARIABLE_PERIOD_DECLARE();

	if (!grid_main_is_running ())
		return;

	const char * nsname = PSRV(p)->ns_name;
	const char * srvtype = PSRV(p)->service_config->srvtype;
	GSList *allsrv = NULL;
	GError *err = conscience_get_services(nsname, srvtype, FALSE, &allsrv, 0);
	if (err) {
		GRID_WARN("Failed to reload the list of [%s/%s]: (%d) %s",
				nsname, srvtype, err->code, err->message);
		g_clear_error(&err);
	} else {
		gchar **down = _filter_down_hosts(allsrv);
		gridd_client_learn_peers_down((const char * const *)down);
		if (down && *down) {
			const gsize len = g_strv_length(down);
			if (VARIABLE_PERIOD_SKIP(180)) {
				GRID_DEBUG("Loaded %" G_GSIZE_FORMAT " down %s", len, srvtype);
			} else {
				/* once per 15 minutes */
				GRID_NOTICE("Loaded %" G_GSIZE_FORMAT " down %s", len, srvtype);
			}
		}
		g_strfreev(down);
	}

	g_slist_free_full(allsrv, (GDestroyNotify)service_info_clean);
}

static void
_reload_lb_service_types(struct oio_lb_world_s *lbw, struct oio_lb_s *lb,
		gchar **srvtypes, GPtrArray *tabsrv, GPtrArray *taberr)
{
	struct service_update_policies_s *pols = service_update_policies_create();
	gchar *pols_cfg = oio_var_get_string(oio_ns_service_update_policy);
	service_update_reconfigure(pols, pols_cfg);
	g_free(pols_cfg);

	for (guint i=0; srvtypes[i] ;++i) {
		const char * srvtype = srvtypes[i];
		if (!oio_lb__has_pool(lb, srvtype)) {
			GRID_DEBUG("Creating pool for service type [%s]", srvtype);
			oio_lb__force_pool(lb,
					oio_lb_pool__from_service_policy( lbw, srvtype, pols));
		}

		if (!taberr->pdata[i])
			oio_lb_world__feed_service_info_list(lbw, tabsrv->pdata[i]);
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

static GError*
_reload_lb_world(struct oio_lb_world_s *lbw, struct oio_lb_s *lb)
{
	gchar **srvtypes = NULL;
	GPtrArray *tabsrv = NULL, *taberr = NULL;
	gboolean any_loading_error = FALSE;

	/* Load the list of service types */
	if (SRV.srvtypes[0] && SRV.srvtypes[0] != '!') {
		srvtypes = g_strsplit(SRV.srvtypes, ",", -1);
	} else {
		GSList *list_srvtypes = NULL;
		GError *err = conscience_get_types(SRV.ns_name, &list_srvtypes);
		if (err) {
			g_prefix_error(&err, "LB pool reload error: ");
			return err;
		}
		if (!SRV.srvtypes[0])
			srvtypes = (gchar**) metautils_list_to_array(list_srvtypes);
		else {
			/* the application gives an exclusion list */
			EXTRA_ASSERT(SRV.srvtypes[0] == '!');
			srvtypes = g_malloc0(sizeof(void*) *
					(1 + g_slist_length(list_srvtypes)));
			guint i = 0;
			for (GSList *l=list_srvtypes; l ;l=l->next) {
				const char * srvtype = l->data;
				if (!g_strstr_len(SRV.srvtypes+1, -1, srvtype)) {
					/* service type not excluded */
					srvtypes[i++] = l->data;
				} else {
					g_free(l->data);
				}
			}
		}
		g_slist_free(list_srvtypes);
	}

	EXTRA_ASSERT(srvtypes != NULL);
	if (!*srvtypes) {
		g_strfreev(srvtypes);
		return NULL;
	}

	/* Now preload all the service of these types */
	tabsrv = g_ptr_array_new_full(8, _free_list_of_services);
	taberr = g_ptr_array_new_full(8, _free_error);
	for (char **pst=srvtypes; *pst ;++pst) {
		const char * srvtype = *pst;
		GSList *srv = NULL;
		GError *e = conscience_get_services(SRV.ns_name, srvtype, FALSE, &srv, 0);
		if (e) {
			GRID_WARN("Failed to load the list of [%s] in NS=%s", srvtype, SRV.ns_name);
			any_loading_error = TRUE;
		}
		g_ptr_array_add(tabsrv, srv);
		g_ptr_array_add(taberr, e);
	}

	/* Now refresh the service pools. We don't trigger any purge if we
	 * encountered any error while loading the list of services, because
	 * the world exposes a global generation number to manage expirations,
	 * and because without service, we have no way (yet) to find *all* the
	 * slots concerned by any service of a given type. */
	if (*srvtypes) {
		if (!any_loading_error)
			oio_lb_world__increment_generation(lbw);
		oio_lb_world__reload_pools(lbw, lb, SRV.nsinfo);
		_reload_lb_service_types(lbw, lb, srvtypes, tabsrv, taberr);
		oio_lb_world__reload_storage_policies(lbw, lb, SRV.nsinfo);
		if (!any_loading_error) {
			oio_lb_world__purge_old_generations(lbw);
		} else {
			oio_lb_world__rehash_all_slots(lbw);
		}
	}

	if (taberr) g_ptr_array_free(taberr, TRUE);
	if (tabsrv) g_ptr_array_free(tabsrv, TRUE);
	g_strfreev(srvtypes);
	return NULL;
}

void
sqlx_task_reload_lb (struct sqlx_service_s *ss)
{
	EXTRA_ASSERT(ss != NULL);
	ADAPTIVE_PERIOD_DECLARE();

	if (!grid_main_is_running ())
		return;  /* stopped */
	if (!SRV.nsinfo || !SRV.nsinfo)
		return;  /* not ready */
	if (ADAPTIVE_PERIOD_SKIP())
		return;

	GError *err = _reload_lb_world(ss->lb_world, ss->lb);
	if (err) {
		GRID_WARN("Failed to reload LB world: %s", err->message);
		g_clear_error(&err);
	} else {
		ADAPTIVE_PERIOD_ONSUCCESS(oio_sqlx_lb_refresh_period);
	}
}

/* Specific requests handlers ----------------------------------------------- */

static gboolean
_dispatch_RELOAD (struct gridd_reply_ctx_s *reply, gpointer pss, gpointer i)
{
	(void) i;
	struct sqlx_service_s *ss = pss;
	g_assert (ss != NULL);

	oio_lb_world__flush(ss->lb_world);

	GError *err = _reload_lb_world(ss->lb_world, ss->lb);
	if (err)
		reply->send_error (0, err);
	else
		reply->send_reply (200, "OK");
	return TRUE;
}

static gboolean
_dispatch_FLUSH (struct gridd_reply_ctx_s *reply, gpointer pss, gpointer i)
{
	(void) i;
	struct sqlx_service_s *ss = pss;
	g_assert(ss != NULL);
	if (ss->resolver) {
		hc_resolver_flush_csm0 (ss->resolver);
		hc_resolver_flush_services (ss->resolver);
	}
	reply->send_reply(200, "OK");
	return TRUE;
}

static const struct gridd_request_descr_s *
_get_service_requests (void)
{
	static struct gridd_request_descr_s descriptions[] = {
		{NAME_MSGNAME_SQLX_RELOAD, _dispatch_RELOAD, NULL},
		{NAME_MSGNAME_SQLX_FLUSH,  _dispatch_FLUSH,  NULL},
		{NULL, NULL, NULL}
	};

	return descriptions;
}

