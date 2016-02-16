/*
OpenIO SDS sqlx
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

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/stats_holder.h>
#include <server/internals.h>
#include <server/transport_gridd.h>
#include <sqliterepo/sqlx_macros.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/election.h>
#include <sqliterepo/synchro.h>
#include <sqliterepo/replication_dispatcher.h>
#include <resolver/hc_resolver.h>

#include <glib.h>

#include "sqlx_service.h"
#include "oio_events_queue.h"

// common_main hooks
static struct grid_main_option_s * sqlx_service_get_options(void);
static const char * sqlx_service_usage(void);
static gboolean sqlx_service_configure(int argc, char **argv);
static void sqlx_service_action(void);
static void sqlx_service_set_defaults(void);
static void sqlx_service_specific_fini(void);
static void sqlx_service_specific_stop(void);

// Periodic tasks & thread's workers
static void _task_malloc_trim(gpointer p);
static void _task_expire_bases(gpointer p);
static void _task_expire_resolver(gpointer p);
static void _task_retry_elections(gpointer p);
static void _task_reload_nsinfo(gpointer p);
static void _task_reload_workers(gpointer p);

static gpointer _worker_queue (gpointer p);
static gpointer _worker_clients (gpointer p);

static const struct gridd_request_descr_s * _get_service_requests (void);

static GError* _reload_lbpool(struct grid_lbpool_s *glp, gboolean flush);

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

	{"Replicate", OT_BOOL, {.b = &SRV.flag_replicable},
		"DO NOT USE THIS. This might disable the replication"},

	{"Sqlx.Sync.Repli", OT_UINT, {.u = &SRV.sync_mode_repli},
		"SYNC mode to be applied on replicated bases after open "
			"(0=NONE,1=NORMAL,2=FULL)"},
	{"Sqlx.Sync.Solo", OT_UINT, {.u = &SRV.sync_mode_solo},
		"SYNC mode to be applied on non-replicated bases after open "
			"(0=NONE,1=NORMAL,2=FULL)"},

	{"OpenTimeout", OT_INT64, {.i64=&SRV.open_timeout},
		"Timeout when opening bases in use by another thread "
			"(milliseconds). -1 means wait forever, 0 return "
			"immediately." },
	{"CnxBacklog", OT_INT64, {.i64=&SRV.cnx_backlog},
		"Number of connections allowed when all workers are busy"},

	{"MaxBases", OT_UINT, {.u = &SRV.cfg_max_bases},
		"Limits the number of concurrent open bases" },
	{"MaxPassive", OT_UINT, {.u = &SRV.cfg_max_passive},
		"Limits the number of concurrent passive connections" },
	{"MaxActive", OT_UINT, {.u = &SRV.cfg_max_active},
		"Limits the number of concurrent active connections" },
	{"MaxWorkers", OT_UINT, {.u=&SRV.cfg_max_workers},
		"Limits the number of worker threads" },

	{"CacheEnabled", OT_BOOL, {.b = &SRV.flag_cached_bases},
		"If set, each base will be cached in a way it won't be accessed"
			" by several requests in the same time."},
	{"DeleteEnabled", OT_BOOL, {.b = &SRV.flag_delete_on},
		"If not set, prevents deleting database files from disk"},

	{NULL, 0, {.i=0}, NULL}
};

// repository hooks ------------------------------------------------------------

static const gchar *
_get_url(gpointer ctx)
{
	EXTRA_ASSERT(ctx != NULL);
	return PSRV(ctx)->announce->str;
}

static GError*
_get_version(gpointer ctx, struct sqlx_name_s *n, GTree **result)
{
	EXTRA_ASSERT(ctx != NULL);
	return sqlx_repository_get_version2(PSRV(ctx)->repository, n, result);
}

// sqlite_service configuration steps ------------------------------------------

static gboolean
_configure_with_arguments(struct sqlx_service_s *ss, int argc, char **argv)
{
	// Sanity checks
	if (ss->sync_mode_solo > SQLX_SYNC_FULL) {
		GRID_WARN("Invalid SYNC mode for not-replicated bases");
		return FALSE;
	}
	if (ss->sync_mode_repli > SQLX_SYNC_FULL) {
		GRID_WARN("Invalid SYNC mode for replicated bases");
		return FALSE;
	}
	if (!ss->url) {
		GRID_WARN("No URL!");
		return FALSE;
	}
	if (!ss->announce) {
		ss->announce = g_string_new(ss->url->str);
		GRID_NOTICE("No announce set, using endpoint [%s]", ss->announce->str);
	}
	if (!metautils_url_valid_for_bind(ss->url->str)) {
		GRID_ERROR("Invalid URL as a endpoint [%s]", ss->url->str);
		return FALSE;
	}
	if (!metautils_url_valid_for_connect(ss->announce->str)) {
		GRID_ERROR("Invalid URL to be announced [%s]", ss->announce->str);
		return FALSE;
	}
	if (argc < 2) {
		GRID_ERROR("Not enough options, see usage.");
		return FALSE;
	}

	// Positional arguments
	gsize s = g_strlcpy(ss->ns_name, argv[0], sizeof(ss->ns_name));
	if (s >= sizeof(ss->ns_name)) {
		GRID_WARN("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%u)",
				s, (unsigned int)sizeof(ss->ns_name));
		return FALSE;
	}
	GRID_NOTICE("NS configured to [%s]", ss->ns_name);

	ss->lb = grid_lbpool_create (ss->ns_name);
	if (!ss->lb) {
		GRID_WARN("LB allocation failure");
		return FALSE;
	}
	GRID_NOTICE("LB allocated");

	s = g_strlcpy(ss->volume, argv[1], sizeof(ss->volume));
	if (s >= sizeof(ss->volume)) {
		GRID_WARN("Volume name too long (given=%"G_GSIZE_FORMAT" max=%u)",
				s, (unsigned int) sizeof(ss->volume));
		return FALSE;
	}
	GRID_NOTICE("Volume configured to [%s]", ss->volume);

	ss->zk_url = gridcluster_get_zookeeper(ss->ns_name);
	if (!ss->zk_url) {
		GRID_INFO("No replication : no ZooKeeper URL configured");
		return TRUE;
	}

	return TRUE;
}

static gboolean
_configure_limits(struct sqlx_service_s *ss)
{
#define CONFIGURE_LIMIT(cfg,real) do { \
	real = (cfg > 0 && cfg < real) ? cfg : (limit.rlim_cur - 20) / 3; \
} while (0)
	struct rlimit limit = {0,0};

	if (0 != getrlimit(RLIMIT_NOFILE, &limit)) {
		GRID_ERROR("Max file descriptor unknown : getrlimit error "
				"(errno=%d) %s", errno, strerror(errno));
		return FALSE;
	}
	if (limit.rlim_cur < 64) {
		GRID_ERROR("Not enough file descriptors allowed [%lu], "
				"minimum 64 required", (unsigned long) limit.rlim_cur);
		return FALSE;
	}

	GRID_INFO("Limits set to ACTIVES[%u] PASSIVES[%u] BASES[%u]",
			SRV.max_active, SRV.max_passive, SRV.max_bases);

	CONFIGURE_LIMIT(ss->cfg_max_passive, ss->max_passive);
	CONFIGURE_LIMIT(ss->cfg_max_active, ss->max_active);
	CONFIGURE_LIMIT(ss->cfg_max_bases, ss->max_bases);

	return TRUE;
#undef CONFIGURE_LIMIT
}

static gboolean
_init_configless_structures(struct sqlx_service_s *ss)
{
	if (!(ss->server = network_server_init())
			|| !(ss->dispatcher = transport_gridd_build_empty_dispatcher())
			|| !(ss->clients_pool = gridd_client_pool_create())
			|| !(ss->resolver = hc_resolver_create1(oio_ext_monotonic_time() / G_TIME_SPAN_SECOND))
			|| !(ss->gtq_admin = grid_task_queue_create("admin"))
			|| !(ss->gtq_reload = grid_task_queue_create("reload"))) {
		GRID_WARN("SERVICE init error : memory allocation failure");
		return FALSE;
	}

	return TRUE;
}

static gboolean
_configure_synchronism(struct sqlx_service_s *ss)
{
	if (!ss->zk_url) {
		GRID_NOTICE("SYNC off (no ZK)");
		return TRUE;
	}

	ss->sync = sqlx_sync_create(ss->zk_url);
	if (!ss->sync)
		return FALSE;

	gchar *realprefix = g_strdup_printf("/hc/ns/%s/%s", SRV.ns_name,
			ss->service_config->zk_prefix);
	sqlx_sync_set_prefix(ss->sync, realprefix);
	g_free(realprefix);

	sqlx_sync_set_hash(ss->sync, ss->service_config->zk_hash_width,
			ss->service_config->zk_hash_depth);

	GError *err = sqlx_sync_open(ss->sync);
	if (err != NULL) {
		GRID_WARN("SYNC init error : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static gboolean
_configure_replication(struct sqlx_service_s *ss)
{
	GRID_INFO("Got zookeeper URL [%s]", ss->zk_url);
	replication_config.mode = (ss->flag_replicable && ss->zk_url != NULL)
		? ELECTION_MODE_QUORUM : ELECTION_MODE_NONE;
	replication_config.ctx = ss;
	replication_config.get_local_url = _get_url;
	replication_config.get_version = _get_version;
	replication_config.get_peers = (GError* (*)(gpointer, struct sqlx_name_s*,
				gboolean nocache, gchar ***)) ss->service_config->get_peers;

	GError *err = election_manager_create(&replication_config,
			&ss->election_manager);
	if (err != NULL) {
		GRID_WARN("Replication init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static gboolean
_configure_backend(struct sqlx_service_s *ss)
{
	struct sqlx_repo_config_s repository_config = {0};
	repository_config.flags = 0;
	repository_config.flags |= ss->flag_delete_on ? SQLX_REPO_DELETEON : 0;
	repository_config.flags |= ss->flag_cached_bases ? 0 : SQLX_REPO_NOCACHE;
	repository_config.flags |= ss->flag_autocreate ? SQLX_REPO_AUTOCREATE : 0;
	repository_config.sync_solo = ss->sync_mode_solo;
	repository_config.sync_repli = ss->sync_mode_repli;

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

	sqlx_repository_configure_open_timeout (ss->repository,
			ss->open_timeout * G_TIME_SPAN_MILLISECOND);

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
	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_workers, NULL, ss);

	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_bases, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_resolver, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_retry_elections, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 3600, _task_malloc_trim, NULL, ss);

	return TRUE;
}

static gboolean
_configure_events_queue (struct sqlx_service_s *ss)
{
	gchar *url =  gridcluster_get_eventagent (SRV.ns_name);
	STRING_STACKIFY (url);

	if (!url) {
		GRID_DEBUG("Events queue disabled, no URL configured");
		return TRUE;
	}

	ss->events_queue = oio_events_queue_factory__create_agent (url, OIO_EVTQ_MAXPENDING);
	if (!ss->events_queue) {
		GRID_WARN("Events queue creation failure");
		return FALSE;
	}

	GRID_INFO("Event queue ready, connected to [%s]", url);
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

// common_main hooks -----------------------------------------------------------

static void
_action_report_error(GError *err, const gchar *msg)
{
	GRID_ERROR("%s : (%d) %s", msg, !err?0:err->code, !err?"":err->message);
	if (err)
		g_clear_error(&err);
	grid_main_stop();
	return;
}

static void
sqlx_service_action(void)
{
	GError *err = NULL;

	if (!SRV.flag_nolock) {
		err = volume_service_lock (SRV.volume, SRV.service_config->srvtype,
				SRV.announce->str, SRV.ns_name);
		if (err)
			return _action_report_error(err, "Volume lock failed");
	}

	gridd_client_pool_set_max(SRV.clients_pool, SRV.max_active);
	network_server_set_maxcnx(SRV.server, SRV.max_passive);
	network_server_set_cnx_backlog(SRV.server, SRV.cnx_backlog);
	sqlx_repository_configure_maxbases(SRV.repository, SRV.max_bases);

	election_manager_set_clients(SRV.election_manager, SRV.clients_pool);
	if (SRV.sync)
		election_manager_set_sync(SRV.election_manager, SRV.sync);
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

	if (SRV.events_queue) {
		SRV.thread_queue = g_thread_try_new("queue", _worker_queue, &SRV, &err);
		if (!SRV.thread_queue)
			return _action_report_error(err, "Failed to start the QUEUE thread");
	}

	/* SERVER/GRIDD main run loop */
	if (!grid_main_is_running())
		return;
	grid_daemon_bind_host(SRV.server, SRV.url->str, SRV.dispatcher);
	err = network_server_open_servers(SRV.server);
	if (NULL != err)
		return _action_report_error(err, "GRIDD bind failure");
	if (!grid_main_is_running())
		return;
	if (NULL != (err = network_server_run(SRV.server)))
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
	return _configure_limits(&SRV)
	    && _init_configless_structures(&SRV)
	    && _configure_with_arguments(&SRV, argc, argv)
		&& _configure_synchronism(&SRV)
	    && _configure_replication(&SRV)
	    && _configure_backend(&SRV)
	    && _configure_tasks(&SRV)
	    && _configure_network(&SRV)
	    && _configure_events_queue(&SRV)
		&& (!SRV.service_config->post_config
				|| SRV.service_config->post_config(&SRV));
}

static void
sqlx_service_set_defaults(void)
{
	SRV.open_timeout = DEFAULT_CACHE_OPEN_TIMEOUT / G_TIME_SPAN_MILLISECOND;
	SRV.cnx_backlog = 50;

	SRV.cfg_max_bases = 0;
	SRV.cfg_max_passive = 0;
	SRV.cfg_max_active = 0;
	SRV.cfg_max_workers = 200;
	SRV.flag_replicable = TRUE;
	SRV.flag_autocreate = TRUE;
	SRV.flag_delete_on = TRUE;
	SRV.flag_cached_bases = TRUE;

	SRV.sync_mode_solo = 1;
	SRV.sync_mode_repli = 1;

	if (SRV.service_config->set_defaults)
		SRV.service_config->set_defaults(&SRV);
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
		network_server_stop(SRV.server);
	}

	if (SRV.thread_reload)
		g_thread_join(SRV.thread_reload);
	if (SRV.thread_admin)
		g_thread_join(SRV.thread_admin);
	if (SRV.thread_client)
		g_thread_join(SRV.thread_client);
	if (SRV.thread_queue)
		g_thread_join(SRV.thread_queue);

	if (SRV.repository) {
		sqlx_repository_stop(SRV.repository);
		struct sqlx_cache_s *cache = sqlx_repository_get_cache(SRV.repository);
		if (cache)
			sqlx_cache_expire(cache, G_MAXUINT, 0);
	}
	if (SRV.election_manager)
		election_manager_exit_all(SRV.election_manager, 0, TRUE);
	if (SRV.sync)
		sqlx_sync_close(SRV.sync);

	// Cleanup
	if (SRV.gtq_admin)
		grid_task_queue_destroy(SRV.gtq_admin);
	if (SRV.gtq_reload)
		grid_task_queue_destroy(SRV.gtq_reload);

	if (SRV.server)
		network_server_clean(SRV.server);
	if (SRV.dispatcher)
		gridd_request_dispatcher_clean(SRV.dispatcher);
	if (SRV.repository)
		sqlx_repository_clean(SRV.repository);
	if (SRV.election_manager)
		election_manager_clean(SRV.election_manager);
	if (SRV.sync)
		sqlx_sync_clear(SRV.sync);
	if (SRV.resolver)
		hc_resolver_destroy(SRV.resolver);

	if (SRV.announce)
		g_string_free(SRV.announce, TRUE);
	if (SRV.url)
		g_string_free(SRV.url, TRUE);
	if (SRV.zk_url)
		oio_str_clean(&SRV.zk_url);

	if (SRV.clients_pool)
		gridd_client_pool_destroy (SRV.clients_pool);

	if (SRV.lb)
		grid_lbpool_destroy (SRV.lb);

	if (SRV.events_queue)
		oio_events_queue__destroy (SRV.events_queue);

	if (SRV.nsinfo)
		namespace_info_free(SRV.nsinfo);
	if (all_options) {
		g_free (all_options);
		all_options = NULL;
	}
}

static guint
_count_options (struct grid_main_option_s const * tab)
{
	guint count = 0;
	for (; tab && tab->name ;++tab,++count) {}
	return count;
}

void
sqlx_service_set_custom_options (struct grid_main_option_s *tab)
{
	custom_options = tab;
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
_worker_queue (gpointer p)
{
	struct sqlx_service_s *ss = PSRV(p);
	if (ss && ss->events_queue)
		oio_events_queue__run_agent (ss->events_queue, grid_main_is_running);
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

static void
_task_malloc_trim(gpointer p)
{
	(void) p;
	malloc_trim (PERIODIC_MALLOC_TRIM_SIZE);
}

static void
_task_expire_bases(gpointer p)
{
	struct sqlx_cache_s *cache = sqlx_repository_get_cache(PSRV(p)->repository);
	if (cache != NULL) {
		guint count = sqlx_cache_expire(cache, 100, 500 * G_TIME_SPAN_MILLISECOND);
		if (count)
			GRID_DEBUG("Expired %u bases", count);
	}
}

static void
_task_expire_resolver(gpointer p)
{
	hc_resolver_set_now(PSRV(p)->resolver, oio_ext_monotonic_time () / G_TIME_SPAN_SECOND);
	guint count = hc_resolver_expire(PSRV(p)->resolver);
	if (count)
		GRID_DEBUG("Expired %u entries from the resolver cache", count);
}

static void
_task_retry_elections(gpointer p)
{
	if (!PSRV(p)->flag_replicable)
		return;

	guint count = election_manager_retry_elections(PSRV(p)->election_manager,
			100, 500 * G_TIME_SPAN_MILLISECOND);
	if (count)
		GRID_DEBUG("Retried %u elections", count);
}

static void
_task_reload_nsinfo(gpointer p)
{
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

static void
_task_reload_workers(gpointer p)
{
	if (!PSRV(p)->nsinfo) {
		GRID_DEBUG("NS info not yet loaded");
		return;
	}

	gint64 max_workers = namespace_info_get_srv_param_i64 (PSRV(p)->nsinfo,
			NULL, PSRV(p)->service_config->srvtype, "max_workers",
			SRV.cfg_max_workers);
	network_server_set_max_workers(PSRV(p)->server, (guint) max_workers);
}

void
sqlx_task_reload_lb (struct sqlx_service_s *ss)
{
	static volatile gboolean already_succeeded = FALSE;
	static volatile guint tick_reload = 0;
	static volatile guint period_reload = 1;

	EXTRA_ASSERT(ss != NULL);
	if (!ss->lb || !ss->nsinfo)
		return;

	if (already_succeeded && 0 != (tick_reload++ % period_reload))
		return;

	GError *err = _reload_lbpool(ss->lb, FALSE);
	if (!err) {
		already_succeeded = TRUE;
		period_reload ++;
		period_reload = CLAMP(period_reload,2,10);
		tick_reload = 1;
	} else {
		GRID_WARN("Failed to reload the LB pool services: (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}

	grid_lbpool_reconfigure(ss->lb, ss->nsinfo);
}

static GError*
_reload_lbpool(struct grid_lbpool_s *glp, gboolean flush)
{
	gboolean _reload_srvtype(const gchar *ns, const gchar *srvtype) {
		GSList *list_srv = NULL;
		GError *err = conscience_get_services (ns, srvtype, &list_srv);
		if (err) {
			GRID_WARN("Gridagent/conscience error: Failed to list the services"
					" of type [%s]: code=%d %s", srvtype, err->code,
					err->message);
			g_clear_error(&err);
			return FALSE;
		}

		if (list_srv || flush) {
			GSList *l = list_srv;

			gboolean provide(struct service_info_s **p_si) {
				if (!l)
					return FALSE;
				*p_si = l->data;
				l->data = NULL;
				l = l->next;
				return TRUE;
			}
			grid_lbpool_reload(glp, srvtype, provide);
			g_slist_free(list_srv);
		}

		return TRUE;
	}

	GSList *list_srvtypes = NULL;
	GError *err = conscience_get_types (grid_lbpool_namespace(glp), &list_srvtypes);
	if (err)
		g_prefix_error(&err, "LB pool reload error: ");
	else {
		guint errors = 0;
		const gchar *ns = grid_lbpool_namespace(glp);

		for (GSList *l=list_srvtypes; l ;l=l->next) {
			if (!l->data)
				continue;
			if (!_reload_srvtype(ns, l->data))
				++ errors;
		}

		if (errors)
			GRID_DEBUG("Reloaded %u service types, with %u errors",
					g_slist_length(list_srvtypes), errors);
	}

	g_slist_free_full (list_srvtypes, g_free);
	return err;
}

/* Specific requests handlers ----------------------------------------------- */

static gboolean
_dispatch_RELOAD (struct gridd_reply_ctx_s *reply, gpointer pss, gpointer i)
{
	(void) i;
	struct sqlx_service_s *ss = pss;
	g_assert (ss != NULL);

	GError *err = _reload_lbpool(ss->lb, TRUE);
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
	/* if (ss->lb) grid_lbpool_flush (ss->lb); */
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

