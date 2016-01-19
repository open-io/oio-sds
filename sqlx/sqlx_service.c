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
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/stats_holder.h>
#include <server/transport_gridd.h>
#include <sqliterepo/sqlx_macros.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/election.h>
#include <sqliterepo/synchro.h>
#include <sqliterepo/replication_dispatcher.h>
#include <resolver/hc_resolver.h>

#include <glib.h>
#include <zmq.h>

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
static void _task_register(gpointer p);
static void _task_expire_bases(gpointer p);
static void _task_expire_resolver(gpointer p);
static void _task_retry_elections(gpointer p);
static void _task_reload_nsinfo(gpointer p);
static void _task_reload_workers(gpointer p);

static gpointer _worker_notify_gq2zmq (gpointer p);
static gpointer _worker_notify_zmq2agent (gpointer p);
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
	ss->notify.max_recv_per_round = 32;
	ss->notify.procid = getpid();
	ss->notify.counter = 0;

	if (!(ss->notify.zctx = zmq_init(1))
			|| !(ss->notify.pending_events = g_ptr_array_sized_new(32))
			|| !(ss->server = network_server_init())
			|| !(ss->dispatcher = transport_gridd_build_empty_dispatcher())
			|| !(ss->si = g_malloc0(sizeof(struct service_info_s)))
			|| !(ss->clients_pool = gridd_client_pool_create())
			|| !(ss->gsr_reqtime = grid_single_rrd_create(oio_ext_monotonic_time() / G_TIME_SPAN_SECOND, 8))
			|| !(ss->gsr_reqcounter = grid_single_rrd_create(oio_ext_monotonic_time() / G_TIME_SPAN_SECOND,8))
			|| !(ss->resolver = hc_resolver_create1(oio_ext_monotonic_time() / G_TIME_SPAN_SECOND))
			|| !(ss->gtq_admin = grid_task_queue_create("admin"))
			|| !(ss->gtq_register = grid_task_queue_create("register"))
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

	sqlx_repository_configure_open_timeout (ss->repository, ss->open_timeout);

	sqlx_repository_configure_hash (ss->repository,
			ss->service_config->repo_hash_width,
			ss->service_config->repo_hash_depth);

	GRID_TRACE("SQLX repository initiated");
	return TRUE;
}

static gboolean
_configure_tasks(struct sqlx_service_s *ss)
{
	grid_task_queue_register(ss->gtq_register, 1, _task_register, NULL, ss);

	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_nsinfo, NULL, ss);
	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_workers, NULL, ss);

	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_bases, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_expire_resolver, NULL, ss);
	grid_task_queue_register(ss->gtq_admin, 1, _task_retry_elections, NULL, ss);

	return TRUE;
}

static void
_add_custom_tags(struct service_info_s *si, GSList *tags)
{
	for (; tags ;tags = g_slist_next(tags)) {
		gchar** tokens = g_strsplit((gchar*)(tags->data), "=", 2);
		if (!tokens)
			continue;
		// TODO add more checks on the name and value.
		if (tokens[0] && tokens[1]) {
			gchar *n = g_strconcat("tag.", tokens[0], NULL);
			service_tag_set_value_string(service_info_ensure_tag(si->tags, n),
					tokens[1]);
			g_free(n);
		}
		g_strfreev(tokens);
	}
}

static gboolean
_configure_registration(struct sqlx_service_s *ss)
{
	struct service_info_s *si = ss->si;

	si->tags = g_ptr_array_new();
	metautils_strlcpy_physical_ns(si->ns_name, ss->ns_name, sizeof(si->ns_name));
	g_strlcpy(si->type, ss->service_config->srvtype, sizeof(si->type)-1);
	grid_string_to_addrinfo(ss->announce->str, &(si->addr));

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.type"),
			ss->service_config->srvtag);

	_add_custom_tags(si, ss->custom_tags);

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.vol"),
			ss->volume);

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
	grid_task_queue_fire(SRV.gtq_register);
	GRID_DEBUG("All tasks now fired once");

	/* Start the administrative threads */
	SRV.thread_admin = grid_task_queue_run(SRV.gtq_admin, &err);
	if (!SRV.thread_admin)
		return _action_report_error(err, "Failed to start the ADMIN thread");

	SRV.thread_reload = grid_task_queue_run(SRV.gtq_reload, &err);
	if (!SRV.thread_reload)
		return _action_report_error(err, "Failed to start the RELOAD thread");

	SRV.thread_register = grid_task_queue_run(SRV.gtq_register, &err);
	if (!SRV.thread_register)
		return _action_report_error(err, "Failed to start the REGISTER thread");

	SRV.thread_client = g_thread_try_new("clients", _worker_clients, &SRV, &err);
	if (!SRV.thread_client)
		return _action_report_error(err, "Failed to start the CLIENT thread");

	if (SRV.notify.queue) {
		SRV.notify.th_gq2zmq = g_thread_try_new("notifier-gq2zmq", _worker_notify_gq2zmq, &SRV, &err);
		if (!SRV.notify.th_gq2zmq)
			return _action_report_error(err, "Failed to start the NOTIFY-GQ2ZMQ thread");
	}

	if (SRV.notify.zpull) {
		SRV.notify.th_zmq2agent = g_thread_try_new("notifier-req", _worker_notify_zmq2agent, &SRV, &err);
		if (!SRV.notify.th_zmq2agent)
			return _action_report_error(err, "Failed to start the NOTIFY-ZMQ2AGENT thread");
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
	if (SRV.gtq_register)
		grid_task_queue_stop(SRV.gtq_register);
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
	    && _configure_registration(&SRV)
	    && _configure_network(&SRV)
		&& (!SRV.service_config->post_config
				|| SRV.service_config->post_config(&SRV));
}

static void
sqlx_service_set_defaults(void)
{
	SRV.open_timeout = 20000;
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
	if (SRV.gtq_register)
		grid_task_queue_stop(SRV.gtq_register);
	if (SRV.gtq_admin)
		grid_task_queue_stop(SRV.gtq_admin);

	if (SRV.server) {
		network_server_close_servers(SRV.server);
		network_server_stop(SRV.server);
	}

	if (SRV.thread_reload)
		g_thread_join(SRV.thread_reload);
	if (SRV.thread_register)
		g_thread_join(SRV.thread_register);
	if (SRV.thread_admin)
		g_thread_join(SRV.thread_admin);
	if (SRV.thread_client)
		g_thread_join(SRV.thread_client);

	if (SRV.notify.th_gq2zmq)
		g_thread_join(SRV.notify.th_gq2zmq);
	if (SRV.notify.th_zmq2agent)
		g_thread_join(SRV.notify.th_zmq2agent);

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
	if (SRV.gtq_register)
		grid_task_queue_destroy(SRV.gtq_register);

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

	if (SRV.gsr_reqtime)
		grid_single_rrd_destroy(SRV.gsr_reqtime);
	if (SRV.gsr_reqcounter)
		grid_single_rrd_destroy(SRV.gsr_reqcounter);

	if (SRV.custom_tags)
		g_slist_free_full(SRV.custom_tags, g_free);
	if (SRV.si)
		service_info_clean(SRV.si);
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

	if (SRV.notify.queue)
		g_async_queue_unref (SRV.notify.queue);
	if (SRV.notify.zpush)
		zmq_close (SRV.notify.zpush);
	if (SRV.notify.zpull)
		zmq_close (SRV.notify.zpull);
	if (SRV.notify.zagent)
		zmq_close (SRV.notify.zagent);
	if (SRV.notify.zctx)
		zmq_term (SRV.notify.zctx);
	if (SRV.notify.pending_events)
		g_ptr_array_free (SRV.notify.pending_events, TRUE);

	if (SRV.nsinfo)
		namespace_info_free(SRV.nsinfo);
}

static struct grid_main_option_s *
sqlx_service_get_options(void)
{
	static struct grid_main_option_s sqlx_options[] =
	{
		{"Endpoint", OT_STRING, {.str = &SRV.url},
			"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
		{"Announce", OT_STRING, {.str = &SRV.announce},
			"Announce this IP:PORT couple instead of the TCP endpoint"},

		{"Tag", OT_LIST, {.lst = &SRV.custom_tags},
			"Tag to associate to the SRV (multiple custom tags are supported)"},

		{"Replicate", OT_BOOL, {.b = &SRV.flag_replicable},
			"DO NOT USE THIS. This might disable the replication"},
		{"NoRegister", OT_BOOL, {.b = &SRV.flag_noregister},
			"DO NOT USE THIS. The SRV won't register in the conscience"},

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

	return sqlx_options;
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
_task_register(gpointer p)
{
	if (PSRV(p)->flag_noregister)
		return;

	/* Computes the avg requests rate/time */
	time_t now = oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;

	grid_single_rrd_push (PSRV(p)->gsr_reqcounter, now,
			network_server_stat_getone(PSRV(p)->server,
				g_quark_from_static_string(INNER_STAT_NAME_REQ_COUNTER)));
	grid_single_rrd_push (PSRV(p)->gsr_reqtime, now,
			network_server_stat_getone(PSRV(p)->server,
				g_quark_from_static_string(INNER_STAT_NAME_REQ_TIME)));

	guint64 avg_counter = grid_single_rrd_get_delta(PSRV(p)->gsr_reqcounter,
			now, 4);
	guint64 avg_time = grid_single_rrd_get_delta(PSRV(p)->gsr_reqtime,
			now, 4);

	avg_counter = MACRO_COND(avg_counter != 0, avg_counter, 1);
	avg_time = MACRO_COND(avg_time != 0, avg_time, 1);

	service_tag_set_value_i64(service_info_ensure_tag(PSRV(p)->si->tags,
				"stat.total_reqpersec"), avg_counter / 4);
	service_tag_set_value_i64(service_info_ensure_tag(PSRV(p)->si->tags,
				"stat.total_avreqtime"), (avg_time)/(avg_counter));

	/* send the registration now */
	GError *err = register_namespace_service(PSRV(p)->si);
	if (err) {
		g_message("Service registration failed: (%d) %s", err->code, err->message);
		g_clear_error(&err);
	}
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


/* Events notifications ----------------------------------------------------- */

GError *
sqlx_notify (gpointer udata, gchar *msg)
{
	struct sqlx_service_s *ss = udata;
	if (ss->notify.queue && ss->notify.th_zmq2agent)
		g_async_queue_push (ss->notify.queue, msg);
	else
		g_free(msg);
	return NULL;
}

gboolean
sqlx_enable_notifier (struct sqlx_service_s *ss)
{
	int rc, err, opt;
	EXTRA_ASSERT(ss != NULL);
	EXTRA_ASSERT(ss->notify.queue == NULL);

	if (!ss->notify.queue)
		ss->notify.queue = g_async_queue_new();

	if (!ss->notify.zagent) {
		ss->notify.zagent = zmq_socket (ss->notify.zctx, ZMQ_DEALER);
		opt = 1000;
		zmq_setsockopt (SRV.notify.zagent, ZMQ_LINGER, &opt, sizeof(opt));
		opt = 64 * 1024;
		zmq_setsockopt (SRV.notify.zagent, ZMQ_SNDBUF, &opt, sizeof(opt));
		zmq_setsockopt (SRV.notify.zagent, ZMQ_RCVBUF, &opt, sizeof(opt));
		opt = 16;
		zmq_setsockopt (SRV.notify.zagent, ZMQ_SNDHWM, &opt, sizeof(opt));
		zmq_setsockopt (SRV.notify.zagent, ZMQ_RCVHWM, &opt, sizeof(opt));

		gchar *url =  gridcluster_get_eventagent (SRV.ns_name);
		if (url) {
			if (0 > (rc = zmq_connect (SRV.notify.zagent, url))) {
				err = zmq_errno ();
				GRID_WARN("ZMQ connection error (event-agent) : (%d) %s",
						err, zmq_strerror (err));
			}
			g_free (url);
		}
	}

	if (!ss->notify.zpush) {
		ss->notify.zpush = zmq_socket(ss->notify.zctx, ZMQ_PUSH);
		zmq_bind (ss->notify.zpush, "inproc://events");
		opt = 1000;
		zmq_setsockopt (ss->notify.zpush, ZMQ_LINGER, &opt, sizeof(opt));
		opt = 16;
		zmq_setsockopt (SRV.notify.zpull, ZMQ_SNDHWM, &opt, sizeof(opt));
	}

	if (!ss->notify.zpull) {
		ss->notify.zpull = zmq_socket(ss->notify.zctx, ZMQ_PULL);
		zmq_connect (SRV.notify.zpull, "inproc://events");
		opt = 16;
		zmq_setsockopt (SRV.notify.zpull, ZMQ_RCVHWM, &opt, sizeof(opt));
	}

	return TRUE;
}

#define HEADER_SIZE 14

struct event_s
{
	// 3 fields used as unique key
	guint32 rand;
	guint32 recv_time;
	guint32 evtid;
	guint16 procid;

	// and then the payload
	guint16 size;
	gint64 last_sent;
	guint8 message[];
};

static gboolean
_zmq2agent_send_event (struct sqlx_service_s *ss, struct event_s *evt)
{
	int rc;
	gchar tmp[1+ 2*HEADER_SIZE];

	evt->last_sent = oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;
	oio_str_bin2hex(evt, HEADER_SIZE, tmp, sizeof(tmp));

retry:
	rc = zmq_send (ss->notify.zagent, "", 0, ZMQ_SNDMORE|ZMQ_MORE|ZMQ_DONTWAIT);
	if (rc == 0) {
		rc = zmq_send (ss->notify.zagent, evt, HEADER_SIZE,
				ZMQ_MORE|ZMQ_SNDMORE|ZMQ_DONTWAIT);
		if (rc == HEADER_SIZE)
			rc = zmq_send (ss->notify.zagent, evt->message, evt->size, ZMQ_DONTWAIT);
	}

	if (rc < 0) {
		int err = zmq_errno ();
		if (err == EINTR)
			goto retry;
		GRID_WARN("EVT:ERR %s (%d) %s", tmp, err, zmq_strerror(err));
		return FALSE;
	} else {
		++ ss->notify.counter_sent;
		GRID_DEBUG("EVT:SNT %s", tmp);
		return TRUE;
	}
}

static gboolean
_zmq2agent_manage_event (guint32 r, struct sqlx_service_s *ss, zmq_msg_t *msg)
{
	if (!ss->notify.zagent)
		return TRUE;

	struct event_s *evt = g_malloc (sizeof(struct event_s) + zmq_msg_size(msg));
	memcpy (evt->message, zmq_msg_data(msg), zmq_msg_size(msg));
	evt->rand = r;
	evt->evtid = ss->notify.counter ++;
	evt->procid = ss->notify.procid;
	evt->size = zmq_msg_size (msg);
	evt->last_sent = oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;
	evt->recv_time = evt->last_sent;

	g_ptr_array_add (ss->notify.pending_events, evt);

	if (GRID_DEBUG_ENABLED()) {
		gchar tmp[1+ 2*HEADER_SIZE];
		oio_str_bin2hex(evt, HEADER_SIZE, tmp, sizeof(tmp));
		GRID_DEBUG("EVT:DEF %s (%u) %.*s", tmp,
				ss->notify.pending_events->len, evt->size, evt->message);
	}

	return _zmq2agent_send_event (ss, evt);
}

static void
_zmq2agent_manage_ack (struct sqlx_service_s *ss, zmq_msg_t *msg)
{
	if (zmq_msg_size (msg) != HEADER_SIZE)
		return;

	void *d = zmq_msg_data (msg);
	for (guint i=0; i<ss->notify.pending_events->len ;i++) {
		struct event_s *evt = g_ptr_array_index(ss->notify.pending_events, i);
		if (!memcmp(evt, d, HEADER_SIZE)) {
			if (GRID_DEBUG_ENABLED()) {
				gchar tmp[1+(2*HEADER_SIZE)];
				oio_str_bin2hex(evt, HEADER_SIZE, tmp, sizeof(tmp));
				GRID_DEBUG("EVT:ACK %s", tmp);
			}
			g_free (evt);
			g_ptr_array_remove_index_fast (ss->notify.pending_events, i);
			++ ss->notify.counter_ack;
			return;
		}
	}
	++ ss->notify.counter_ack_notfound;
}

static void
_retry_events (struct sqlx_service_s *ss)
{
	const time_t now = oio_ext_monotonic_time () / G_TIME_SPAN_SECOND;
	for (guint i=0; i<ss->notify.pending_events->len ;i++) {
		struct event_s *evt = g_ptr_array_index (ss->notify.pending_events, i);
		if (evt->last_sent < now-29) {
			if (!_zmq2agent_send_event (ss, evt))
				break;
		}
	}
}

static void
_zmq2agent_receive_acks (struct sqlx_service_s *ss)
{
	int rc;
	zmq_msg_t msg;
	do {
		zmq_msg_init (&msg);
		rc = zmq_msg_recv (&msg, ss->notify.zagent, ZMQ_DONTWAIT);
		if (rc > 0)
			_zmq2agent_manage_ack (ss, &msg);
		zmq_msg_close (&msg);
	} while (rc >= 0);
}

static gboolean
_zmq2agent_receive_events (GRand *r, struct sqlx_service_s *ss)
{
	int i=0, rc, ended = 0;
	do {
		zmq_msg_t msg;
		zmq_msg_init (&msg);
		rc = zmq_msg_recv (&msg, ss->notify.zpull, ZMQ_DONTWAIT);
		ended = (rc == 0); // empty frame is an EOF
		if (rc > 0) {
			++ ss->notify.counter_received;
			if (!_zmq2agent_manage_event (g_rand_int(r), ss, &msg))
				rc = 0; // make it break
		}
		zmq_msg_close (&msg);
	} while (rc > 0 && i++ < ss->notify.max_recv_per_round);
	return !ended;
}

static gpointer
_worker_notify_zmq2agent (gpointer p)
{
	/* XXX(jfs): a dedicated PRNG avoids locking the glib's PRNG for each call
	   (such global locks are present in the GLib) and opening it with a seed
	   from the glib's PRNG avoids syscalls to the special file /dev/urandom */
	GRand *r = g_rand_new_with_seed (g_random_int ());

	gint64 last_debug = oio_ext_monotonic_time ();
	struct sqlx_service_s *ss = p;
	zmq_pollitem_t pi[2] = {
		{ss->notify.zpull, -1, ZMQ_POLLIN, 0},
		{ss->notify.zagent, -1, ZMQ_POLLIN, 0},
	};

	for (gboolean run = TRUE; run ;) {
		int rc = zmq_poll (pi, 2, 1000);
		if (rc < 0) {
			int err = zmq_errno();
			if (err != ETERM && err != EINTR)
				GRID_WARN("ZMQ poll error : (%d) %s", err, zmq_strerror(err));
			if (err != EINTR)
				break;
		}
		if (pi[1].revents)
			_zmq2agent_receive_acks (ss);
		_retry_events (ss);
		if (pi[0].revents)
			run = _zmq2agent_receive_events (r, ss);

		/* Periodically write stats in the log */
		gint64 now = oio_ext_monotonic_time ();
		if ((now - last_debug) > G_TIME_SPAN_MINUTE) {
			GRID_INFO("ZMQ2AGENT recv=%"G_GINT64_FORMAT" sent=%"G_GINT64_FORMAT
					" ack=%"G_GINT64_FORMAT"+%"G_GINT64_FORMAT" queue=%u",
					ss->notify.counter_received, ss->notify.counter_sent,
					ss->notify.counter_ack, ss->notify.counter_ack_notfound,
					ss->notify.pending_events->len);
			last_debug = now;
		}
	}

	g_rand_free (r);
	GRID_INFO ("Thread stopping [NOTIFY-ZMQ2AGENT]");
	return p;
}

static gboolean
_forward_event (struct sqlx_service_s *ss, gchar *encoded)
{
	gboolean rc = TRUE;
	size_t len = strlen(encoded);
	if (ss->notify.zpush) {
retry:
		if (0 > zmq_send (ss->notify.zpush, encoded, len, 0)) {
			int err = zmq_errno();
			if (err == EINTR)
				goto retry;
			if (err == ETERM)
				rc = FALSE;
			GRID_WARN("EVT:ERR - %s %s", encoded, zmq_strerror(err));
		}
	} else {
		GRID_DEBUG("EVT:END - %s", encoded);
	}
	g_free (encoded);
	return rc;
}

static gpointer
_worker_notify_gq2zmq (gpointer p)
{
	struct sqlx_service_s *ss = p;
	gchar *tmp;

	while (grid_main_is_running()) {
		tmp = (gchar*) g_async_queue_timeout_pop (ss->notify.queue, 1 * G_TIME_SPAN_SECOND);
		if (tmp && !_forward_event (ss, tmp))
			break;
	}

	/* manage what remains in the GQueue */
	while (NULL != (tmp = g_async_queue_try_pop (ss->notify.queue))) {
		if (!_forward_event (ss, tmp))
			break;
	}

	/* Empty frame is an EOF */
	zmq_send (ss->notify.zpush, "", 0, 0);
	GRID_INFO ("Thread stopping [NOTIFY-GQ2ZMQ]");
	return p;
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

