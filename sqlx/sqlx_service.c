#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "sqlite_service"
#endif

#include <stdlib.h>
#include <stddef.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>
#include <server/network_server.h>
#include <server/grid_daemon.h>
#include <server/stats_holder.h>
#include <server/transport_gridd.h>

#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/election.h>
#include <sqliterepo/synchro.h>
#include <sqliterepo/replication_dispatcher.h>

#include <resolver/hc_resolver.h>

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
static gpointer _worker_clients(gpointer p);

// Static variables
static struct sqlx_service_s SRV;
static struct replication_config_s replication_config;
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
	return PSRV(ctx)->url->str;
}

static GError*
_get_version(gpointer ctx, const gchar *n, const gchar *t, GTree **result)
{
	EXTRA_ASSERT(ctx != NULL);
	return sqlx_repository_get_version2(PSRV(ctx)->repository, t, n, result);
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
	if (argc < 2) {
		GRID_WARN("Not enough options, see usage.");
		return FALSE;
	}

	// Positional arguments
	gsize s = g_strlcpy(ss->ns_name, argv[0], sizeof(ss->ns_name));
	if (s >= sizeof(ss->ns_name)) {
		GRID_WARN("Namespace name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(ss->ns_name));
		return FALSE;
	}
	GRID_NOTICE("NS configured to [%s]", ss->ns_name);

	s = g_strlcpy(ss->volume, argv[1], sizeof(ss->volume));
	if (s >= sizeof(ss->volume)) {
		GRID_WARN("Volume name too long (given=%"G_GSIZE_FORMAT" max=%lu)",
				s, sizeof(ss->volume));
		return FALSE;
	}
	GRID_NOTICE("Volume configured to [%s]", ss->volume);

	ss->zk_url = gridcluster_get_config(ss->ns_name, "zookeeper",
			GCLUSTER_CFG_NS|GCLUSTER_CFG_LOCAL);
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
				"minimum 64 required", limit.rlim_cur);
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
			|| !(ss->si = g_malloc0(sizeof(struct service_info_s)))
			|| !(ss->clients_pool = gridd_client_pool_create())
			|| !(ss->gsr_reqtime = grid_single_rrd_create(8))
			|| !(ss->gsr_reqcounter = grid_single_rrd_create(8))
			|| !(ss->resolver = hc_resolver_create())
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
	replication_config.get_peers = (GError* (*)(gpointer, const gchar*,
			const gchar*, gchar ***)) ss->service_config->get_peers;

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
	struct sqlx_repo_config_s repository_config;
	memset(&repository_config, 0, sizeof(repository_config));
	repository_config.flags = 0;
	repository_config.flags |= ss->flag_delete_on ? SQLX_REPO_DELETEON : 0;
	repository_config.flags |= ss->flag_cached_bases ? 0 : SQLX_REPO_NOCACHE;
	repository_config.flags |= ss->flag_autocreate ? SQLX_REPO_AUTOCREATE : 0;
	repository_config.flags |= ss->flag_nolock ? SQLX_REPO_NOLOCK : 0;
	repository_config.sync_solo = ss->sync_mode_solo;
	repository_config.sync_repli = ss->sync_mode_solo;
	repository_config.lock.ns = ss->ns_name;
	repository_config.lock.type = ss->service_config->srvtype;
	repository_config.lock.srv = ss->url->str;

	GError *err = sqlx_repository_init(ss->volume, &repository_config,
			&ss->repository);
	if (err) {
		GRID_WARN("SQLX repository init failure : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	err = sqlx_repository_configure_type(ss->repository,
			ss->service_config->srvtype, NULL,
			ss->service_config->schema);

	if (err) {
		GRID_ERROR("SQLX schema init failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return FALSE;
	}

	sqlx_repository_configure_open_timeout(ss->repository, ss->open_timeout);

	GRID_TRACE("SQLX repository initiated");
	return TRUE;
}

static gboolean
_configure_tasks(struct sqlx_service_s *ss)
{
	grid_task_queue_register(ss->gtq_register, 1, _task_register, NULL, ss);

	grid_task_queue_register(ss->gtq_reload, 5, _task_reload_nsinfo, NULL, ss);

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
	grid_string_to_addrinfo(ss->url->str, NULL, &(si->addr));

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.type"),
			ss->service_config->srvtag);

	_add_custom_tags(si, ss->custom_tags);

	service_tag_set_value_string(
			service_info_ensure_tag(si->tags, "tag.vol"),
			ss->volume);

	service_tag_set_value_float(
			service_info_ensure_tag(si->tags, "stat.req_idle"),
			100.0);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.cpu"),
			"cpu", NULL);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.space"),
			"space", ss->volume);
	service_tag_set_value_macro(
			service_info_ensure_tag(si->tags, "stat.io"),
			"io", ss->volume);
	return TRUE;
}

static gboolean
_configure_network(struct sqlx_service_s *ss)
{
	transport_gridd_dispatcher_add_requests(ss->dispatcher,
			sqlx_repli_gridd_get_requests(), ss->repository);
	return TRUE;
}

// common_main hooks -----------------------------------------------------------

static void
sqlx_service_action(void)
{
	GError *err = NULL;

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
	if (!SRV.thread_admin) {
		GRID_WARN("Failed to start the ADMIN thread : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	SRV.thread_reload = grid_task_queue_run(SRV.gtq_reload, &err);
	if (!SRV.thread_reload) {
		GRID_WARN("Failed to start the RELOAD thread : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	SRV.thread_register = grid_task_queue_run(SRV.gtq_register, &err);
	if (!SRV.thread_register) {
		GRID_WARN("Failed to start the REGISTER thread : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
		return;
	}

	SRV.thread_client = g_thread_create(_worker_clients, &SRV, TRUE, NULL);
	if (!SRV.thread_client) {
		GRID_WARN("Failed to start the CLIENT thread");
		return;
	}

	/* SERVER/GRIDD main run loop */
	if (!grid_main_is_running())
		return;
	grid_daemon_bind_host(SRV.server, SRV.url->str, SRV.dispatcher);
	err = network_server_open_servers(SRV.server);
	if (NULL != err) {
		GRID_ERROR("GRIDD bind failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}
	if (!grid_main_is_running())
		return;
	if (NULL != (err = network_server_run(SRV.server))) {
		GRID_ERROR("GRIDD run failure : (%d) %s", err->code, err->message);
		g_clear_error(&err);
		return;
	}
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

	if (SRV.repository) {
		sqlx_repository_stop(SRV.repository);
		struct sqlx_cache_s *cache = sqlx_repository_get_cache(SRV.repository);
		if (cache)
			sqlx_cache_expire(cache, G_MAXUINT, NULL);
	}
	if (SRV.election_manager) {
		election_manager_exit_all(SRV.election_manager, NULL, TRUE);
	}

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
	if (SRV.url)
		g_string_free(SRV.url, TRUE);
	if (SRV.zk_url)
		metautils_str_clean(&SRV.zk_url);

	namespace_info_clear(&SRV.nsinfo);
}

static struct grid_main_option_s *
sqlx_service_get_options(void)
{
	static struct grid_main_option_s sqlx_options[] =
	{
		{"Endpoint", OT_STRING, {.str = &SRV.url},
			"Bind to this IP:PORT couple instead of 0.0.0.0 and a random port"},
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
			"Limits the number of concurrent passive connections" },

		{"CacheEnabled", OT_BOOL, {.b = &SRV.flag_cached_bases},
			"If set, each base will be cached in a way it won't be accessed"
			" by several requests in the same time."},

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
	memset(&SRV, 0, sizeof(SRV));
	memset(&replication_config, 0, sizeof(replication_config));
	SRV.replication_config = &replication_config;
	SRV.service_config = cfg;
	return grid_main(argc, argv, &sqlx_service_callbacks);
}

// Tasks -----------------------------------------------------------------------

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
	grid_single_rrd_feed(network_server_get_stats(PSRV(p)->server),
			INNER_STAT_NAME_REQ_COUNTER, PSRV(p)->gsr_reqcounter,
			INNER_STAT_NAME_REQ_TIME, PSRV(p)->gsr_reqtime,
			NULL);

	guint64 avg_counter = grid_single_rrd_get_delta(PSRV(p)->gsr_reqcounter, 4);
	guint64 avg_time = grid_single_rrd_get_delta(PSRV(p)->gsr_reqtime, 4);

	avg_counter = MACRO_COND(avg_counter != 0, avg_counter, 1);
	avg_time = MACRO_COND(avg_time != 0, avg_time, 1);

	service_tag_set_value_i64(service_info_ensure_tag(PSRV(p)->si->tags,
				"stat.total_reqpersec"), avg_counter / 4);
	service_tag_set_value_i64(service_info_ensure_tag(PSRV(p)->si->tags,
				"stat.total_avreqtime"), (avg_time)/(avg_counter));
	service_tag_set_value_float(service_info_ensure_tag(PSRV(p)->si->tags,
				"stat.req_idle"), network_server_reqidle(PSRV(p)->server));

	/* send the registration now */
	GError *err = NULL;
	if (!register_namespace_service(PSRV(p)->si, &err))
		g_message("Service registration failed: (%d) %s", err->code, err->message);
	if (err)
		g_clear_error(&err);
}

static void
_task_expire_bases(gpointer p)
{
	GTimeVal end;
	g_get_current_time(&end);
	g_time_val_add(&end, 500000L);

	struct sqlx_cache_s *cache = sqlx_repository_get_cache(PSRV(p)->repository);
	if (cache != NULL) {
		guint count = sqlx_cache_expire(cache, 100, &end);
		if (count)
			GRID_DEBUG("Expired %u bases", count);
	}
}

static void
_task_expire_resolver(gpointer p)
{
	hc_resolver_set_now(PSRV(p)->resolver, time(0));
	guint count = hc_resolver_expire(PSRV(p)->resolver);
	if (count)
		GRID_DEBUG("Expired %u entries from the resolver cache", count);
}

static void
_task_retry_elections(gpointer p)
{
	if (!PSRV(p)->flag_replicable)
		return;

	GTimeVal end;
	g_get_current_time(&end);
	g_time_val_add(&end, 500000L);

	guint count = election_manager_retry_elections(
			PSRV(p)->election_manager, 100, &end);
	if (count)
		GRID_DEBUG("Retried %u elections", count);
}

static void
_task_reload_nsinfo(gpointer p)
{
	GError *err = NULL;
	struct namespace_info_s *ni;

	if (!(ni = get_namespace_info(PSRV(p)->ns_name, &err))) {
		GRID_WARN("NSINFO reload error [%s] : (%d) %s",
				PSRV(p)->ns_name, err->code, err->message);
		g_clear_error(&err);
	} else {
		namespace_info_copy(ni, &(PSRV(p)->nsinfo), NULL);
		namespace_info_free(ni);
	}
}

