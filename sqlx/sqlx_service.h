#ifndef REDCURRANT_sqlx_service__h
# define REDCURRANT_sqlx_service__h 1

#define PSRV(P) ((struct sqlx_service_s*)(P))

struct sqlx_service_config_s;
struct sqlx_service_s;

struct service_info_s;
struct gridd_client_pool_s;
struct sqlx_repository_s;
struct election_manager_s;
struct network_server_s;
struct gridd_request_dispatcher_s;
struct hc_resolver_s;
struct grid_task_queue_s;
struct grid_single_rrd_s;
struct sqlx_repo_config_s;
struct sqlx_sync_s;
struct replication_config_s;
struct sqlx_service_extras_s;

struct sqlx_service_config_s
{
	const gchar *srvtype;
	const gchar *srvtag;
	const gchar *zk_prefix;
	const guint zk_hash_depth;
	const guint zk_hash_width;
	const gchar *schema;

	GError* (*get_peers) (struct sqlx_service_s *ss,
			const gchar *n, const gchar *t, gboolean nocache,
			gchar ***result);

	// Called at the end of the configure step. Destined to initiating
	// servces backends, plugging message handers, etc.
	gboolean (*post_config) (struct sqlx_service_s *ss);

	// Available to override
	void (*set_defaults) (struct sqlx_service_s *ss);
};

// Elements common to any gridd+sqliterepo services
struct sqlx_service_s
{
	gchar volume[1024];
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	struct replication_config_s *replication_config;
	const struct sqlx_service_config_s *service_config;

	GString *url;
	GString *announce;
	gchar *zk_url;

	struct sqlx_repository_s *repository;
	struct sqlx_sync_s *sync;
	struct election_manager_s *election_manager;
	struct network_server_s *server;
	struct gridd_request_dispatcher_s *dispatcher;
	struct hc_resolver_s *resolver;
	struct sqlx_service_extras_s *extras;

	// The tasks under this queue always follow a reload of the
	// nsinfo field, and can safely play with it. This is the place
	// for LB reloading, reconfiguration, etc.
	struct namespace_info_s nsinfo;
	struct grid_task_queue_s *gtq_reload;
	GThread *thread_reload;

	// Queue dedicated to expirations elections, caches, etc.
	struct grid_task_queue_s *gtq_admin;
	GThread *thread_admin;

	// Conscience registration
	struct grid_single_rrd_s *gsr_reqcounter;
	struct grid_single_rrd_s *gsr_reqtime;
	struct service_info_s *si;
	struct grid_task_queue_s *gtq_register;
	GThread *thread_register;

	struct gridd_client_pool_s *clients_pool;
	GThread *thread_client;

	// This is configured during the "configure" step, and can be overriden
	// in the _post_config hook.
	gint64 open_timeout;
	gint64 cnx_backlog;
	guint max_bases;
	guint max_passive;
	guint max_active;

	//-------------------------------------------------------------------
	// Variables used during the startup time of the server, but not used
	// anymore after that.
	//-------------------------------------------------------------------

	GSList *custom_tags;

	guint cfg_max_bases;
	guint cfg_max_passive;
	guint cfg_max_active;
	guint cfg_max_workers;

	guint sync_mode_repli;
	guint sync_mode_solo;

	// Must the cache be set
	gboolean flag_cached_bases;

	// Are DB deletions allowed ?
	gboolean flag_delete_on;

	// Are DB autocreations enabled?
	gboolean flag_autocreate;

	// Turn to TRUE to avoid locking the repository volume
	gboolean flag_nolock;

	// Is the registration task to be executed?
	gboolean flag_noregister;

	// Controls the election mode:
	// TRUE :  ELECTION_MODE_QUORUM
	// FALSE : ELECTION_MODE_NONE
	gboolean flag_replicable;

};

// Public API
extern int sqlite_service_main(int argc, char **argv,
		const struct sqlx_service_config_s *cfg);

#endif // REDCURRANT_sqlx_service__h
