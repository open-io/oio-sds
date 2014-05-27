#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.main"
#endif

#include <errno.h>
#include <getopt.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./broken_workers.h"
#include "./config.h"
#include "./cpu_stat_task_worker.h"
#include "./event_workers.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./io_stat_task_worker.h"
#include "./namespace_get_task_worker.h"
#include "./request_worker.h"
#include "./services_workers.h"
#include "./server.h"
#include "./task_scheduler.h"


/* GLOBALS */
gboolean gridagent_blank_undefined_srvtags = TRUE;

GHashTable *namespaces = NULL;

int event_file_mode = EVENTS_MODE_FILE_DEFAULT;
int event_directory_mode = EVENTS_MODE_DIR_DEFAULT;
gboolean event_queue_cleaning_allowed = TRUE;
gchar *path_configured_top_spool_dir = NULL;
char event_enable_receive = EVENTS_RECEIVE_ENABLE_DEFAULT;
char event_enable_manage = EVENTS_MANAGE_ENABLE_DEFAULT;

guint max_events_actions_pending = EVENTS_MAXPENDING_ACTIONS_DEFAULT;
guint max_events_pending = EVENTS_MAXPENDING_DEFAULT;

char xattr_event_timestamp[256] = AGENT_DEFAULT_EVENT_XATTR;
time_t event_delay = EVENTS_DELAY_INCOMING_DEFAULT;

enum process_type_e agent_type = PT_REQ;

gboolean flag_check_services = DEFAULT_SVC_CHECK;
int period_check_services = DEFAULT_SVC_CHECK_FREQ;

int period_get_evtconfig = DEFAULT_CS_UPDATE_FREQ;
int period_get_ns = DEFAULT_CS_UPDATE_FREQ;
int period_get_srvtype = DEFAULT_CS_UPDATE_FREQ;
int period_get_srvlist = DEFAULT_CS_UPDATE_FREQ;
int period_push_srvlist = DEFAULT_CS_UPDATE_FREQ;

gboolean flag_manage_broken = DEFAULT_BROKEN_MANAGE;
int period_push_broken = DEFAULT_BROKEN_FREQ;
int period_get_broken = DEFAULT_BROKEN_FREQ;

gchar str_opt_config[1024] = "/GRID/common/conf/gridagent.conf";
gchar str_opt_log[1024] = "/GRID/common/conf/gridagent.log4crc";

static int flag_help = FALSE;
static gchar ns_name[LIMIT_LENGTH_NSNAME];

const gchar*
get_signame(int s)
{
	switch (s) {
		case SIGPIPE: return "SIGPIPE";
		case SIGUSR1: return "SIGUSR1";
		case SIGUSR2: return "SIGUSR2";
		case SIGINT: return "SIGINT";
		case SIGTERM: return "SIGTERM";
		case SIGABRT: return "SIGABRT";
		case SIGQUIT: return "SIGQUIT";
		case SIGCHLD: return "SIGCHLD";
		case SIGCONT: return "SIGCONT";
		case SIGHUP: return "SIGHUP";
	}
	return "?";
}

/* ------------------------------------------------------------------------- */

static int
change_user(const char *user_name, const char *group_name, GError ** error)
{
	struct passwd *pwd = NULL;
	struct group *grp = NULL;

	pwd = getpwnam(user_name);
	if (pwd == NULL) {
		GSETERROR(error, "User [%s] not found in /etc/passwd", user_name);
		return (0);
	}

	grp = getgrnam(group_name);
	if (grp == NULL) {
		GSETERROR(error, "Group [%s] not found in /etc/group", group_name);
		return (0);
	}

	if (setgid(grp->gr_gid) < 0) {
		GSETERROR(error, "Failed to switch group to [%s] : %s", group_name, strerror(errno));
		return (0);
	}

	if (setuid(pwd->pw_uid) < 0) {
		GSETERROR(error, "Failed to switch user to [%s] : %s", user_name, strerror(errno));
		return (0);
	}

	return (1);
}

int
is_agent_running(void)
{
	int usock;
	struct sockaddr_un local;

	/* Create socket */
	usock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (usock < 0)
		return (0);

	/* Connect to file */
	memset(&local, 0x00, sizeof(local));
	local.sun_family = AF_UNIX;
	g_strlcpy(local.sun_path, AGENT_SOCK_PATH, sizeof(local.sun_path)-1);

	if (connect(usock, (struct sockaddr *) &local, sizeof(local)) < 0) {
		unlink(AGENT_SOCK_PATH);
		metautils_pclose(&usock);
		return (0);
	}
	else {
		metautils_pclose(&usock);
		return (1);
	}
}

static struct namespace_data_s *
create_namespace_data(const gchar * name, const addr_info_t * addr)
{
	gchar *path_top_spool_dir;
	struct namespace_data_s *ns_data;

	ns_data = g_malloc0(sizeof(struct namespace_data_s));

	ns_data->configured = FALSE;

	g_strlcpy(ns_data->name, name, LIMIT_LENGTH_NSNAME);
	g_strlcpy(ns_data->ns_info.name, name, sizeof(ns_data->ns_info.name)-1);
	memcpy(&(ns_data->ns_info.addr), addr, sizeof(addr_info_t));

	ns_data->conscience = conscience_create();
	namespace_info_copy(&(ns_data->ns_info), &(ns_data->conscience->ns_info), NULL);

	ns_data->local_services = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify) service_info_clean);
	ns_data->down_services = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, (GDestroyNotify) service_info_clean);

	/*queue data*/
	path_top_spool_dir = path_configured_top_spool_dir && *path_configured_top_spool_dir
		? path_configured_top_spool_dir : EVENTS_SPOOL_DIR_DEFAULT;

	g_snprintf(ns_data->queues.dir_incoming, sizeof(ns_data->queues.dir_incoming),
		"%s/%s/"SUFFIX_SPOOL_INCOMING, path_top_spool_dir, name);
	g_snprintf(ns_data->queues.dir_trash, sizeof(ns_data->queues.dir_trash),
		"%s/%s/"SUFFIX_SPOOL_TRASH, path_top_spool_dir, name);
	g_snprintf(ns_data->queues.dir_pending, sizeof(ns_data->queues.dir_pending),
		"%s/%s/"SUFFIX_SPOOL_PENDING, path_top_spool_dir, name);

	return ns_data;
}

int
parse_namespaces(GError ** error)
{
	GHashTableIter iterator;
	gpointer k, v;
	GHashTable *ns_hash = NULL;

	ns_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!ns_hash) {
		GSETERROR(error, "Memory allocation failure");
		return (0);
	}

	if (!parse_cluster_config(ns_hash, error)) {
		GSETERROR(error, "Failed to parse cluster config");
		g_hash_table_destroy(ns_hash);
		return (0);
	}

	g_hash_table_iter_init(&iterator, ns_hash);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		namespace_data_t *ns_data;

		ns_data = g_hash_table_lookup(namespaces, k);
		if (!ns_data) {
			ns_data = create_namespace_data((gchar *) k, (addr_info_t *) v);
			if (!ns_data)
				return 0;
			g_hash_table_insert(namespaces, g_strdup((gchar *) k), ns_data);
		}
		else
			memcpy(&(ns_data->ns_info.addr), v, sizeof(addr_info_t));
	}

	g_hash_table_destroy(ns_hash);
	return (1);
}

int
agent_worker_default_func(worker_t * worker, GError ** error)
{
	(void)worker;
	(void)error;
	return 1;
}

void
agent_worker_default_cleaner(worker_t * worker)
{
	(void) worker;
}

void
free_agent_structures(void)
{
	clean_task_scheduler();

	if (namespaces) {
		g_hash_table_destroy(namespaces);
		namespaces = NULL;
	}
}

static void
destroy_namespace_data(gpointer p)
{
	struct namespace_data_s *ns_data;

	if (!p)
		return;
	ns_data = p;

	if (ns_data->conscience)
		conscience_destroy(ns_data->conscience);
	if (ns_data->list_broken) {
		g_slist_foreach(ns_data->list_broken, g_free1, NULL);
		g_slist_free(ns_data->list_broken);
	}
	if (ns_data->local_services)
		g_hash_table_destroy(ns_data->local_services);
	if (ns_data->down_services)
		g_hash_table_destroy(ns_data->down_services);

	memset(ns_data, 0x00, sizeof(struct namespace_data_s));
	g_free(ns_data);
}

static inline int
_cfg_get_int_base(int base, GHashTable *ht, const gchar *name, int def)
{
	gchar *str = g_hash_table_lookup(ht, name);
	if (!str)
		return def;
	gint64 i64 = g_ascii_strtoll(str, NULL, base);
	gint i;
	return (i = i64);
}

static int
_cfg_get_int(GHashTable *ht, const gchar *name, int def)
{
	return _cfg_get_int_base(10, ht, name, def);
}

static inline gboolean
_cfg_get_bool(GHashTable *ht, const gchar *name, gboolean def)
{
	return metautils_cfg_get_bool(g_hash_table_lookup(ht, name), def);
}

#define INT(K,D) _cfg_get_int(params, K, D)
#define CFGBOOL(K,D) _cfg_get_bool(params, K, D)

static int
parse_configuration(const gchar *config, GError **error)
{
	namespaces = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, destroy_namespace_data);

	GHashTable *params = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);

	if (!parse_config(config, params, error)) {
		GSETERROR(error,"Invalid configuration");
		g_hash_table_destroy(params);
		return 0;
	}

	if (!change_user(g_hash_table_lookup(params, USER_KEY),
				g_hash_table_lookup(params, GROUP_KEY), error)) {
		GSETERROR(error,"Failed to change user");
		g_hash_table_destroy(params);
		return 0;
	}

	NOTICE("Direct configuration variables set to...");

	/* main configuration */
	flag_check_services = CFGBOOL(SVC_CHECK_KEY, DEFAULT_SVC_CHECK);
	period_check_services = INT(SVC_CHECK_FREQ_KEY, DEFAULT_SVC_CHECK_FREQ);

	NOTICE("  Check service = %s", flag_check_services ? "ON" : "OFF");
	NOTICE("    period_check_services = %d", period_check_services);

	/* finer tuning */
	int def = INT(CS_DEFAULT_FREQ_KEY, DEFAULT_CS_UPDATE_FREQ);
	period_get_ns = INT(CS_GET_NS_PERIOD_KEY, def);
	period_get_srvtype = INT(CS_GET_SRVTYPE_PERIOD_KEY, def);
	period_get_srvlist = INT(CS_GET_SRVLIST_PERIOD_KEY, def);
	period_push_srvlist = INT(CS_PUSH_SRVLIST_PERIOD_KEY, def);
	period_get_evtconfig = INT(CS_GET_EVTCFG_PERIOD_KEY, def);

	NOTICE("  Default period = %d", def);
	NOTICE("    period_get_ns = %d", period_get_ns);
	NOTICE("    period_get_srvtype = %d", period_get_srvtype);
	NOTICE("    period_get_srvlist = %d", period_get_srvlist);
	NOTICE("    period_get_evtconfig = %d", period_get_evtconfig);
	NOTICE("    period_push_srvlist = %d", period_push_srvlist);

	/* broken elements streams */
	flag_manage_broken = CFGBOOL(KEY_BROKEN_MANAGE, DEFAULT_BROKEN_MANAGE);
	period_push_broken = INT(KEY_BROKEN_FREQ_PUSH, DEFAULT_BROKEN_FREQ);
	period_get_broken = INT(KEY_BROKEN_FREQ_GET, DEFAULT_BROKEN_FREQ);

	NOTICE("  broken streams = %s", flag_manage_broken ? "ON" : "OFF");
	NOTICE("    period_push_broken = %d", period_push_broken);
	NOTICE("    period_get_broken = %d", period_get_broken);

	/*events configuration*/
	event_enable_manage = CFGBOOL(EVENTS_MANAGE_ENABLE_KEY, FALSE);
	event_enable_receive = CFGBOOL(EVENTS_RECEIVE_ENABLE_KEY, FALSE);
	max_events_pending = INT(EVENTS_MAXPENDING_KEY, EVENTS_MAXPENDING_DEFAULT);
	event_delay = INT(EVENTS_DELAY_INCOMING_KEY, EVENTS_DELAY_INCOMING_DEFAULT);
	gchar *str;
	if (NULL != (str = g_hash_table_lookup(params, EVENTS_SPOOL_DIR_KEY)))
		path_configured_top_spool_dir = g_strdup(str);
	else
		path_configured_top_spool_dir = g_strdup(EVENTS_SPOOL_DIR_DEFAULT);

	NOTICE("Event handling limits set to ...");
	NOTICE("  event_receive = %s", event_enable_receive?"ON":"OFF");
	NOTICE("  event_manage = %s", event_enable_manage?"ON":"OFF");
	NOTICE("  max_events_pending = %u", max_events_pending);
	NOTICE("  events_incoming_delay = %ld", event_delay);
	NOTICE("  events_spool_dir = %s", path_configured_top_spool_dir);

	unix_socket_mode = _cfg_get_int_base(8,
			params, UNIX_SOCK_KEY_MODE, UNIX_SOCK_DEFAULT_MODE);
	unix_socket_uid = INT(UNIX_SOCK_KEY_UID,  UNIX_SOCK_DEFAULT_UID);
	unix_socket_gid = INT(UNIX_SOCK_KEY_GID,  UNIX_SOCK_DEFAULT_GID);
	NOTICE("Socket permissions set to ...");
	NOTICE("  unix_socket_mode = %o", unix_socket_mode);
	NOTICE("  unix_socket_uid = %d", unix_socket_uid);
	NOTICE("  unix_socket_gid = %d", unix_socket_gid);

	g_hash_table_destroy(params);
	return 1;
}

static void
usage(const char * prog_name)
{
	g_printerr("Usage: %s (--help|OPTIONS <path_config> <path_log>)\n", prog_name);
	g_printerr("OPTIONS:\n");
	g_printerr("  --help               : display this help section\n");
	g_printerr("  --child-req          : Starts a request agent.\n");
	g_printerr("  --child-evt=<NS>     : start a processus only repsonsible for the event requests\n");
}

static int
parse_options(int argc, char ** args, GError **error)
{
	static struct option long_options[] = {
		{"help",             0, 0, 1},
		{"child-req",        0, 0, 2},
		{"child-evt",        1, 0, 3},
		{"supervisor",       0, 0, 4},
		{0, 0, 0, 0}
	};

	if (argc<2) {
		g_printerr("Missing argument\n");
		usage(args[0]);
		exit(-1);
	}

	memset(str_opt_log, 0x00, sizeof(str_opt_log));
	memset(str_opt_config, 0x00, sizeof(str_opt_config));
	memset(ns_name, 0x00, sizeof(ns_name));

	log4c_init();

	for (;;) {
		int c, option_index;

		c = getopt_long_only(argc, args, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 1:
			flag_help = ~0;
			break;
		case 2:
			agent_type = PT_REQ;
			break;
		case 3:
			bzero(ns_name, sizeof(ns_name));
			g_strlcpy(ns_name, optarg, sizeof(ns_name)-1);
			agent_type = PT_EVT;
			break;
		case 4:
			agent_type = PT_SUPERV;
			break;
		case '?':
			break;
		default:
			GSETERROR(error,"Invalid option received %02X [%c]", c, c);
			return 0;
		}
	}

	if (flag_help) {
		usage(args[0]);
		exit(0);
	}

	if (optind+1 >= argc) {
		GSETERROR(error,"Configuration file missing (<config_file> and/or <log_config>)");
		return 0;
	}

	g_set_prgname(args[0]);
	g_strlcpy(str_opt_config, args[optind], sizeof(str_opt_config)-1);
	g_strlcpy(str_opt_log, args[optind+1], sizeof(str_opt_log)-1);

	log4c_load(str_opt_log);
	return parse_configuration(str_opt_config, error);
}

static void
set_system_limits(void)
{
	struct rlimit rl, rl_old;

	getrlimit(RLIMIT_STACK, &rl_old);
	rl.rlim_cur = rl.rlim_max = 1 << 20;
	if (-1 == setrlimit(RLIMIT_STACK, &rl))
		WARN("Failed to set stack-size limit to %ld, kept to %ld (%s)",
			rl.rlim_cur, rl_old.rlim_cur, strerror(errno));

	getrlimit(RLIMIT_NOFILE, &rl_old);
	rl.rlim_cur = rl.rlim_max = 32768;
	if (-1 == setrlimit(RLIMIT_NOFILE, &rl))
		WARN("Failed to set max-open-files limit to %ld, kept to %ld (%s)",
			rl.rlim_cur, rl_old.rlim_cur, strerror(errno));

	getrlimit(RLIMIT_CORE, &rl_old);
	rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
	if (-1 == setrlimit(RLIMIT_CORE, &rl))
		WARN("Failed to set core-file-size limit to %ld, kept to %ld (%s)",
			rl.rlim_cur, rl_old.rlim_cur, strerror(errno));
}

int
main(int argc, char **argv)
{
	GError *error = NULL;
	gint rc = 0;

	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);
	set_system_limits();

	if (!parse_options(argc, argv, &error)) {
		g_printerr("Failed to parse the program options : %s\n", gerror_get_message(error));
		g_error_free(error);
		return -1;
	}

	if (!parse_namespaces(&error)) {
		ERROR("An error occured while filling namespaces hash with cluster config : %s", gerror_get_message(error));
		g_printerr("An error occured while filling namespaces hash with cluster config : %s\n", gerror_get_message(error));
		free_agent_structures();
		return -1;
	}

	switch (agent_type) {
		case PT_SUPERV:
			rc = main_supervisor();
			break;
		case PT_EVT:
			rc = main_event(ns_name);
			break;
		case PT_REQ:
			rc = main_reqagent();
			break;
	}

	free_agent_structures();
	log4c_fini();
	return rc;
}

