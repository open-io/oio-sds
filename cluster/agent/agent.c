/*
OpenIO SDS cluster
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

#include <syslog.h>

#include <metautils/lib/metautils.h>

#include <cluster/lib/gridcluster.h>
#include <cluster/conscience/conscience.h>
#include <cluster/module/module.h>

#include "./agent.h"
#include "./cpu_stat_task_worker.h"
#include "./gridagent.h"
#include "./io_scheduler.h"
#include "./io_stat_task_worker.h"
#include "./namespace_get_task_worker.h"
#include "./request_worker.h"
#include "./services_workers.h"
#include "./server.h"
#include "./task_scheduler.h"

/* GLOBALS */

gchar syslog_id[64] = "";
gchar str_opt_config[512] = "";
GHashTable *namespaces = NULL;

gboolean gridagent_blank_undefined_srvtags = TRUE;

/* config for networking */
int inet_socket_backlog = INET_DEFAULT_BACKLOG;
int inet_socket_timeout = INET_DEFAULT_TIMEOUT;
int inet_socket_port = INET_DEFAULT_PORT;

gchar unix_socket_path[512] = UNIX_DEFAULT_PATH;
int unix_socket_timeout = UNIX_DEFAULT_TIMEOUT;
int unix_socket_backlog = UNIX_DEFAULT_BACKLOG;
int unix_socket_mode = UNIX_DEFAULT_MODE;
int unix_socket_uid = UNIX_DEFAULT_UID;
int unix_socket_gid = UNIX_DEFAULT_GID;

/* config for periodic tasks */
gboolean flag_check_services = DEFAULT_SVC_CHECK;
int period_check_services = DEFAULT_SVC_CHECK_FREQ;

int period_get_evtconfig = DEFAULT_CS_UPDATE_FREQ;
int period_get_ns = DEFAULT_CS_UPDATE_FREQ;
int period_get_srvtype = DEFAULT_CS_UPDATE_FREQ;
int period_get_srvlist = DEFAULT_CS_UPDATE_FREQ;
int period_push_srvlist = DEFAULT_CS_UPDATE_FREQ;

/* ------------------------------------------------------------------------- */

static int flag_help = FALSE;
static gchar ns_name[LIMIT_LENGTH_NSNAME];

/* ------------------------------------------------------------------------- */

static void
destroy_namespace_data(gpointer p)
{
	struct namespace_data_s *ns_data;

	if (!p)
		return;
	ns_data = p;

	if (ns_data->conscience)
		conscience_destroy(ns_data->conscience);
	if (ns_data->local_services)
		g_hash_table_destroy(ns_data->local_services);
	if (ns_data->down_services)
		g_hash_table_destroy(ns_data->down_services);

	memset(ns_data, 0x00, sizeof(struct namespace_data_s));
	g_free(ns_data);
}

static struct namespace_data_s *
create_namespace_data(const gchar * ns)
{
	struct namespace_data_s *ns_data = g_malloc0(sizeof(struct namespace_data_s));

	ns_data->configured = FALSE;

	namespace_info_init (&ns_data->ns_info);
	metautils_strlcpy_physical_ns(ns_data->name, ns,
			sizeof(ns_data->name));
	metautils_strlcpy_physical_ns(ns_data->ns_info.name, ns,
			sizeof(ns_data->ns_info.name));

	ns_data->conscience = conscience_create();
	namespace_info_copy(&(ns_data->ns_info), &(ns_data->conscience->ns_info), NULL);

	ns_data->local_services = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) service_info_clean);
	ns_data->down_services = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, (GDestroyNotify) service_info_clean);

	return ns_data;
}

static struct namespace_data_s *
ensure_namespace_data(const gchar * ns)
{
	namespace_data_t *ns_data = g_hash_table_lookup(namespaces, ns);
	if (!ns_data) {
		ns_data = create_namespace_data(ns);
		g_hash_table_insert(namespaces, g_strdup(ns), ns_data);
	}
	return ns_data;
}

void
parse_namespaces(void)
{
	GHashTableIter iterator;
	gpointer k, v;
	GHashTable *ns_hash = oio_cfg_parse();

	g_hash_table_iter_init(&iterator, ns_hash);
	while (g_hash_table_iter_next(&iterator, &k, &v)) {
		const gchar *sk = (gchar*) k;
		if (g_str_has_prefix(sk, "default/"))
			continue;
		if (!g_str_has_suffix(sk, "/conscience"))
			continue;

		const gchar *cs = (gchar*) v;
		addr_info_t addr;
		grid_string_to_addrinfo(cs, NULL, &addr);

		gchar *ns = g_strndup(sk, strrchr(sk,'/') - sk);
		namespace_data_t *ns_data = ensure_namespace_data(ns);
		memcpy(&ns_data->addr, &addr, sizeof(addr_info_t));
		g_free(ns);
	}

	g_hash_table_destroy(ns_hash);
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
default_configuration ()
{
	memset(str_opt_config, 0x00, sizeof(str_opt_config));
	memset(ns_name, 0x00, sizeof(ns_name));

	namespaces = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, destroy_namespace_data);
}

static int
change_user(const char *user_name, const char *group_name, GError ** error)
{
	char *end = NULL;
	long l;
	uid_t uid;
	gid_t gid;

	end = NULL;
	l = strtoll(user_name, &end, 10);
	if (l < 0 || (end && *end)) {
		struct passwd *pwd = getpwnam(user_name);
		if (pwd == NULL) {
			GSETERROR(error, "User [%s] not found in /etc/passwd", user_name);
			return (0);
		}
		uid = pwd->pw_uid;
	} else {
		uid = l;
	}

	end = NULL;
	l = strtoll(group_name, &end, 10);
	if (l < 0 || (end && *end)) {
		struct group *grp = getgrnam(group_name);
		if (grp == NULL) {
			GSETERROR(error, "Group [%s] not found in /etc/group", group_name);
			return (0);
		}
		gid = grp->gr_gid;
	} else {
		gid = l;
	}

	if (setgid(gid) < 0) {
		GSETERROR(error, "Failed to switch group to [%s] : %s", group_name, strerror(errno));
		return (0);
	}

	if (setuid(uid) < 0) {
		GSETERROR(error, "Failed to switch user to [%s] : %s", user_name, strerror(errno));
		return (0);
	}

	return (1);
}

static int
parse_configuration(const gchar *config, GError **error)
{
	GKeyFile *key_file;

	/* helpers */
	void getstr(gchar *dst, gsize dstlen,
			const gchar *g, const gchar *n, const gchar *def) {
		if (!g_key_file_has_key(key_file, g, n, NULL))
			g_strlcpy(dst, def, dstlen);
		else {
			gchar *str = g_key_file_get_value(key_file, g, n, NULL);
			g_strlcpy(dst, str, dstlen);
			g_free(str);
		}
	}
	int getint(const gchar *g, const gchar *n, int def) {
		if (!g_key_file_has_key(key_file, g, n, NULL))
			return def;
		gchar *str = g_key_file_get_value(key_file, g, n, NULL);
		gint64 i64 = g_ascii_strtoll(str, NULL, 0);
		g_free(str);
		return i64;
	}
	gboolean getbool(const gchar *g, const gchar *n, gboolean def) {
		if (!g_key_file_has_key(key_file, g, n, NULL))
			return def;
		gchar *str = g_key_file_get_value(key_file, g, n, NULL);
		gboolean b = metautils_cfg_get_bool(str, def);
		g_free(str);
		return b;
	}

	key_file = g_key_file_new();
	if (!g_key_file_load_from_file(key_file, config, 0, error)) {
		GSETERROR(error, "Failed to load key file %s", config);
		g_key_file_free(key_file);
		return 0;
	}

	gchar user[128], group[128];

	/* main configuration */
	getstr(user, sizeof(user), SECTION_GENERAL, KEY_USER, "");
	getstr(group, sizeof(group), SECTION_GENERAL, KEY_GROUP, "");

	flag_check_services = getbool(SECTION_GENERAL, SVC_CHECK_KEY,
			DEFAULT_SVC_CHECK);
	period_check_services = getint(SECTION_GENERAL, SVC_CHECK_FREQ_KEY,
			DEFAULT_SVC_CHECK_FREQ);
	gridagent_blank_undefined_srvtags = getbool(SECTION_GENERAL, SVC_PUSH_BLANK_KEY,
			DEFAULT_SVC_PUSH_BLANK);

	/* networking config */
	inet_socket_port = getint(SECTION_SERVER_INET, KEY_PORT,
			INET_DEFAULT_PORT);
	inet_socket_backlog = getint(SECTION_SERVER_INET, KEY_BACKLOG,
			INET_DEFAULT_BACKLOG);
	inet_socket_timeout = getint(SECTION_SERVER_INET, KEY_TIMEOUT,
			INET_DEFAULT_TIMEOUT);

	unix_socket_gid = getint(SECTION_SERVER_UNIX, KEY_GID,
			UNIX_DEFAULT_GID);
	unix_socket_uid = getint(SECTION_SERVER_UNIX, KEY_UID,
			UNIX_DEFAULT_UID);
	unix_socket_mode = getint(SECTION_SERVER_UNIX, KEY_MODE,
			UNIX_DEFAULT_MODE);
	unix_socket_backlog = getint(SECTION_SERVER_UNIX, KEY_BACKLOG,
			UNIX_DEFAULT_BACKLOG);
	unix_socket_timeout = getint(SECTION_SERVER_UNIX, KEY_TIMEOUT,
			UNIX_DEFAULT_TIMEOUT);
	getstr(unix_socket_path, sizeof(unix_socket_path),
			SECTION_SERVER_UNIX, KEY_PATH, "");

	/* finer tuning */
	int def = getint(SECTION_GENERAL, CS_DEFAULT_FREQ_KEY, DEFAULT_CS_UPDATE_FREQ);
	period_get_ns = getint(SECTION_GENERAL, CS_GET_NS_PERIOD_KEY, def);
	period_get_srvtype = getint(SECTION_GENERAL, CS_GET_SRVTYPE_PERIOD_KEY, def);
	period_get_srvlist = getint(SECTION_GENERAL, CS_GET_SRVLIST_PERIOD_KEY, def);
	period_push_srvlist = getint(SECTION_GENERAL, CS_PUSH_SRVLIST_PERIOD_KEY, def);

	g_key_file_free(key_file);
	key_file = NULL;

	GRID_NOTICE("general.user = [%s]", user);
	GRID_NOTICE("general.group = [%s]", group);
	GRID_NOTICE("general.Check service = %s", flag_check_services ? "ON" : "OFF");
	GRID_NOTICE("general.period_check_services = %d", period_check_services);
	GRID_NOTICE("inet.port = %d", inet_socket_port);
	GRID_NOTICE("inet.backlog = %d", inet_socket_backlog);
	GRID_NOTICE("inet.timeout = %d", inet_socket_timeout);
	GRID_NOTICE("unix.mode = %o", unix_socket_mode);
	GRID_NOTICE("unix.uid = %d", unix_socket_uid);
	GRID_NOTICE("unix.gid = %d", unix_socket_gid);
	GRID_NOTICE("unix.backlog = %d", unix_socket_backlog);
	GRID_NOTICE("unix.timeout = %d", unix_socket_timeout);
	GRID_NOTICE("unix.path = [%s]", unix_socket_path);
	GRID_NOTICE("services.default_period = %d", def);
	GRID_NOTICE("services.period_get_ns = %d", period_get_ns);
	GRID_NOTICE("services.period_get_srvtype = %d", period_get_srvtype);
	GRID_NOTICE("services.period_get_srvlist = %d", period_get_srvlist);
	GRID_NOTICE("services.period_push_srvlist = %d", period_push_srvlist);

	if (*user && *group && !change_user(user, group, error)) {
		GSETERROR(error,"Failed to change user");
		return 0;
	}

	return 1;
}

static void
usage(const char * prog_name)
{
	g_printerr("Usage: %s (--help|OPTIONS <path_config> <path_log>)\n", prog_name);
	g_printerr("OPTIONS:\n");
	g_printerr("  --help               : display this help section\n");
}

static int
parse_options(int argc, char ** args, GError **error)
{
	static struct option long_options[] = {
		{"syslog",           1, 0, 's'},
		{"verbose",          0, 0, 'v'},
		{"quiet",            0, 0, 'q'},
		{"help",             0, 0, 1},
		{0, 0, 0, 0}
	};

	if (argc<2) {
		g_printerr("Missing argument\n");
		usage(args[0]);
		exit(-1);
	}

	default_configuration();

	for (;;) {
		int c, option_index;

		c = getopt_long_only(argc, args, "", long_options, &option_index);
		if (c == -1)
			break;
		switch (c) {
		case 1:
			flag_help = ~0;
			break;
		case 's':
			g_strlcpy(syslog_id, optarg, sizeof(syslog_id));
			break;
		case 'v':
			oio_log_verbose();
			break;
		case 'q':
			oio_log_quiet();
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

	if (*syslog_id) {
		g_log_set_default_handler(oio_log_syslog, NULL);
		openlog(syslog_id, LOG_NDELAY, LOG_LOCAL0);
	}

	if (optind >= argc) {
		GSETERROR(error,"Configuration file missing (<config_file> and/or <log_config>)");
		return 0;
	}

	g_strlcpy(str_opt_config, args[optind], sizeof(str_opt_config)-1);
	return parse_configuration(str_opt_config, error);
}

int
main(int argc, char **argv)
{
	GError *error = NULL;
	gint rc = 0;

	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);

	if (!parse_options(argc, argv, &error)) {
		g_printerr("Failed to parse the program options : %s\n", gerror_get_message(error));
		g_error_free(error);
		return -1;
	}

	parse_namespaces();
	rc = main_reqagent();
	free_agent_structures();
	return rc;
}

