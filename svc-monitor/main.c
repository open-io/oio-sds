/*
OpenIO SDS svc-monitor
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

#ifndef  G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.svc-monitor"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/resource.h>
#include <sys/stat.h>

#include <math.h>
#include <getopt.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#include <gridinit-utils.h>

#define CHILD_KEY "SVC"
#define DEFAULT_MONITOR_PERIOD 10

static char svc_id[1024] = {0,0,0};
static char svc_mon[4096] = {0,0,0};
static char svc_cmd[4096] = {0,0,0};

static GRegex *regex_tag = NULL;
static GRegex *regex_svc = NULL;

static volatile int flag_quiet = 0;
static volatile int flag_running = ~0;
static volatile int flag_reconfigure = 0;
static volatile int flag_restart_children = 0;
/* Should we restart children when they die, or should we die ourselves? */
static gboolean auto_restart_children = FALSE;
static gint monitor_period = DEFAULT_MONITOR_PERIOD;
static GSList *custom_tags = NULL;

static void
my_chomp(char *str)
{
	int len = strlen(str);
	if (!len)
		return;

	for (; len > 0 ;len--) {
		switch (str[len-1]) {
			case '\n':
			case '\t':
			case ' ':
			case '\r':
				str[len-1] = '\0';
				break;
			default:
				return;
		}
	}
}

static void
parse_output(const gchar *cmd, service_info_t *si)
{
	int fd;
	FILE *stream_in;
	gchar line[1024];
	gchar cmd_with_args[4096] = {0,0,0};

	g_snprintf(cmd_with_args, sizeof(cmd_with_args), "%s %s", cmd, svc_id);
	if (0 > (fd = command_get_pipe(cmd_with_args))) {
		GRID_WARN("Exec [%s] failed: %s", cmd_with_args, strerror(errno));
		return;
	}
	GRID_DEBUG("Exec [%s]", cmd_with_args);

	if (!(stream_in = fdopen(fd, "r"))) {
		GRID_WARN("fdopen failed: %s", strerror(errno));
		metautils_pclose(&fd);
		return;
	}

	while (!feof(stream_in) && !ferror(stream_in)) {
		GMatchInfo *mi = NULL;

		if (!fgets(line, sizeof(line), stream_in))
			break;

		/* chomp the line */
		my_chomp(line);

		if (!g_regex_match(regex_tag, line, 0, &mi)) {
			GRID_DEBUG("Unrecognized pattern for output line [%s]", line);
		} else {
			struct service_tag_s *tag;
			gchar *str_type, *str_name, *str_sub, *str_value;

			str_name = g_match_info_fetch(mi, 1);
			str_type = g_match_info_fetch(mi, 2);
			str_sub = g_match_info_fetch(mi, 3);
			str_value = g_match_info_fetch(mi, 4);

			if (!g_ascii_strcasecmp(str_type, "tag")) {
				tag = service_info_ensure_tag(si->tags, str_name);
				service_tag_set_value_string(tag, str_value);

				if (!g_ascii_strcasecmp(str_sub, "vol")) {
					service_tag_set_value_macro(
							service_info_ensure_tag (si->tags, "stat.space"),
							NAME_MACRO_SPACE_TYPE, str_value);
					service_tag_set_value_macro(
							service_info_ensure_tag (si->tags, "stat.io"),
							NAME_MACRO_IOIDLE_TYPE, str_value);
				}
			}
			else if (!g_ascii_strcasecmp(str_type, "stat")) {
				gdouble dval;

				dval = g_ascii_strtod(str_value, NULL);
				tag = service_info_ensure_tag(si->tags, str_name);
				service_tag_set_value_float(tag, dval);
			}

			g_free(str_value);
			g_free(str_sub);
			g_free(str_type);
			g_free(str_name);
		}
		g_match_info_free(mi);
	}

	fclose(stream_in);
}

static void
_add_custom_tags(service_info_t *si)
{
	struct service_tag_s *tag = NULL;
	for (GSList *cursor = custom_tags; cursor; cursor = cursor->next) {
		gchar **kv = cursor->data;
		tag = service_info_ensure_tag(si->tags, kv[0]);
		service_tag_set_value_string(tag, kv[1]);
	}
}

static void
monitor_get_status(const gchar *monitor_cmd, service_info_t *si)
{
	gchar *str_si;

	if (strlen(monitor_cmd) > 0) {
		GRID_TRACE("Collecting the service state");
		parse_output(monitor_cmd, si);
		str_si =  service_info_to_string(si);
		GRID_DEBUG("SVC state: %s", str_si);
		g_free(str_si);
	}
}

static int
init_srvinfo(const gchar *sid, service_info_t *si)
{
	GMatchInfo *mi = NULL;

	if (!g_regex_match(regex_svc, sid, 0, &mi)) {
		g_printerr("Unrecognized pattern for service id [%s]\n", sid);
		return -1;
	} else {
		gchar *str_ns, *str_type, *str_addr;

		str_ns = g_match_info_fetch(mi, 1);
		str_type = g_match_info_fetch(mi, 2);
		str_addr = g_match_info_fetch(mi, 3);
		g_free(mi);
		g_strlcpy(si->type, str_type, sizeof(si->type)-1);
		g_free(str_type);
		g_strlcpy(si->ns_name, str_ns, sizeof(si->ns_name)-1);
		g_free(str_ns);
		if (!l4_address_init_with_url(&(si->addr), str_addr, NULL)) {
			g_printerr("Invalid service address [%s]", str_addr);
			return -1;
		}

		g_free(str_addr);
	}

	if (!si->tags)
		si->tags = g_ptr_array_sized_new(6);

	service_tag_set_value_macro (
			service_info_ensure_tag (si->tags, "stat.cpu"),
			NAME_MACRO_CPU_TYPE, NULL);

	return 0;
}

static void
sighandler_supervisor(int s)
{
	switch (s) {
	case SIGUSR1:
		supervisor_children_killall(s);
		flag_reconfigure = TRUE;
		signal(s,sighandler_supervisor);
		return;
	case SIGUSR2:
		flag_restart_children = TRUE;
		signal(s,sighandler_supervisor);
		return;
	case SIGPIPE:
		signal(s,sighandler_supervisor);
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		flag_running = FALSE;
		signal(s,sighandler_supervisor);
		return;
	case SIGCHLD:
		if (0 < supervisor_children_catharsis(NULL, NULL))
			flag_restart_children = ~0;
		signal(s,sighandler_supervisor);
		return;
	}
}

static void
monitoring_loop(service_info_t *si)
{
	long jiffies = 0;
	GTimer *timer;
	GError *error = NULL;
	guint proc_count;

	timer = g_timer_new();
	monitor_get_status(svc_mon, si);
	_add_custom_tags(si);

	proc_count = supervisor_children_startall(NULL, NULL);
	GRID_DEBUG("First started %u processes", proc_count);

	while (flag_running) { /* main loop */

		if (flag_restart_children) {
			if (auto_restart_children) {
				supervisor_children_repair(CHILD_KEY);
				supervisor_children_enable(CHILD_KEY, TRUE);
				proc_count = supervisor_children_startall(NULL,NULL);

				GRID_DEBUG("Started %u processes", proc_count);
				flag_restart_children = !!proc_count;
			} else {
				GRID_DEBUG("One of my children died, I will die too (auto_restart_children=%d)", auto_restart_children);
				break;
			}
		}

		if (!flag_running)
			break;

		gdouble elapsed = g_timer_elapsed(timer, NULL);
		if (elapsed >= 1.0) {
			if (!((++jiffies) % monitor_period)) {
				monitor_get_status(svc_mon, si);
				_add_custom_tags(si);
			}
			if (!register_namespace_service(si, &error)) {
				GRID_WARN("Failed to register the service: %s", gerror_get_message(error));
				g_clear_error(&error);
			}
			g_timer_reset(timer);
			elapsed = 0.0;
		}

		g_usleep (1000000UL - ((gulong)elapsed));
	}

	supervisor_children_stopall(4);
	supervisor_children_catharsis(NULL, NULL);

	g_free(timer);
}

int
main(int argc, char ** argv)
{
	HC_PROC_INIT(argv,GRID_LOGLVL_INFO);

	int rc = 1;
	service_info_t *service = NULL;
	setenv("GS_DEBUG_ENABLE", "0", TRUE);

	supervisor_children_init();

	do {
		GError *err = NULL;
		regex_tag = g_regex_new("((stat|tag)\\.([^.=\\s]+))\\s*=\\s*(.*)",
				G_REGEX_CASELESS|G_REGEX_EXTENDED, 0, &err);
		if (!regex_tag) {
			FATAL("Cannot compile tag regex: %s", err->message);
			g_clear_error(&err);
			exit(-1);
		}
		regex_svc = g_regex_new("([^|]*)\\|([^|]*)\\|(.*)",
				G_REGEX_CASELESS, 0, &err);
		if (!regex_svc) {
			FATAL("Cannot compile svc regex: %s", err->message);
			g_clear_error(&err);
			exit(-1);
		}
	} while (0);

	static struct option long_options[] = {
		{"svc-id", 1, 0, 'i'},
		{"monitor", 1, 0, 'm'},
		{"svc-cmd", 1, 0, 'c'},
		{"syslog-id", 1, 0, 's'},
		{"auto-restart-children", 0, 0, 'a'},
		{"monitor-period", 1, 0, 'p'},
		{"no-tcp-check", 0, 0, 'n'},
		{"tag", 1, 0, 't'},
		{0, 0, 0, 0}
	};

	int c;
	int option_index = 0;
	gchar *optarg2 = NULL;
	gchar **kv = NULL;
	while (-1 != (c = getopt_long(argc, argv, "ac:i:m:np:s:t:",
			long_options, &option_index))) {
		switch (c) {
		case 'i':
			g_strlcpy(svc_id, optarg, sizeof(svc_id)-1);
			break;
		case 'm':
			g_strlcpy(svc_mon, optarg, sizeof(svc_mon)-1);
			break;
		case 'c':
			g_strlcpy(svc_cmd, optarg, sizeof(svc_cmd)-1);
			break;
		case 'n':
			kv = g_malloc0(3 * sizeof(gchar*));
			kv[0] = g_strdup("tag.agent_check");
			kv[1] = g_strdup("false");
			custom_tags = g_slist_prepend(custom_tags, kv);
			break;
		case 'a':
			auto_restart_children = TRUE;
			break;
		case 'p':
			monitor_period = strtoll(optarg, NULL, 10);
			break;
		case 's':
			g_strlcpy(syslog_id, optarg, sizeof(syslog_id)-1);
			break;
		case 't':
			if (!g_str_has_prefix(optarg, "tag."))
				optarg2 = g_strdup_printf("tag.%s", optarg);
			else
				optarg2 = g_strdup(optarg);
			kv = g_strsplit(optarg2, "=", 2);
			if (kv && g_strv_length(kv) == 2) {
				custom_tags = g_slist_prepend(custom_tags, kv);
			} else {
				g_printerr("Invalid tag, must contain '=': %s", optarg);
				g_strfreev(kv);
				kv = NULL;
			}
			g_free(optarg2);
			optarg2 = NULL;
			break;
		default:
			g_printerr("Unexpected option: %c\n", c);
			break;
		}
		option_index = 0;
	}

	if (argc <= 1 || strlen(svc_id) == 0 || strlen(svc_cmd) == 0) {
		g_printerr("Usage: %s\n", argv[0]);
		g_printerr("Mandatory options:\n");
		g_printerr("\t-i\t--svc-id <NS|type|ip:port>\n"
				"\t-c\t--svc-cmd </service/cmd/to/launch>\n\n"
				"Other options:\n"
				"\t-m\t--monitor </script/to/monitor>\n"
				"\t-p\t--monitor-period <seconds>\n"
				"\t-s\t--syslog-id <syslog-id>\n"
				"\t-t\t--tag <key=val>\n"
				"\t-a\t--auto-restart-children\n"
				"\t-n\t--no-tcp-check\n");
		return 1;
	}

	if (*syslog_id)
		logger_syslog_open();

	GError *error = NULL;
	if (!supervisor_children_register(CHILD_KEY, svc_cmd, &error)) {
		g_printerr("Child registration failure:\n\t%s\n", gerror_get_message(error));
		goto label_error;
	}

	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_THREAD_STACK, 8192 * 1024))
		GRID_WARN("Limit on thread stack size cannot be set: %s", strerror(errno));
	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_MAX_FILES, 32 * 1024))
		GRID_WARN("Limit on max opened files cannot be set: %s", strerror(errno));
	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_CORE_SIZE, -1))
		GRID_WARN("Limit on core file size cannot be set: %s", strerror(errno));

	supervisor_children_set_respawn(CHILD_KEY, FALSE);
	supervisor_children_set_working_directory(CHILD_KEY, "/tmp");
	supervisor_children_inherit_env(CHILD_KEY);

	service = g_malloc0(sizeof(service_info_t));
	if (0 != init_srvinfo(svc_id, service)) {
		g_printerr("Internal error: failed to init srvinfo\n");
		goto label_error;
	}

	stdin = freopen("/dev/null", "r", stdin);

	GRID_NOTICE("%s restarted, pid=%d", argv[0], getpid());

	signal(SIGQUIT, sighandler_supervisor);
	signal(SIGTERM, sighandler_supervisor);
	signal(SIGINT,  sighandler_supervisor);
	signal(SIGPIPE, sighandler_supervisor);
	signal(SIGUSR1, sighandler_supervisor);
	signal(SIGUSR2, sighandler_supervisor);
	signal(SIGCHLD, sighandler_supervisor);

	monitoring_loop(service);

	rc = 0;

label_error:
	g_slist_free_full(custom_tags, (GDestroyNotify) g_strfreev);
	service_info_clean(service);
	supervisor_children_cleanall();
	return rc;
}

