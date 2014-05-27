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

#include <gridinit-utils.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>

#define CHILD_KEY "SVC"
#define DEFAULT_MONITOR_PERIOD 10

static char svc_id[1024] = {0,0,0};
static char svc_mon[4096] = {0,0,0};
static char svc_cmd[4096] = {0,0,0};
static char log_path[1024] = {0,0,0};

static GRegex *regex_tag = NULL;
static GRegex *regex_svc = NULL;

static volatile int flag_quiet = 0;
static volatile int flag_daemon = 0;
static volatile int flag_running = ~0;
static volatile int flag_reconfigure = 0;
static volatile int flag_restart_children = 0;
/* Should we restart children when they die, or should we die ourselves? */
static gboolean auto_restart_children = FALSE;
static gint monitor_period = DEFAULT_MONITOR_PERIOD;

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
	INFO("Executing [%s]", cmd_with_args);
	if (0 > (fd = command_get_pipe(cmd_with_args))) {
		WARN("Exec failed : %s", strerror(errno));
		return;
	}

	if (!(stream_in = fdopen(fd, "r"))) {
		WARN("fdopen failed : %s", strerror(errno));
		metautils_pclose(&fd);
		return;
	}

	while (!feof(stream_in) && !ferror(stream_in)) {
		GMatchInfo *mi = NULL;

		bzero(line, sizeof(line));
		if (!fgets(line, sizeof(line), stream_in)) {
			break;
		}

		/* chomp the line */
		my_chomp(line);

		if (!g_regex_match(regex_tag, line, 0, &mi)) {
			NOTICE("Unrecognized pattern for output line [%s]", line);
		} else {
			struct service_tag_s *tag;
			gchar *str_type, *str_name, *str_value;

			str_name = g_match_info_fetch(mi, 1);
			str_type = g_match_info_fetch(mi, 2);
			str_value = g_match_info_fetch(mi, 4);

			if (!g_ascii_strcasecmp(str_type, "tag")) {
				tag = service_info_ensure_tag(si->tags, str_name);
				service_tag_set_value_string(tag, str_value);
			}
			else if (!g_ascii_strcasecmp(str_type, "stat")) {
				gdouble dval;

				dval = g_ascii_strtod(str_value, NULL);
				tag = service_info_ensure_tag(si->tags, str_name);
				service_tag_set_value_float(tag, dval);
			}

			g_free(str_value);
			g_free(str_type);
			g_free(str_name);
		}
		g_match_info_free(mi);
	}

	fclose(stream_in);
}

static void
monitor_get_status(const gchar *monitor_cmd, service_info_t *si)
{
	gchar *str_si;

	if (strlen(monitor_cmd) > 0) {
		TRACE("Collecting the service state");
		parse_output(monitor_cmd, si);
		str_si =  service_info_to_string(si);
		DEBUG("SVC state : %s", str_si);
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

	proc_count = supervisor_children_startall(NULL, NULL);
	DEBUG("First started %u processes", proc_count);

	for (;;) { /* main loop */
		struct timeval tv_sleep;

		if (flag_restart_children) {
			if (auto_restart_children) {
				supervisor_children_repair(CHILD_KEY);
				supervisor_children_enable(CHILD_KEY, TRUE);
				proc_count = supervisor_children_startall(NULL,NULL);

				DEBUG("Started %u processes", proc_count);
				flag_restart_children = !!proc_count;
			} else {
				DEBUG("One of my children died, I will die too (auto_restart_children=%d)", auto_restart_children);
				break;
			}
		}

		if (!flag_running)
			break;

		if (g_timer_elapsed(timer, NULL) >= 1.0) {
			if (!((++jiffies) % monitor_period))
				monitor_get_status(svc_mon, si);
			if (!register_namespace_service(si, &error)) {
				ERROR("Failed to register the service : %s", gerror_get_message(error));
				g_clear_error(&error);
			}
			g_timer_reset(timer);
		}

		tv_sleep.tv_sec = 1L;
		tv_sleep.tv_usec = 0L;
		select(0, NULL, NULL, NULL, &tv_sleep);
		errno = 0;
	}

	supervisor_children_stopall(4);
	supervisor_children_catharsis(NULL, NULL);

	g_free(timer);
}

static void
close_all_fd(void)
{
	rlim_t i;
	struct rlimit rl;

	memset(&rl, 0x00, sizeof(rl));
	if (0 != getrlimit(RLIMIT_NOFILE, &rl)) {
		ERROR("getrlimit(RLIMIT_NOFILE) error : %s", strerror(errno));
		return;
	}

	close(0);
	if (flag_daemon) {
		close(1);
		close(2);
	}

	DEBUG("Closing the %ld first descriptors", rl.rlim_max);
	for (i=3; i<rl.rlim_max ;i++)
		(void) close(i);
	errno = 0;
}

int
main(int argc, char ** argv)
{
	int rc = 1;
	service_info_t *service = NULL;

	supervisor_children_init();
	memset(log_path, 0x00, sizeof(log_path));

	do {
		GError *err = NULL;
		regex_tag = g_regex_new("((stat|tag)\\.([^.=\\s]+))\\s*=\\s*(.*)",
				G_REGEX_CASELESS|G_REGEX_EXTENDED, 0, &err);
		if (!regex_tag) {
			FATAL("Cannot compile tag regex : %s", err->message);
			g_clear_error(&err);
			exit(-1);
		}
		regex_svc = g_regex_new("([^|]*)\\|([^|]*)\\|(.*)",
				G_REGEX_CASELESS, 0, &err);
		if (!regex_svc) {
			FATAL("Cannot compile svc regex : %s", err->message);
			g_clear_error(&err);
			exit(-1);
		}
	} while (0);

	static struct option long_options[] = {
		{"svc-id", 1, 0, 0},
		{"monitor", 1, 0, 1},
		{"svc-cmd", 1, 0, 2},
		{"log4c", 1, 0, 3},
		{"auto-restart-children", 0, 0, 4},
		{"monitor-period", 1, 0, 5},
		{0, 0, 0, 0}
	};

	int c;
	int option_index = 0;
	while (-1 != (c = getopt_long(argc, argv, "", long_options, &option_index))) {
		switch (c) {
		case 0:
			g_strlcpy(svc_id, optarg, sizeof(svc_id)-1);
			break;
		case 1:
			g_strlcpy(svc_mon, optarg, sizeof(svc_mon)-1);
			break;
		case 2:
			g_strlcpy(svc_cmd, optarg, sizeof(svc_cmd)-1);
			break;
		case 3:
			g_strlcpy(log_path, optarg, sizeof(log_path)-1);
			break;
		case 4:
			auto_restart_children = TRUE;
			break;
		case 5:
			monitor_period = strtoll(optarg, NULL, 10);
			break;
		default:
			g_printerr("Unexpected option : %c\n", c);
			break;
		}
		option_index = 0;
	}

	if (argc <= 1 || strlen(svc_id) == 0 || strlen(svc_cmd) == 0) {
		g_printerr("Usage: %s --svc-id <NS|type|ip:port> --svc-cmd /service/cmd/to/launch\n"
				"\t[--monitor /script/to/monitor] [--monitor-period <seconds>]\n"
				"\t[--log4c /path/to/log4crc] [--auto-restart-children]\n",
				argv[0]);
		return 1;
	}

	GError *error = NULL;
	if (!supervisor_children_register(CHILD_KEY, svc_cmd, &error)) {
		g_printerr("Child registration failure :\n\t%s\n", gerror_get_message(error));
		goto label_error;
	}

	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_THREAD_STACK, 8192 * 1024))
		WARN("Limit on thread stack size cannot be set : %s", strerror(errno));
	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_MAX_FILES, 32 * 1024))
		WARN("Limit on max opened files cannot be set : %s", strerror(errno));
	if (0 != supervisor_children_set_limit(CHILD_KEY, SUPERV_LIMIT_CORE_SIZE, -1))
		WARN("Limit on core file size cannot be set : %s", strerror(errno));

	supervisor_children_set_respawn(CHILD_KEY, FALSE);
	supervisor_children_set_working_directory(CHILD_KEY, "/tmp");

	service = g_malloc0(sizeof(service_info_t));
	if (0 != init_srvinfo(svc_id, service)) {
		g_printerr("Internal error : failed to init srvinfo\n");
		goto label_error;
	}

	close_all_fd();

	log4c_init();
	if (*log_path)
		log4c_load(log_path);

	NOTICE("%s restarted, pid=%d", argv[0], getpid());

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
	service_info_clean(service);
	supervisor_children_cleanall();
	return rc;
}

