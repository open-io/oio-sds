/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <metautils/lib/common_variables.h>

#include "metautils.h"
#include "common_main.h"

char syslog_id[64] = "";
static volatile gint64 main_log_level_update = 0;

static int syslog_opened = 0;
static int grid_main_rc = 0;
static volatile gboolean flag_running = FALSE;
static volatile gboolean flag_daemon = FALSE;
static volatile gboolean flag_quiet = FALSE;
static volatile gboolean flag_dump_options = FALSE;

static struct grid_main_callbacks *user_callbacks;
static volatile gboolean pidfile_written = FALSE;
static gchar pidfile_path[1024] = {0,0,0};
static struct stat pidfile_stat;

static gchar errbuff[1024];

#define ERR(FMT,...) do { \
	g_snprintf(errbuff, sizeof(errbuff), FMT, ##__VA_ARGS__); \
	return errbuff; \
} while (0)

/* ------------------------------------------------------------------------- */

void
logger_syslog_open (void)
{
	if (syslog_opened)
		return;
	syslog_opened = 1;
	openlog(syslog_id, LOG_NDELAY, LOG_LOCAL0);
	g_log_set_default_handler(oio_log_syslog, NULL);
}

static const char*
_set_config_option(struct grid_main_option_s *opt, gchar **tokens)
{
	gint64 i64 = 0;

	if (tokens[1] == NULL && opt->type != OT_BOOL)
		ERR("Missing parameter, expected '%s=<Value>'", tokens[0]);

	switch (opt->type) {
		case OT_BOOL:
			if (tokens[1] == NULL) {
				*(opt->data.b) = TRUE;
				return NULL;
			}
			*(opt->data.b) = oio_str_parse_bool(tokens[1], *(opt->data.b));
			return NULL;
		case OT_INT:
			i64 = 0;
			if (!oio_str_is_number(tokens[1], &i64))
				ERR("Invalid integer parameter");
			if (i64 < G_MININT || i64 > G_MAXINT)
				ERR("Invalid parameter range");
			*(opt->data.i) = i64;
			return NULL;
		case OT_UINT:
			i64 = 0;
			if (!oio_str_is_number(tokens[1], &i64))
				ERR("Invalid integer parameter");
			if (i64 < 0 || i64 > G_MAXUINT)
				ERR("Invalid parameter range");
			*(opt->data.u) = i64;
			return NULL;
		case OT_INT64:
			i64 = g_ascii_strtoll(tokens[1], NULL, 10);
			*(opt->data.i64) = i64;
			return NULL;
		case OT_TIME:
			i64 = g_ascii_strtoll(tokens[1], NULL, 10);
			*(opt->data.t) = i64;
			return NULL;
		case OT_DOUBLE:
			*(opt->data.d) = g_ascii_strtod(tokens[1], NULL);
			return NULL;
		case OT_STRING:
			if (!*(opt->data.str))
				*(opt->data.str) = g_string_new("");
			g_string_set_size(*(opt->data.str), 0);
			g_string_append(*(opt->data.str), tokens[1]);
			return NULL;
		case OT_LIST:
			*(opt->data.lst) = g_slist_prepend(*(opt->data.lst), g_strdup(tokens[1]));
			return NULL;
		default:
			ERR("Invalid option type, possible corruption");
	}
}

static const char*
_set_fixed_opt(gchar **tokens)
{
	errbuff[0] = '\0';

	if (!tokens || tokens[0] == NULL)
		ERR("Invalid option format, expected 'Key=Value'");

	for (struct grid_main_option_s *opt=user_callbacks->options();
		 opt && opt->name;
		 opt++) {
		if (0 == g_ascii_strcasecmp(opt->name, tokens[0]))
			return _set_config_option(opt, tokens);
	}

	if (oio_var_value_one_with_option(tokens[0], tokens[1]))
		return NULL;

	ERR("Option '%s' not supported", tokens[0]);
}

static const char*
grid_main_set_option(const gchar *str_opt)
{
	gchar **tokens;
	const gchar *result;

	tokens = g_strsplit(str_opt, "=", 2);
	result = _set_fixed_opt(tokens);
	if (tokens)
		g_strfreev(tokens);
	return result;
}

static void
_dump_extra_options(void)
{
	gchar name[256];
	struct grid_main_option_s *o;

	if (flag_quiet)
		return;

	for (o=user_callbacks->options(); o && o->name ;o++) {
		switch (o->type) {
			case OT_BOOL:
				g_snprintf(name, sizeof(name), "%s=%s", o->name, (*(o->data.b)?"on":"off"));
				break;
			case OT_INT:
				g_snprintf(name, sizeof(name), "%s=%d", o->name, *(o->data.i));
				break;
			case OT_UINT:
				g_snprintf(name, sizeof(name), "%s=%u", o->name, *(o->data.u));
				break;
			case OT_INT64:
				g_snprintf(name, sizeof(name), "%s=%"G_GINT64_FORMAT, o->name, *(o->data.i64));
				break;
			case OT_TIME:
				g_snprintf(name, sizeof(name), "%s=%ld", o->name, *(o->data.t));
				break;
			case OT_DOUBLE:
				g_snprintf(name, sizeof(name), "%s=%f", o->name, *(o->data.d));
				break;
			case OT_STRING:
				do {
					GString *str = *(o->data.str);
					g_snprintf(name, sizeof(name), "%s=%s", o->name, str ? str->str : NULL);
				} while (0);
				break;
			case OT_LIST:
				g_snprintf(name, sizeof(name), "%s", o->name);
				break;
		}
		g_printerr("\t%s\n\t\t%s\n", name, o->descr);
	}
}

static void
_on_option__dump_to_stdout(const char *k, const char *v)
{
	g_print("%s=%s\n", k, v);
}

static void
_dump_config_options(void)
{
	if (flag_quiet)
		return;
	oio_var_list_all(_on_option__dump_to_stdout);
}

static void
grid_main_usage(void)
{
	if (flag_quiet)
		return;

	g_printerr("Usage: %s [OPTIONS...] EXTRA_ARGS\n", g_get_prgname());

	g_printerr("\nOPTIONS:\n");
	g_printerr("  -h         help, displays this section\n");
	g_printerr("  -c         instead of starting the server, it dumps the current lve central configurable variables\n");
	g_printerr("  -d         daemonizes the process (default FALSE)\n");
	g_printerr("  -q         quiet mode, supress output on stdout stderr \n");
	g_printerr("  -v         verbose mode, this activates stderr traces (default FALSE)\n");
	g_printerr("  -p PATH    pidfile path, no pidfile if unset\n");
	g_printerr("  -s TOKEN   activates syslog traces (default FALSE)\n"
			   "             with the given identifier\n");
	g_printerr("  -O XOPT    set extra options.\n");

	g_printerr("\nXOPT'S with default value:\n");
	_dump_extra_options();

	g_printerr("\nEXTRA_ARGS usage:\n%s\n", user_callbacks->usage());
}

static void
grid_main_cli_usage(void)
{
	if (flag_quiet)
		return;

	g_printerr("Usage: %s [OPTIONS...] EXTRA_ARGS\n", g_get_prgname());

	g_printerr("\nOPTIONS:\n");
	g_printerr("  -h         help, displays this section\n");
	g_printerr("  -c         instead of starting the server, it dumps the current lve central configurable variables\n");
	g_printerr("  -q         quiet mode, supress output on stdout stderr \n");
	g_printerr("  -v         verbose mode, this activates stderr traces (default FALSE)\n");
	g_printerr("  -O XOPT    set extra options.\n");

	g_printerr("\nXOPT'S with default value:\n");
	_dump_extra_options();

	g_printerr("\nEXTRA_ARGS usage:\n%s\n", user_callbacks->usage());
}

static void
_signal_block(int s)
{
	sigset_t new_set, old_set;
	sigemptyset(&new_set);
	sigemptyset(&old_set);
	sigaddset(&new_set, s);
	pthread_sigmask(SIG_BLOCK, &new_set, &old_set);
	sigprocmask(SIG_BLOCK, &new_set, &old_set);
}

static void
_signal_ignore(int s)
{
	struct sigaction sa = {{0}}, saold = {{0}};
	sigaddset(&sa.sa_mask, s);
	sa.sa_handler = SIG_IGN;
	sigaction(s, &sa, &saold);
}

static void
grid_main_sighandler_exception(int s)
{
	(void) s;
	grid_main_set_status(-1);
	grid_main_stop();
	_signal_block(s);
	_signal_ignore(s);
	sleep(3);
}

static void
grid_main_sighandler_stop(int s)
{
	grid_main_stop();
	signal(s, grid_main_sighandler_stop);
}

static void
grid_main_sighandler_USR1(int s)
{
	oio_log_verbose();
	main_log_level_update = oio_ext_monotonic_time ();
	alarm(900);
	signal(s, grid_main_sighandler_USR1);
}

static void
grid_main_sighandler_USR2(int s)
{
	oio_log_reset_level();
	main_log_level_update = 0;
	signal(s, grid_main_sighandler_USR2);
}

static void
grid_main_sighandler_ALRM(int s)
{
	gint64 now = oio_ext_monotonic_time();
	signal(s, grid_main_sighandler_ALRM);
	if (!main_log_level_update ||
			now > (main_log_level_update + main_log_level_reset_delay)) {
		oio_log_reset_level();
		main_log_level_update = 0;
	}
}

static void
grid_main_install_sighandlers(void)
{
	signal(SIGHUP,  grid_main_sighandler_stop);
	signal(SIGINT,  grid_main_sighandler_stop);
	signal(SIGQUIT, grid_main_sighandler_stop);
	signal(SIGTERM, grid_main_sighandler_stop);

	signal(SIGFPE,  grid_main_sighandler_exception);

	signal(SIGPIPE, SIG_IGN);
	signal(SIGUSR1, grid_main_sighandler_USR1);
	signal(SIGUSR2, grid_main_sighandler_USR2);
	signal(SIGALRM, grid_main_sighandler_ALRM);
}

static void
grid_main_write_pid_file(void)
{
	FILE *stream_pidfile;

	if (!*pidfile_path)
		return ;

	stream_pidfile = fopen(pidfile_path, "w+");
	if (!stream_pidfile)
		return ;

	fprintf(stream_pidfile, "%d", getpid());
	fclose(stream_pidfile);

	stat(pidfile_path, &pidfile_stat);
	pidfile_written = TRUE;
}

static void
grid_main_delete_pid_file(void)
{
	struct stat current_pidfile_stat;

	if (!pidfile_written) {
		GRID_DEBUG("No pidfile to delete");
		return;
	}
	if (-1 == stat(pidfile_path, &current_pidfile_stat)) {
		GRID_WARN("Unable to remove pidfile at [%s] : %s", pidfile_path, strerror(errno));
		return;
	}
	if (current_pidfile_stat.st_ino != pidfile_stat.st_ino) {
		GRID_WARN("Current and old pidfile differ, it is unsafe to delete it");
		return;
	}

	if (-1 == metautils_syscall_unlink(pidfile_path))
		GRID_WARN("Failed to unlink [%s] : %s", pidfile_path, strerror(errno));
	else {
		GRID_INFO("Deleted [%s]", pidfile_path);
		pidfile_written = FALSE;
	}
}

void
grid_main_set_prgname(const gchar *cmd)
{
	EXTRA_ASSERT(cmd != NULL);
	gchar *bn = g_path_get_basename(cmd);
	g_set_prgname(bn);
	g_free(bn);
}

static gboolean
grid_main_init(int argc, char **args)
{
	memset(syslog_id, 0, sizeof(syslog_id));
	memset(pidfile_path, 0, sizeof(pidfile_path));

	for (;;) {
		int c = getopt(argc, args, "O:hdvcqp:s:");
		if (c == -1)
			break;
		switch (c) {
			case 'O':
				do {
					const char *errmsg = grid_main_set_option(optarg);
					if (errmsg) {
						GRID_WARN("Invalid option : %s", errmsg);
						grid_main_usage();
						return FALSE;
					}
				} while (0);
				break;
			case 'd':
				flag_daemon = TRUE;
				break;
			case 'h':
				grid_main_usage();
				exit(0);
				break;
			case 'p':
				memset(pidfile_path, 0, sizeof(pidfile_path));
				if (sizeof(pidfile_path) <= g_strlcpy(pidfile_path, optarg, sizeof(pidfile_path)-1)) {
					GRID_WARN("Invalid '-p' argument : too long");
					grid_main_usage();
					return FALSE;
				}
				GRID_DEBUG("Explicitely configured pidfile_path=[%s]", pidfile_path);
				break;
			case 'q':
				oio_log_quiet();
				flag_quiet = TRUE;
				break;
			case 's':
				memset(syslog_id, 0, sizeof(syslog_id));
				if (sizeof(syslog_id) <= g_strlcpy(syslog_id, optarg, sizeof(syslog_id)-1)) {
					GRID_WARN("Invalid '-s' argument : too long");
					grid_main_usage();
					return FALSE;
				}
				GRID_DEBUG("Explicitely configured syslog_id=[%s]", syslog_id);
				break;
			case 'c':
				flag_dump_options = TRUE;
				break;
			case 'v':
				if (!flag_quiet) {
					oio_log_verbose_default();
					main_log_level_update = oio_ext_monotonic_time ();
				}
				break;
			case ':':
				GRID_WARN("Unexpected option at position %d ('%c')", optind, optopt);
				return FALSE;
			default:
				GRID_WARN("Unknown option at position %d ('%c')", optind, optopt);
				return FALSE;
		}
	}

	if (*syslog_id) {
		GRID_DEBUG("Opening syslog with id [%s]", syslog_id);
		logger_syslog_open();
	}

	flag_running = TRUE;

	if (!user_callbacks->configure(argc-optind, args+optind)) {
		flag_running = FALSE;
		GRID_WARN("User init error");
		return FALSE;
	}

	GRID_DEBUG("Process initiation successful");
	return TRUE;
}

static void
grid_main_fini(void)
{
	metautils_ignore_signals();
	user_callbacks->specific_fini();
	grid_main_delete_pid_file();
	GRID_DEBUG("Exiting");
}

void
grid_main_stop(void)
{
	flag_running = FALSE;
	user_callbacks->specific_stop();
}

gboolean
grid_main_is_running(void)
{
	return flag_running;
}

#define CHECK_CALLBACKS(CB) do { \
	EXTRA_ASSERT((CB) != NULL); \
	EXTRA_ASSERT((CB)->options != NULL); \
	EXTRA_ASSERT((CB)->action != NULL); \
	EXTRA_ASSERT((CB)->set_defaults != NULL); \
	EXTRA_ASSERT((CB)->specific_fini != NULL); \
	EXTRA_ASSERT((CB)->configure != NULL); \
	EXTRA_ASSERT((CB)->usage != NULL); \
	EXTRA_ASSERT((CB)->specific_stop != NULL); \
} while (0)

int
grid_main(int argc, char ** argv, struct grid_main_callbacks * callbacks)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);
	CHECK_CALLBACKS(callbacks);
	user_callbacks = callbacks;
	user_callbacks->set_defaults();

	if (!grid_main_init(argc, argv)) {
		grid_main_usage();
		return -1;
	}
	grid_main_install_sighandlers();

	if (flag_dump_options) {
		_dump_config_options();
	} else {

		if (flag_daemon || *syslog_id) {
			stdout = freopen("/dev/null", "w", stdout);
			stderr = freopen("/dev/null", "w", stderr);
		}

		if (flag_daemon) {
			stdin = freopen("/dev/null", "r", stdin);
			if (-1 == daemon(1,0)) {
				GRID_WARN("daemonize error : %s", strerror(errno));
				grid_main_fini();
				return 1;
			}
			grid_main_write_pid_file();
		}

		grid_main_install_sighandlers();
		if (flag_running)
			user_callbacks->action();
	}

	grid_main_fini();
	return grid_main_rc;
}

static gboolean
grid_main_cli_init(int argc, char **args)
{
	memset(syslog_id, 0, sizeof(syslog_id));
	memset(pidfile_path, 0, sizeof(pidfile_path));

	for (;;) {
		int c = getopt(argc, args, "O:hvq");
		if (c == -1)
			break;
		switch (c) {
			case 'O':
				do {
					const char *errmsg = grid_main_set_option(optarg);
					if (errmsg) {
						GRID_WARN("Invalid option : %s", errmsg);
						grid_main_cli_usage();
						return FALSE;
					}
				} while (0);
				break;
			case 'h':
				grid_main_cli_usage();
				exit(0);
				break;
			case 'q':
				oio_log_quiet();
				flag_quiet = TRUE;
				break;
			case 'v':
				if (!flag_quiet)
					oio_log_verbose_default();
				break;
			case 'c':
				flag_dump_options = TRUE;
				break;
			case ':':
				GRID_WARN("Unexpected option at position %d ('%c')", optind, optopt);
				return FALSE;
			default:
				GRID_WARN("Unknown option at position %d ('%c')", optind, optopt);
				return FALSE;
		}
	}

	flag_running = TRUE;

	if (!user_callbacks->configure(argc-optind, args+optind)) {
		flag_running = FALSE;
		GRID_DEBUG("User init error");
		return FALSE;
	}

	GRID_DEBUG("Process initiation successful");
	return TRUE;
}

int
grid_main_cli(int argc, char ** argv, struct grid_main_callbacks * callbacks)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_INFO);
	CHECK_CALLBACKS(callbacks);
	user_callbacks = callbacks;
	user_callbacks->set_defaults();

	if (!grid_main_cli_init(argc, argv)) {
		grid_main_cli_usage();
		return -1;
	}
	grid_main_install_sighandlers();

	if (flag_dump_options)
		_dump_config_options();
	else if (flag_running)
		user_callbacks->action();

	metautils_ignore_signals();
	user_callbacks->specific_fini();
	return grid_main_rc;
}

void
metautils_ignore_signals(void)
{
	sigset_t new_set;

	sigfillset(&new_set);
	if (0 != sigprocmask(SIG_BLOCK, &new_set, NULL))
		g_message("LIBC Some signals could not be blocked : %s", strerror(errno));

	sigfillset(&new_set);
	if (0 != pthread_sigmask(SIG_BLOCK, &new_set, NULL))
		g_message("PTHREAD Some signals could not be blocked : %s", strerror(errno));
}

void
grid_main_set_status(int rc)
{
	grid_main_rc = rc;
}

void
grid_main_srand(void)
{
	srand(oio_ext_real_time () ^ getpid ());
}

