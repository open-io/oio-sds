#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.supervisor"
#endif

#include <errno.h>
#include <fnmatch.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <metautils/lib/metautils.h>
#include <cluster/lib/gridcluster.h>


#include "./agent.h"
#include "./broken_workers.h"
#include "./cpu_stat_task_worker.h"
#include "./event_workers.h"
#include "./io_scheduler.h"
#include "./io_stat_task_worker.h"
#include "./namespace_get_task_worker.h"
#include "./request_worker.h"
#include "./server.h"
#include "./services_workers.h"
#include "./task.h"
#include "./task_scheduler.h"

enum service_type_e {
	ST_REQAGENT = 0x10,
	ST_EVT = 0X11,
};

#define SRV_IS_INTERNAL(sd) ((sd)->type & 0x10)

struct service_def_s {

	enum service_type_e type;

	gboolean obsolete;
	gboolean not_verified;

	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar type_name[LIMIT_LENGTH_SRVTYPE];
	
	time_t last_start_attempt;
	time_t last_kill_attempt;
	time_t period;

	pid_t pid;
	gchar *command;
	gchar **args;
	gchar *full_command;

	struct service_def_s *next;
};

/* ------------------------------------------------------------------------- */

static volatile gboolean is_running = TRUE;
static volatile gboolean must_reconfigure = FALSE;

static struct service_def_s SRV_BEACON = {
	0,
	FALSE, FALSE,
	{0}, {0},
	
	0L, 0L, 0L,
	
	-1, NULL, NULL,  NULL,

	NULL

};

/* ------------------------------------------------------------------------- */

static void
silo_service_copy(struct service_def_s *dst, struct service_def_s *src)
{
	guint i, max;
	
	memcpy(dst, src, sizeof(struct service_def_s));
	if (src->command)
		dst->command = g_strdup(src->command);
	else
		dst->command = g_strdup("/bin/false");
	
	if (src->full_command)
		dst->full_command = g_strdup(src->full_command);
	else
		dst->full_command = g_strdup("/bin/false");
	
	max = src->args ? g_strv_length(src->args) : 0;
	dst->args = g_try_malloc0(sizeof(gchar*)*(max+1));
	for (i=0; i<max ;i++)
		dst->args[i] = g_strdup(src->args[i]);
	
	dst->next = NULL;
}

static void
silo_service_clean(struct service_def_s *sd)
{
	if (sd) {
		if (sd->command)
			g_free(sd->command);
		if (sd->full_command)
			g_free(sd->full_command);
		if (sd->args)
			g_strfreev(sd->args);
		memset(sd, 0x00, sizeof(struct service_def_s));
	}
}

static void
silo_service_cleanall(void)
{
	struct service_def_s *sd, *sd_next;

	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;) {
		sd_next = sd->next;
		silo_service_clean(sd);
		g_free(sd);
		sd = sd_next;
	}

	SRV_BEACON.next = &SRV_BEACON;
}

static guint
_wait_for_dead_child(pid_t *ptr_pid)
{
	register pid_t pid, pid_exited;

	pid = *ptr_pid;
	if (pid < 0)
		return 0;

	errno = 0;
	pid_exited = waitpid(pid, NULL, WNOHANG);
	if (pid_exited>0 || errno==ECHILD) {
		*ptr_pid = -1;
		return 1;
	}

	return 0;
}

static void
sighandler_NOOP(int s)
{
	signal(s, sighandler_NOOP);
}

static void
reset_sighandler(void)
{
	signal(SIGQUIT, sighandler_NOOP);
	signal(SIGTERM, sighandler_NOOP);
	signal(SIGINT,  sighandler_NOOP);
	signal(SIGPIPE, sighandler_NOOP);
	signal(SIGUSR1, sighandler_NOOP);
	signal(SIGUSR2, sighandler_NOOP);
	signal(SIGCHLD, sighandler_NOOP);
}

/**
 * @return <li>-1 when the fork failed;<li>0 when the service does not meet the
 * conditions to start;<li>1 when the service has been forked successfuly.
 */
static gint
silo_service_start(struct service_def_s *sd, GError **err)
{
	struct service_def_s sd_copy;
	pid_t pid_father;
	
	pid_father = getpid();
	sd->last_start_attempt = time(0);

	switch (sd->pid = fork()) {

	case -1:/*error*/
		GSETCODE(err, errno, "fork failed : %s", strerror(errno));
		return -1;

	case 0:/*child*/
		reset_sighandler();
		silo_service_copy(&sd_copy, sd);
		silo_service_cleanall();
		NOTICE("Forked by pid=%d, now executing NS=[%s] type=[%s] cmd=[%s]",
			pid_father, sd_copy.ns_name, sd_copy.type_name, sd_copy.full_command);
		execv(sd_copy.command, sd_copy.args);
		ALERT("Failed to exec '%s' : %s", sd_copy.full_command, strerror(errno));
		abort();
		break;

	default:/*father*/
		NOTICE("Forked a new child NS=[%s] type=[%s] pid=%d cmd=[%s]",
			sd->ns_name, sd->type_name, sd->pid, sd->full_command);
		return 0;
	}
}

static guint
silo_service_killall(int sig)
{
	guint count;
	struct service_def_s *sd;

	count = 0;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid > 0) {
			kill(sd->pid, sig);
			count ++;
		}
	}

	return count;
}

/**
 * @return the number of processes really started
 */
static guint
silo_service_startall(void)
{
	guint count, rc_start;
	struct service_def_s *sd;

	count = 0U;
	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid > 0)
			_wait_for_dead_child(&(sd->pid));
		if (sd->pid <= 0) {
			GError *error_local = NULL;
			rc_start = silo_service_start(sd, &error_local);
			if (!rc_start)
				count ++;
			else
				ERROR("Child startup failure : %s", gerror_get_message(error_local));
			if (error_local)
				g_error_free(error_local);
		}
	}

	return count;
}

static void
silo_service_set_all_obsolete(void)
{
	struct service_def_s *sd;

	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next)
		sd->obsolete = TRUE;
}

static void
silo_service_kill_obsolete(void)
{
	time_t now;
	struct service_def_s *sd;

	now = time(0);

	for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
		if (sd->pid>1 && sd->obsolete) {
			kill(sd->pid,
				(now - sd->last_kill_attempt > DEFAULT_TIMEOUT_KILL ? SIGKILL : SIGTERM));
			sd->last_kill_attempt = now;
		}
	}
}

/**
 * Check the ring's content for a servic ematching the criterions,
 * and if not present, inserts a brand new service.
 */
static void
_ensure_internal_service(const gchar *ns, enum service_type_e type)
{
	struct service_def_s *sd = NULL;

	if (type == ST_REQAGENT) {
		for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
			if (sd->type == type) {
				sd->obsolete = FALSE;
				return;
			}
		}
	}
	else {
		for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
			if (sd->type == type && !g_ascii_strcasecmp(ns, sd->ns_name)) {
				sd->obsolete = FALSE;
				return;
			}
		}
	}

	/* if we get here the service was not found */
	sd = g_try_malloc0(sizeof(struct service_def_s));
	if (!sd)
		return;
	sd->type = type;
	sd->pid = -1;

	switch (type) {
	case ST_REQAGENT:
		g_strlcpy(sd->type_name, "REQAGENT", sizeof(sd->type_name)-1);
		sd->command = g_strdup(g_get_prgname());
		sd->args = g_try_malloc0(5 * sizeof(gchar*));
		sd->args[0] = g_strdup(g_get_prgname());
		sd->args[1] = g_strdup("--child-req");
		sd->args[2] = g_strdup(str_opt_config);
		sd->args[3] = g_strdup(str_opt_log);
		sd->args[4] = NULL;
		break;
	case ST_EVT:
		g_strlcpy(sd->type_name, "EVT", sizeof(sd->type_name)-1);
		g_strlcpy(sd->ns_name, ns, sizeof(sd->ns_name)-1);
		sd->command = g_strdup(g_get_prgname());
		sd->args = g_try_malloc0(5 * sizeof(gchar*));
		sd->args[0] = g_strdup(g_get_prgname());
		sd->args[1] = g_strdup_printf("--child-evt=%s", ns);
		sd->args[2] = g_strdup(str_opt_config);
		sd->args[3] = g_strdup(str_opt_log);
		sd->args[4] = NULL;
		break;
	default:/*corruption*/
		abort();
	}

	sd->full_command = g_strdup_printf("%s %s %s %s",
		sd->args[0], sd->args[1], sd->args[2], sd->args[3]);

	/* ring insertion */
	sd->next = SRV_BEACON.next;
	SRV_BEACON.next = sd;

	INFO("Internal service registered with command=[%s] (%u args)", sd->full_command, g_strv_length(sd->args));
}

static void
silo_service_reload_internal(void)
{
	GHashTableIter iter;
	gpointer k, v;

	_ensure_internal_service(NULL, ST_REQAGENT);
	g_hash_table_iter_init(&iter, namespaces);
	while (g_hash_table_iter_next(&iter, &k, &v))
		_ensure_internal_service(k, ST_EVT);
}

static void
sighandler_supervisor(int s)
{
	struct service_def_s *sd;
	pid_t pid_dead;
	
	switch (s) {
	case SIGUSR1:
		silo_service_killall(s);
		signal(s,sighandler_supervisor);
		return;
	case SIGUSR2:
		must_reconfigure = TRUE;
		signal(s,sighandler_supervisor);
		return;
	case SIGPIPE:
		signal(s,sighandler_supervisor);
		return;
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		is_running = FALSE;
		signal(s,sighandler_supervisor);
		return;
	case SIGCHLD:
		while ((pid_dead = waitpid(0, NULL, WNOHANG)) > 0) {
			for (sd=SRV_BEACON.next; sd && sd!=&SRV_BEACON ;sd=sd->next) {
				if (sd->pid == pid_dead) {
					sd->pid = -1;
					break;
				}
			}
		}
		signal(s,sighandler_supervisor);
		return;
	}
}

static void
set_sighandlers(void)
{
	signal(SIGQUIT, sighandler_supervisor);
	signal(SIGTERM, sighandler_supervisor);
	signal(SIGINT,  sighandler_supervisor);
	signal(SIGPIPE, sighandler_supervisor);
	signal(SIGUSR1, sighandler_supervisor);
	signal(SIGUSR2, sighandler_supervisor);
	signal(SIGCHLD, sighandler_supervisor);
}

static void
stop_all_children(void)
{
	gint retries;

	for (retries=3; retries ;retries--) {
		if (!silo_service_killall(SIGTERM))
			return;
		sleep(1);
	}

	reset_sighandler();
	silo_service_killall(SIGKILL);
}

int
main_supervisor(void)
{
	GError *error = NULL;

	SRV_BEACON.next = &SRV_BEACON;
	set_sighandlers();

	if (is_agent_running()) {
		g_printerr("An agent is already running => aborting\n");
		return -1;
	}

	/*The first configuration parse must not fail*/
	if (!parse_namespaces(&error)) {
		ERROR("An error occured while filling namespaces hash with cluster config : %s", gerror_get_message(error));
		g_clear_error(&error);
		return (-1);
	}

	while (is_running) {

		/*here reconfigure the gridagent*/
		if (must_reconfigure) {
			(void) parse_namespaces(NULL);
			must_reconfigure = FALSE;
		}

		/* Regularily, we check the processes that have been marked obsolete
		 * but are still up */
		silo_service_set_all_obsolete();
		silo_service_reload_internal();
		silo_service_kill_obsolete();
		silo_service_startall();

		if (is_running) {
			struct timeval tv_sleep;
			tv_sleep.tv_sec = tv_sleep.tv_usec = 1L;
			select(0,NULL,NULL,NULL,&tv_sleep);
			errno = 0;
		}
	}

	stop_all_children();
	return 0;
}

