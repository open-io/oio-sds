#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "gridcluster.agent.cpu_stat_task_worker"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <mntent.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <asm/param.h>

#include <metautils/lib/metautils.h>

#include "./cpu_stat_task_worker.h"
#include "./task_scheduler.h"
#include "./agent.h"

#define TASK_ID "cpu_stat_task"
#define PROC_STAT "/proc/stat"
#define DEFAULT_BUFFER_SIZE 2048

#define DIFF(Max,Current,Previous) ((Current>=Previous) ? (Current-Previous) : (Max-Previous)+Current)
#define DIFF2(Field) DIFF(G_MAXUINT64,cpu_stat.current.Field,cpu_stat.previous.Field)

static int last_idle = 0;
static volatile guint64 last_nb_loops = 0;
static volatile guint64 nb_loops = 0;
static struct cpu_stat_s cpu_stat;

/**
 * FIXME TODO XXX file load duplicated at cluster/lib/gridcluster.c : gba_read()
 */
static int
cpu_stat_task_worker(gpointer udata, GError ** error)
{
	char end_of_buffer = '\0';
	int fd = 0;
	ssize_t rl;
	char *procstat = NULL;
	GByteArray *buffer = NULL;
	char buff[DEFAULT_BUFFER_SIZE];
	proc_stat_t pstat;

	(void)udata;
	TRACE_POSITION();

	fd = open(PROC_STAT, O_RDONLY);
	if (fd < 0) {
		GSETERROR(error, "Failed to open file [%s] : %s", PROC_STAT, strerror(errno));
		task_done(TASK_ID);
		return 0;
	}

	buffer = g_byte_array_new();
	while ((rl = read(fd, buff, DEFAULT_BUFFER_SIZE)) > 0)
		buffer = g_byte_array_append(buffer, (guint8*)buff, rl);
	metautils_pclose(&fd);

	if (rl < 0) {
		GSETERROR(error, "Read file [%s] failed with error : %s", PROC_STAT, strerror(errno));
		g_byte_array_free(buffer, TRUE);
		task_done(TASK_ID);
		return 0;
	}

	/*ensure the statistics string is NULL-terminated */
	g_byte_array_append(buffer, (guint8*)&end_of_buffer, sizeof(end_of_buffer));
	procstat = (char*)g_byte_array_free(buffer, FALSE);

	memset(&pstat, 0, sizeof(proc_stat_t));

	if (sscanf(procstat, "cpu  %llu %llu %llu %llu %llu %llu %llu",
		&(pstat.user), &(pstat.nice), &(pstat.system), &(pstat.idle),
		&(pstat.io_wait), &(pstat.irq), &(pstat.soft_irq)) == 7) {

		memcpy(&(cpu_stat.previous), &(cpu_stat.current), sizeof(proc_stat_t));
		memcpy(&(cpu_stat.current), &pstat, sizeof(proc_stat_t));
		nb_loops++;
	}
	else {
		WARN("Failed to scan cpu in string [%s]", procstat);
	}

	g_free(procstat);
	task_done(TASK_ID);
	return (1);
}

int
start_cpu_stat_task(GError ** error)
{
	nb_loops = 0;

	task_t *task = g_malloc0(sizeof(task_t));
	task->id = g_strdup(TASK_ID);
	task->period = 1;
	task->task_handler = cpu_stat_task_worker;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add cpu_stat task to scheduler");
		g_free(task);
		return 0;
	}

	return (1);
}

// values from /proc/stat are in 1/HZ sec
int
get_cpu_idle(int *cpu_idle, GError ** error)
{
	unsigned long long sum;

	unsigned long long user;
	unsigned long long n;
	unsigned long long sys;
	unsigned long long idle;
	unsigned long long io_wait;
	unsigned long long irq;
	unsigned long long soft_irq;

	(void)error;

	if (nb_loops < 2LLU)
		last_idle = 98;
	else if (last_nb_loops < nb_loops) {
		user = DIFF2(user);
		n = DIFF2(nice);
		sys = DIFF2(system);
		idle = DIFF2(idle);
		io_wait = DIFF2(io_wait);
		irq = DIFF2(irq);
		soft_irq = DIFF2(soft_irq);

		sum = user + n + sys + idle + io_wait + irq + soft_irq;
		if (!sum)
			WARN("Invalid CPU total usage found (0), old value left (%d)", last_idle);
		else {
			gdouble d_sum, d_idle, d_ratio;

			d_sum = sum;	/*implicit conversion */
			d_idle = idle;	/*implicit conversion */
			d_ratio = (100.0 * d_idle) / d_sum;
			d_ratio = floor(d_ratio);
			last_idle = d_ratio;	/*implicit conversion */
		}
	}

	last_nb_loops = nb_loops;
	*cpu_idle = last_idle;
	return (1);
}
