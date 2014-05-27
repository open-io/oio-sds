#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.io_stat_task_worker"
#endif

#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <mntent.h>

#include <metautils/lib/metautils.h>

#include "io_stat_task_worker.h"
#include "task_scheduler.h"
#include "agent.h"
#include "worker.h"

#define TASK_ID "io_stat_task"
#define PROC_DISKSTAT "/proc/diskstats"
#define DEFAULT_BUFFER_SIZE 4096

struct majmin_s
{
	int major;
	int minor;
};

struct dated_majmin_s
{
	struct majmin_s majmin;
	time_t last_update;
};

struct disk_stat_s
{
	unsigned long reads;        // # of reads issued
	unsigned long read_merged;  // # of reads merged
	unsigned long read_sectors; // # of sectors read
	unsigned long read_time;    // # of milliseconds spent reading
	unsigned long writes;       // # of writes completed
	unsigned long write_merged; // # of writes merged
	unsigned long write_sectors;    // # of sectors written
	unsigned long write_time;   // # of milliseconds spent writing
	unsigned long io_in_progress;   // # of I/Os currently in progress
	unsigned long io_time;      // # of milliseconds spent doing I/Os
	unsigned long w_io_time;    // weighted # of milliseconds spent doing I/Os
};

struct io_stat_s
{
	struct timeval previous_time;
	struct disk_stat_s previous;
	struct timeval current_time;
	struct disk_stat_s current;
};

static GHashTable *majmin_to_stats = NULL;
static GHashTable *path_to_majmin = NULL;

/**
 * FIXME TODO XXX file load duplicated at cluster/lib/gridcluster.c : gba_read()
 */
static char*
get_proc_stat_content(const char *path, GError **error)
{
	char end_of_buffer = '\0';
	ssize_t rl;
	GByteArray *buffer;
	char buff[DEFAULT_BUFFER_SIZE];

	int fd = open(PROC_DISKSTAT, O_RDONLY);
	if (fd < 0) {
		GSETERROR(error, "Failed to open file [%s] : %s", path, strerror(errno));
		return NULL;
	}

	buffer = g_byte_array_new();
	while ((rl = read(fd, buff, DEFAULT_BUFFER_SIZE)) > 0)
		buffer = g_byte_array_append(buffer, (guint8*)buff, rl);
	metautils_pclose(&fd);

	if (rl < 0) {
		GSETERROR(error, "Read file [%s] failed with error : %s", PROC_DISKSTAT, strerror(errno));
		g_byte_array_free(buffer, TRUE);
		return NULL;
	}
	buffer = g_byte_array_append(buffer, (guint8*)&end_of_buffer, sizeof(end_of_buffer));
	return (gchar*)g_byte_array_free(buffer, FALSE);
}

static guint64
_token(GMatchInfo *match_info, gint group)
{
	gchar *str = g_match_info_fetch(match_info, group);
	if (!str)
		return 0;
	guint64 v = g_ascii_strtoull(str, NULL, 10);
	g_free(str);
	return v;
}

static int
_token_int(GMatchInfo *match_info, gint group)
{
	gchar *str = g_match_info_fetch(match_info, group);
	if (!str)
		return 0;
	int v = atoi(str);
	g_free(str);
	return v;
}

static void
_diskstat_line(GMatchInfo *match_info)
{
	struct majmin_s key;
	key.major = _token_int(match_info, 1);
	key.minor = _token_int(match_info, 2);

	struct disk_stat_s dstat;
	dstat.reads = _token(match_info, 3);
	dstat.read_merged = _token(match_info, 4);
	dstat.read_sectors = _token(match_info, 5);
	dstat.read_time = _token(match_info, 6);
	dstat.writes = _token(match_info, 7);
	dstat.write_merged = _token(match_info, 8);
	dstat.write_sectors = _token(match_info, 9);
	dstat.write_time = _token(match_info, 10);
	dstat.io_in_progress = _token(match_info, 11);
	dstat.io_time = _token(match_info, 12);
	dstat.w_io_time = _token(match_info, 13);

	struct io_stat_s *s = g_hash_table_lookup(majmin_to_stats, &key);
	if (NULL == s) {
		s = g_malloc0(sizeof(struct io_stat_s));
		g_hash_table_insert(majmin_to_stats, g_memdup(&key, sizeof(key)), s);
	}

	memcpy(&(s->previous), &(s->current), sizeof(struct disk_stat_s));
	memcpy(&(s->previous_time), &(s->current_time), sizeof(struct timeval));
	memcpy(&(s->current), &dstat, sizeof(struct disk_stat_s));
	gettimeofday(&(s->current_time), NULL);
}

static int
io_stat_task_worker(gpointer p, GError ** error)
{
	char *current_line = NULL;
	char *next_new_line = NULL;
	char *diskstat = NULL;
	GRegex *regex = NULL;

	TRACE_POSITION();
	(void)p;

	diskstat = get_proc_stat_content(PROC_DISKSTAT, error);
	if (!diskstat) {
		GSETERROR(error, "Failed to get the statistics");
		return 0;
	}

	regex = g_regex_new(
			"^\\s*([0-9]*)\\s*([0-9]*)"
			"\\s*\\w*"
			"\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)"
			"\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)"
			"\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)",
			0, 0, error);

	if (regex == NULL) {
		GSETERROR(error, "Failed to build regex for parsing %s", PROC_DISKSTAT);
		g_free(diskstat);
		return 0;
	}

	current_line = diskstat;
	next_new_line = strchr(current_line, '\n');
	while (next_new_line) {
		GMatchInfo *match_info = NULL;
		if (g_regex_match(regex, current_line, 0, &match_info)) {
			if (match_info) {
				_diskstat_line(match_info);
			}
		}
		if (match_info)
			g_match_info_free(match_info);
		match_info = NULL;
		current_line = next_new_line + 1;
		next_new_line = strchr(current_line, '\n');
	}

	g_regex_unref(regex);
	g_free(diskstat);
	task_done(TASK_ID);
	return (1);
}

static guint
majmin_hash(struct majmin_s *p)
{
	return makedev(p->major, p->minor);
}

static gboolean
majmin_equal(struct majmin_s *p0, struct majmin_s *p1)
{
	return p0->major == p1->major && p0->minor == p1->minor;
}

int
start_io_stat_task(GError **err)
{
	if (!path_to_majmin) {
		path_to_majmin = g_hash_table_new_full(
				g_str_hash, g_str_equal,
				g_free, g_free);
	}

	if (!majmin_to_stats) {
		majmin_to_stats = g_hash_table_new_full(
				(GHashFunc)majmin_hash, (GEqualFunc)majmin_equal,
				g_free, g_free);
	}

	task_t *task = create_task(2, TASK_ID);
	task->task_handler = io_stat_task_worker;

	if (!add_task_to_schedule(task, err)) {
		GSETERROR(err, "Failed to add io_stat task to scheduler");
		g_free(task);
		return 0;
	}

	return 1;
}


/* ------------------------------------------------------------------------- */

static int
get_io_idle(int major, int minor, int *idle, GError **err)
{
	struct majmin_s key;
	struct io_stat_s *s = NULL;
	struct timeval elapsed;
	double sec_d, usec_d, prev_d, cur_d, percent_used_d, time_spent_d, result_d;

	key.major = major;
	key.minor = minor;
	if (!(s = g_hash_table_lookup(majmin_to_stats, &key))) {
		GSETERROR(err, "Device not found major=%d minor=%d", major, minor);
		return 0;
	}

	timersub(&(s->current_time), &(s->previous_time), &(elapsed));

	/*convert working values in floating point numbers */
	cur_d = s->current.io_time;
	prev_d = s->previous.io_time;
	sec_d = elapsed.tv_sec;
	usec_d = elapsed.tv_usec;

	percent_used_d = 100.0 * (cur_d > prev_d ? cur_d - prev_d : 0.0);
	time_spent_d = sec_d * 1000.0 + usec_d / 1000.0;

	result_d = 100.0 - (percent_used_d / (time_spent_d > 0.0 ? time_spent_d : 1.0));

	*idle = result_d; // implicit conversion
	return 1;
}

static int
get_major_minor(const gchar *path, int *pmaj, int *pmin, GError **err)
{
	*pmaj = 0;
	*pmin = 0;

	struct dated_majmin_s *v = g_hash_table_lookup(path_to_majmin, path);
	if (NULL == v) {
		v = g_malloc0(sizeof(struct dated_majmin_s));
		g_hash_table_insert(path_to_majmin, g_strdup(path), v);
	}

	time_t now = time(NULL);
	if (!v->last_update || v->last_update > now || v->last_update < now - 30) {
		struct stat file_stat;
		memset(&file_stat, 0, sizeof(file_stat));
		if (0 > stat(path, &file_stat)) {
			GSETERROR(err, "stat(%s) : errno=%d %s", path, errno, strerror(errno));
			return 0;
		}
		v->majmin.major = major(file_stat.st_dev);
		v->majmin.minor = minor(file_stat.st_dev);
		v->last_update = now;
	}

	*pmaj = v->majmin.major;
	*pmin = v->majmin.minor;
	GRID_TRACE("Device [%s] major=%d minor=%d", path, *pmaj, *pmin);
	return 1;
}

int
get_io_idle_for_path(const char *path, int *idle, GError **err)
{
	int major, minor;

	if (get_major_minor(path, &major, &minor, err) &&
			get_io_idle(major, minor, idle, err))
		return 1;

	GSETERROR(err, "No stat for [%s]", path);
	return 0;
}

