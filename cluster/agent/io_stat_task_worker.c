/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "gridcluster.agent.io_stat_task_worker"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
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

#include <metautils.h>

#include "io_stat_task_worker.h"
#include "task_scheduler.h"
#include "agent.h"

#define TASK_ID "io_stat_task"
#define PROC_DISKSTAT "/proc/diskstats"
#define DEFAULT_BUFFER_SIZE 4096
#define PROC_PARTITION "/proc/partitions"
#define PROC_PARTITION_TEMPLATE "%d\\s+%d\\s+[0-9]+\\s+(.*)"

static GHashTable *devices = NULL;

static gboolean
device_best_match(gpointer key, gpointer value, gpointer user_data)
{
	char *partition_name, *device_name;

	(void) user_data;
	(void) value;
	partition_name = (char *) user_data;
	device_name = (char *) key;
	return (0 == strncmp(partition_name, device_name, strlen(device_name)));
}

static char*
get_proc_stat_content(const char *path, GError **error)
{
	char end_of_buffer = '\0';
	int fd;
	ssize_t rl;
	GByteArray *buffer;
	char buff[DEFAULT_BUFFER_SIZE];

	fd = open(PROC_DISKSTAT, O_RDONLY);
	if (fd < 0) {
		GSETERROR(error, "Failed to open file [%s] : %s", path, strerror(errno));
		return NULL;
	}

	buffer = g_byte_array_new();
	while ((rl = read(fd, buff, DEFAULT_BUFFER_SIZE)) > 0)
		buffer = g_byte_array_append(buffer, (guint8*)buff, rl);
	close(fd);

	if (rl < 0) {
		GSETERROR(error, "Read file [%s] failed with error : %s", PROC_DISKSTAT, strerror(errno));
		g_byte_array_free(buffer, TRUE);
		return NULL;
	}
	buffer = g_byte_array_append(buffer, (guint8*)&end_of_buffer, sizeof(end_of_buffer));
	return (gchar*)g_byte_array_free(buffer, FALSE);
}

static int
io_stat_task_worker(gpointer p, GError ** error)
{
	char *current_line = NULL;
	char *next_new_line = NULL;
	disk_stat_t dstat;
	struct io_stat_s *s = NULL;
	char *diskstat = NULL;
	GRegex *regex = NULL;
	GMatchInfo *match_info = NULL;

	TRACE_POSITION();
	(void)p;

	regex = g_regex_new("^\\s*[0-9]*\\s*[0-9]*\\s*(\\w*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)\\s*([0-9]*)", 0, 0, error);
	if (regex == NULL) {
		GSETERROR(error, "Failed to build regex for parsing %s", PROC_DISKSTAT);
		return FALSE;
	}

	diskstat = get_proc_stat_content(PROC_DISKSTAT, error);
	if (!diskstat) {
		GSETERROR(error, "Failed to get the statistics");
		return 0;
	}

	current_line = diskstat;
	next_new_line = strchr(current_line, '\n');
	while (next_new_line) {

		memset(&dstat, 0, sizeof(disk_stat_t));
		match_info = NULL;

		if (g_regex_match(regex, current_line, 0, &match_info)) {

			gchar *device_name = NULL;
			gchar *str_reads = NULL;
			gchar *str_read_merged = NULL;
			gchar *str_read_sectors = NULL;
			gchar *str_read_time = NULL;
			gchar *str_writes = NULL;
			gchar *str_write_merged = NULL;
			gchar *str_write_sectors = NULL;
			gchar *str_write_time = NULL;
			gchar *str_io_in_progress = NULL;
			gchar *str_io_time = NULL;
			gchar *str_w_io_time = NULL;

			device_name = g_match_info_fetch(match_info, 1);

			str_reads = g_match_info_fetch(match_info, 2);
			if (str_reads != NULL) {
				dstat.reads = g_ascii_strtoull(str_reads, NULL, 10);
				g_free(str_reads);
			}

			str_read_merged = g_match_info_fetch(match_info, 3);
			if (str_read_merged != NULL) {
				dstat.read_merged = g_ascii_strtoull(str_read_merged, NULL, 10);
				g_free(str_read_merged);
			}

			str_read_sectors = g_match_info_fetch(match_info, 4);
			if (str_read_sectors != NULL) {
				dstat.read_sectors = g_ascii_strtoull(str_read_sectors, NULL, 10);
				g_free(str_read_sectors);
			}

			str_read_time = g_match_info_fetch(match_info, 5);
			if (str_read_time != NULL) {
				dstat.read_time = g_ascii_strtoull(str_read_time, NULL, 10);
				g_free(str_read_time);
			}

			str_writes = g_match_info_fetch(match_info, 6);
			if (str_writes != NULL) {
				dstat.writes = g_ascii_strtoull(str_writes, NULL, 10);
				g_free(str_writes);
			}

			str_write_merged = g_match_info_fetch(match_info, 7);
			if (str_write_merged != NULL) {
				dstat.write_merged = g_ascii_strtoull(str_write_merged, NULL, 10);
				g_free(str_write_merged);
			}

			str_write_sectors = g_match_info_fetch(match_info, 8);
			if (str_write_sectors != NULL) {
				dstat.write_sectors = g_ascii_strtoull(str_write_sectors, NULL, 10);
				g_free(str_write_sectors);
			}

			str_write_time = g_match_info_fetch(match_info, 9);
			if (str_write_time != NULL) {
				dstat.write_time = g_ascii_strtoull(str_write_time, NULL, 10);
				g_free(str_write_time);
			}

			str_io_in_progress = g_match_info_fetch(match_info, 10);
			if (str_io_in_progress != NULL) {
				dstat.io_in_progress = g_ascii_strtoull(str_io_in_progress, NULL, 10);
				g_free(str_io_in_progress);
			}

			str_io_time = g_match_info_fetch(match_info, 11);
			if (str_io_time != NULL) {
				dstat.io_time = g_ascii_strtoull(str_io_time, NULL, 10);
				g_free(str_io_time);
			}

			str_w_io_time = g_match_info_fetch(match_info, 12);
			if (str_w_io_time != NULL) {
				dstat.w_io_time = g_ascii_strtoull(str_w_io_time, NULL, 10);
				g_free(str_w_io_time);
			}


			/* Check that we have already some data for that device */
			s = (struct io_stat_s *) g_hash_table_lookup(devices, device_name);
			if (!s) {
				s = g_try_new0(struct io_stat_s, 1);

				if (!s) {
					GSETERROR(error, "Memory allocation failure");
					g_free(device_name);
					g_free(diskstat);
					g_regex_unref(regex);
					g_match_info_free(match_info);
					return 0;
				}

				g_hash_table_insert(devices, g_strdup(device_name), s);
			}

			memcpy(&(s->previous), &(s->current), sizeof(disk_stat_t));
			memcpy(&(s->previous_time), &(s->current_time), sizeof(struct timeval));
			memcpy(&(s->current), &dstat, sizeof(disk_stat_t));
			gettimeofday(&(s->current_time), NULL);
			g_free(device_name);
		}

		if (match_info)
			g_match_info_free(match_info);

		current_line = next_new_line + 1;
		next_new_line = strchr(current_line, '\n');
	}

	g_regex_unref(regex);
	g_free(diskstat);
	task_done(TASK_ID);
	return (1);
}

int
start_io_stat_task(GError ** error)
{
	task_t *task = NULL;

	devices = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);

	task = g_try_new0(task_t, 1);
	if (task == NULL) {
		GSETERROR(error, "Memory allocation failure");
		return 0;
	}

	task->id = g_strdup(TASK_ID);
	task->period = svc_check_freq;
	task->task_handler = io_stat_task_worker;

	if (!add_task_to_schedule(task, error)) {
		GSETERROR(error, "Failed to add io_stat task to scheduler");
		g_free(task);
		return 0;
	}

	return 1;
}

/* ------------------------------------------------------------------------- */

static void
debug_known_volumes(const gchar * dev)
{
	GHashTableIter iterator;
	gpointer k, v;

	g_hash_table_iter_init(&iterator, devices);
	DEBUG("Volume [%s] not found in...", dev);
	while (g_hash_table_iter_next(&iterator, &k, &v))
		DEBUG("> %s", (gchar *) k);
}

struct mp_s
{
	int dirlen;
	gchar *dir;
	gchar *fsname;
};

gboolean
get_device_from_path(const gchar * path, gchar * dst, gsize dst_size, GError ** error)
{
	static time_t last = 0;
	static GPtrArray *allmp = NULL;

	void cleanup(void) {
		if (!allmp)
			allmp = g_ptr_array_new();
		while (allmp->len > 0) {
			struct mp_s *mp = allmp->pdata[0];
			g_ptr_array_remove_index_fast(allmp, 0);
			g_free(mp->dir);
			g_free(mp->fsname);
			g_free(mp);
		}
	}
	void reload(void) {
		struct mntent *mntent;
		FILE *fp;

		if (!(fp = setmntent(_PATH_MOUNTED, "r")))
			return;
		while ((mntent = getmntent(fp)) != NULL) {
			if (!strcmp(mntent->mnt_dir, "/") && !strcmp(mntent->mnt_fsname, "rootfs"))
				continue;
			struct mp_s mp;
			mp.dirlen = strlen(mntent->mnt_dir);
			mp.dir = g_strdup(mntent->mnt_dir);
			mp.fsname = g_strdup(mntent->mnt_fsname);
			g_ptr_array_add(allmp, g_memdup(&mp, sizeof(mp)));
		}
		endmntent(fp);
	}
	void conditonal_reload(void) {
		time_t now;
		if (last == (now = time(0)))
			return;
		cleanup();
		reload();
		last = now;
	}

	conditonal_reload();

	int best_match_len = 0;
	for (guint i=0; i < allmp->len ;++i) {
		struct mp_s *mp = allmp->pdata[i];
		//GRID_WARN("MP [%d] [%s] [%s]", mp->dirlen, mp->dir, mp->fsname);
		if (mp->dirlen > best_match_len && g_str_has_prefix(path, mp->dir)) {
			g_strlcpy(dst, mp->fsname, dst_size);
			best_match_len = mp->dirlen;
		}
	}

	if (best_match_len == 0) {
		GSETERROR(error, "Failed to find the device corresponding to %s", path);
		return FALSE;
	}

	GRID_DEBUG("Best matching device for path [%s] is [%s]", path, dst);
	return TRUE;
}

static gboolean
get_device_from_major_minor(int major, int minor, gchar * dst, gsize dst_size, GError ** error)
{
	FILE *fd;
	char buff[512];
	char proc_partition_template[sizeof(PROC_PARTITION_TEMPLATE) + 3 + 3 + 1];
	GRegex *regex = NULL;

	memset(proc_partition_template, '\0', sizeof(proc_partition_template));
	g_snprintf(proc_partition_template, sizeof(proc_partition_template), PROC_PARTITION_TEMPLATE, major, minor);

	regex = g_regex_new(proc_partition_template, 0, 0, error);
	if (regex == NULL) {
		GSETERROR(error, "Failed to build regex from string [%s]", proc_partition_template);
		return FALSE;
	}

	fd = fopen(PROC_PARTITION, "ro");
	if (fd == NULL) {
		GSETERROR(error, "Failed to open [%s] : %s", PROC_PARTITION, strerror(errno));
		return FALSE;
	}

	/* Remove first 2 lines */
	if (!fgets(buff, sizeof(buff), fd) || !fgets(buff, sizeof(buff), fd)) {
		GSETERROR(error, "Failed to read 2 lines of [%s] : %s", PROC_PARTITION, strerror(errno));
		fclose(fd);
		return FALSE;
	}

	while (fgets(buff, sizeof(buff), fd)) {
		GMatchInfo *match_info = NULL;
		gchar *str_dev = NULL;

		if (g_regex_match(regex, buff, 0, &match_info)) {

			str_dev = g_match_info_fetch(match_info, 1);

			if (str_dev != NULL) {

				bzero(dst, dst_size);
				g_strlcpy(dst, str_dev, dst_size-1);

				DEBUG("Found kernel representation of device [%s]", dst);
				g_free(str_dev);
				g_match_info_free(match_info); 
				g_regex_unref(regex);
				fclose(fd);
				return TRUE;
			}
			else
				g_free(str_dev);
		}
		if (match_info)
			g_match_info_free(match_info);
	}

	g_regex_unref(regex);

	fclose(fd);
	GSETERROR(error, "Device with major[%d] minor[%d] not found in [%s]", major, minor, PROC_PARTITION);
	return FALSE;
}

/* ------------------------------------------------------------------------- */

int
get_io_idle_for_device(const char *device_name, int *idle, GError ** error)
{
	gchar wrk_name[1024];
	struct io_stat_s *s = NULL;
	struct timeval elapsed;
	double sec_d, usec_d, prev_d, cur_d, percent_used_d, time_spent_d, result_d;

	if (!device_name || !*device_name) {
		GSETERROR(error, "NULL/empty device");
		return 0;
	}

	bzero(wrk_name, sizeof(wrk_name));
	g_strlcpy(wrk_name, device_name, sizeof(wrk_name)-1);

	/**@todo TODO purify the name*/

	if (!(s = g_hash_table_lookup(devices, wrk_name))) {
		s = g_hash_table_find(devices, device_best_match, wrk_name);
		if (!s) {
			if (DEBUG_ENABLED())
				debug_known_volumes(wrk_name);
			GSETERROR(error, "No stat for device [%s] found", wrk_name);
			return (0);
		}
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

	*idle = result_d;	/*implicit conversion */
	return (1);
}

int
get_io_idle_for_path(const char *path_name, int *idle, GError ** error)
{
	char best_match_dev[1024];
	char short_dev[512];
	struct stat file_stat;
	int major, minor;

	if (!get_device_from_path(path_name, best_match_dev, sizeof(best_match_dev), error)) {
		GSETERROR(error, "No device found for [%s]", path_name);
	}

	if (stat(best_match_dev, &file_stat) < 0) {
		GSETERROR(error, "Failed to stat device file [%s -> %s] : %s", path_name, best_match_dev,
		    strerror(errno));
		return (0);
	}

	major = major(file_stat.st_rdev);
	minor = minor(file_stat.st_rdev);

	DEBUG("Device [%s] has major[%d] and minor[%d]", best_match_dev, major, minor);

	if (!get_device_from_major_minor(major, minor, short_dev, sizeof(short_dev), error)) {
		GSETERROR(error, "Device not found for [%s] major=%d minor=%d", path_name, major, minor);
		return 0;
	}

	if (!get_io_idle_for_device(short_dev, idle, error)) {
		GSETERROR(error, "Failed to get IO-idle");
		return 0;
	}

	return 1;
}
