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
# define LOG_DOMAIN "gridcluster.agent.event.common"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils.h>

#include <glib.h>
#include <glib/gstdio.h>

#include "./event_workers.h"

struct dir_run_info_s
{
	const gchar *basedir;
	guint max;
	time_t delay;
	time_t now;
	gboolean (*filter)(path_data_t *);
};

struct time_path_s
{
	gint64 parsed;
	gchar raw;
};

#define TIMEPATH(P) ((struct time_path_s*)(P))

/* ------------------------------------------------------------------------- */

static const gchar*
time_path_get_path(struct time_path_s *tp)
{
	if (!tp)
		return NULL;
	return &(tp->raw);
}

static struct time_path_s*
time_path_create(const gchar *path)
{
	struct time_path_s *time_path;
	size_t len;

	len = strlen(path);
	time_path = g_try_malloc0(sizeof(struct time_path_s) + len + 1);
	time_path->parsed = g_ascii_strtoll(path, NULL, 10);
	g_strlcpy(&(time_path->raw), path, len+1);

	return time_path;
}

static gint 
compare_path_data_time_ASC(const struct path_data_s *p1, const struct path_data_s *p2)
{
	register gint64 cmp, i1, i2;

	i1 = p1->xattr_seq;
	i2 = p2->xattr_seq;
	cmp = i1 - i2;
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

/* ------------------------------------------------------------------------- */

static gint
compare_time_path_by_parsed_ASC(gconstpointer p1, gconstpointer p2)
{
	if (p1 == p2)
		return 0;
	if (TIMEPATH(p1)->parsed < TIMEPATH(p2)->parsed)
		return -1;
	if (TIMEPATH(p1)->parsed > TIMEPATH(p2)->parsed)
		return 1;
	return 0;
}

static gint 
compare_path_data_sequence_ASC(const struct path_data_s *p1, const struct path_data_s *p2)
{
	register gint64 cmp, i1, i2;

	i1 = p1->xattr_seq;
	i2 = p2->xattr_seq;
	cmp = i1 - i2;
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
}

static gint 
compare_path_data_ASC(const struct path_data_s *p1, const struct path_data_s *p2)
{
	gint64 cmp;

	if (p1 == p2)
		return 0;

	cmp = compare_path_data_time_ASC(p1, p2);
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : compare_path_data_sequence_ASC(p1, p2));
}

static void
keep_earliest_path_data(GHashTable *ht_current, const struct path_data_s *pd)
{
	struct path_data_s *previous, *pd_copy;

	previous = g_hash_table_lookup(ht_current, pd->str_cid);

	if (!previous) {
		TRACE("CID[%s] TIME[%ld] SEQ[%"G_GINT64_FORMAT"] saved because not found",
				pd->str_cid, pd->xattr_time, pd->xattr_seq);
		pd_copy = g_memdup(pd, sizeof(struct path_data_s));
		g_hash_table_insert(ht_current, pd_copy->str_cid, pd_copy);
		return ;
	}

	if (compare_path_data_ASC(previous, pd) > 0) {
		TRACE("CID[%s] TIME[%ld] SEQ[%"G_GINT64_FORMAT"] saved because earlier",
				pd->str_cid, pd->xattr_time, pd->xattr_seq);

		g_hash_table_remove(ht_current, pd->str_cid);
		g_free(previous);

		pd_copy = g_memdup(pd, sizeof(struct path_data_s));
		g_hash_table_insert(ht_current, pd_copy->str_cid, pd_copy);
		return ;
	}

	TRACE("CID[%s] TIME[%ld] SEQ[%"G_GINT64_FORMAT"] not saved because later",
			pd->str_cid, pd->xattr_time, pd->xattr_seq);
}

static gboolean
event_is_delayed(time_t now, time_t delay, struct path_data_s *pd)
{
	if (pd->xattr_time)
		return pd->xattr_time + delay > now;

	return pd->stat.st_ctime + delay > now;
}

/**
 * Returns the number of entries in the directory at the path given by 'dir'.
 * This does not consider the entries on the subdirectories.
 */
static guint
get_one_event_per_container(GHashTable *ht, const gchar *dir, const gchar *subdir,
		struct dir_run_info_s *info)
{
	const gchar *path;
	GDir *gdir = NULL;
	GError *err;
	guint count_entry = 0;
	GSList *list_of_subdirs = NULL;

	/* Run the directory, we manage the files directly, and keep the subdirs
	 * for later */
	err = NULL;
	gdir = g_dir_open(dir, 0, &err);
	if (!gdir) {
		ERROR("g_dir_open(%s) error : %s", dir, gerror_get_message(err));
		g_clear_error(&err);
		return 0;
	}
	while (NULL != (path = g_dir_read_name(gdir))) {
		struct path_data_s pd;
		gchar *fullpath;

		++ count_entry; 
		fullpath = g_strconcat(dir, G_DIR_SEPARATOR_S, path, NULL);

		bzero(&pd, sizeof(pd));
		g_snprintf(pd.relpath, sizeof(pd.relpath), "%s%c%s", subdir, G_DIR_SEPARATOR, path);
		pd.relpath_size = strlen(pd.relpath);

		if (-1 == stat(fullpath, &(pd.stat)))
			WARN("stat(%s) error : %s", fullpath, strerror(errno));
		else if (S_ISDIR(pd.stat.st_mode)) {
			struct time_path_s *tp;
			if (NULL != (tp = time_path_create(path)))
				list_of_subdirs = g_slist_prepend(list_of_subdirs, tp);
		}
		else if (S_ISREG(pd.stat.st_mode)) {
			if (0 != path_get_container_id(fullpath, &(pd.id), pd.str_cid, sizeof(pd.str_cid)))
				DEBUG("Invalid event, missing XATTR (container) at [%s]", pd.relpath);
			else if (0 != path_get_incoming_time(fullpath, &(pd.xattr_time)))
				DEBUG("Invalid event, missing XATTR (time) at [%s]", pd.relpath);
			else if (0 != path_get_sequence(fullpath, &(pd.xattr_seq)))
				DEBUG("Invalid event, missing XATTR (sequence) at [%s]", pd.relpath);
			else if (event_is_delayed(info->now, info->delay, &pd))
				DEBUG("Delayed event at [%s]", pd.relpath);
			else if (!info->filter || info->filter(&pd))
				keep_earliest_path_data(ht, &pd);
			else
				TRACE("CID[%s] TIME[%ld] SEQ[%"G_GINT64_FORMAT"] filtered at [%s]",
						pd.str_cid, pd.xattr_time, pd.xattr_seq, pd.relpath);

		}

		g_free(fullpath);
	}
	g_dir_close(gdir);
	gdir = NULL;

	/* Now manage the subdirectories:
	 * They are sorted by order of the parsed timestamp, and we run directories
	 * until enough events are found */
	if (list_of_subdirs) {
		GSList *l;

		list_of_subdirs = g_slist_sort(list_of_subdirs, compare_time_path_by_parsed_ASC);

		if (TRACE_ENABLED()) { 
			TRACE("Basedir's [%s] sorted subdirs :", dir);
			for (l=list_of_subdirs; l ;l=l->next) {
				struct time_path_s *time_path = l->data;
				g_assert(time_path != NULL);
				TRACE(" > %"G_GINT64_FORMAT" %s", time_path->parsed,
							time_path_get_path(time_path));
			}
		}

		gint64 now64, oldest;
		now64 = time(0);
		oldest = now64 - 3600;

		for (l=list_of_subdirs; l ;l=l->next) {
			struct time_path_s *tp;
			gchar *fullpath, *new_subdir;

			/* Run that directory */
			tp = l->data;
			fullpath = g_strconcat(dir, G_DIR_SEPARATOR_S, time_path_get_path(tp), NULL);
			new_subdir = g_strconcat(subdir, G_DIR_SEPARATOR_S, time_path_get_path(tp), NULL);
			if (!get_one_event_per_container(ht, fullpath, new_subdir, info)) {
				if (l->next || (tp->parsed && (tp->parsed < oldest)) || oldest > now64)
					(void) g_rmdir(fullpath);
			}
			g_free(new_subdir);
			g_free(fullpath);

			/* Stop the iterations as soon as the hashtable size reaches the maximum size */
			if (info->max && g_hash_table_size(ht) >= info->max)
				break;
		}
		g_slist_foreach(list_of_subdirs, g_free1, NULL);
		g_slist_free(list_of_subdirs);
	}

	return count_entry;
}

static GSList*
get_ht_values(GHashTable *ht)
{
	GHashTableIter iter;
	gpointer k, v;
	GSList *ht_values;

	ht_values = NULL;
	k = v = NULL;

	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		ht_values = g_slist_prepend(ht_values, v);
		k = v = NULL;
	}

	return ht_values;
}

static GSList*
list_events(struct dir_run_info_s *info)
{
	GHashTable *ht;
	GSList *ht_values;

	ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
	if (!ht)
		return NULL;

	(void) get_one_event_per_container(ht, info->basedir, ".", info);

	ht_values = get_ht_values(ht);
	g_hash_table_destroy(ht);
	ht = NULL;

	return ht_values;
}

GSList*
agent_list_earliest_events(const gchar *dir, guint max, time_t delay, gboolean(*filter)(path_data_t *))
{
	struct dir_run_info_s info;

	GSList *events = NULL, *nth = NULL, *next = NULL;
	
	bzero(&info, sizeof(info));
	info.basedir = dir;
	info.max = max;
	info.now = time(0);
	info.delay = delay;
	info.filter = filter;

	if (NULL == (events = list_events(&info)))
		return NULL;

	events = g_slist_sort(events, (GCompareFunc)compare_path_data_time_ASC);

	/* Now truncate this list */
	if (NULL != (nth = g_slist_nth(events, max))) {
		next = nth->next;
		nth->next = NULL;
		if (next) {
			g_slist_foreach(next, g_free1, NULL);
			g_slist_free(next);
		}
	}

	return events;
}

int
path_get_sequence(const gchar *path, gint64 *i64)
{
	gssize str_len;
	gchar str[128];

	bzero(str, sizeof(str));
	str_len = getxattr(path, "user.grid.agent.incoming-sequence", str, sizeof(str));
	if (str_len <= 0)
		return -1;

	*i64 = g_ascii_strtoll(str, NULL, 10);
	errno = 0;
	return 0;
}

int
path_get_incoming_time(const gchar *path, time_t *t)
{
	gint64 i64;
	gssize str_len;
	gchar str[128];

	bzero(str, sizeof(str));
	str_len = getxattr(path, "user.grid.agent.incoming-time", str, sizeof(str));
	if (str_len < 0)
		return -1;
	if (str_len == 0) {
		errno = ERANGE;
		return -1;
	}

	i64 = g_ascii_strtoll(str, NULL, 10);
	if (i64 >= G_MAXLONG) {
		errno = ERANGE;
		return -1;
	}

	*t = i64;
	errno = 0;
	return 0;
}

int
path_get_container_id(const gchar *path, container_id_t *id, gchar *str, gsize str_len)
{
	gssize len;

	g_assert(str_len >= 65);

	bzero(str, str_len);
	len = getxattr(path, "user.grid.agent.incoming-container", str, str_len);

	if (len < 0)
		return -1;
	if (len != 64) {
		errno = EINVAL;
		return -1;
	}

	bzero(id, sizeof(container_id_t));
	if (!container_id_hex2bin(str, str_len, id, NULL)) {
		errno = EINVAL;
		return -1;
	}

	errno = 0;
	return 0;
}

