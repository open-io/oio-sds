#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.agent.event.common"
#endif

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

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

static gint 
compare_path_data_time_ASC(const struct path_data_s *p1, const struct path_data_s *p2)
{
	register gint64 cmp, i1, i2;

	i1 = p1->xattr_seq;
	i2 = p2->xattr_seq;
	cmp = i1 - i2;
	return (cmp < 0) ? -1 : ((cmp > 0) ? 1 : 0);
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

static guint
get_one_event_per_container2(GHashTable *ht, const gchar *dir, struct dir_run_info_s *info)
{
	const gchar *subdir;
	const gchar *path;
	static GDir *gdir = NULL;
	GError *err = NULL;
	guint count_entry = 0;

	/* If gdir is NULL, it should be (re)created */
	if (gdir == NULL) {
		gdir = g_dir_open(dir, 0, &err);
		if (!gdir) {
			ERROR("g_dir_open(%s) error : %s", dir, gerror_get_message(err));
			g_clear_error(&err);
			return 0;
		}
	}

	/* Go through hash (one level of 2 char) */
	while (NULL != (subdir = g_dir_read_name(gdir))) {
		gchar *hashpath = NULL;
		struct stat hashstat;

		memset(&hashstat, '\0', sizeof(hashstat));
		hashpath = g_strconcat(dir, G_DIR_SEPARATOR_S, subdir, NULL);

		if (-1 == stat(hashpath, &hashstat))
			WARN("stat(%s) error : %s", hashpath, strerror(errno));
		else if (S_ISDIR(hashstat.st_mode)) {
			GDir *hashdir = g_dir_open(hashpath, 0, &err);
			if (hashdir == NULL) {
				ERROR("g_dir_open(%s) error : %s", hashpath, gerror_get_message(err));
				g_clear_error(&err);
				continue;
			}

			/* Go through files in a hash dir */
			while (NULL != (path = g_dir_read_name(hashdir))) {
				struct path_data_s pd;
				gchar *fullpath;

				++ count_entry; 
				fullpath = g_strconcat(hashpath, G_DIR_SEPARATOR_S, path, NULL);

				bzero(&pd, sizeof(pd));
				g_snprintf(pd.relpath, sizeof(pd.relpath), "%s%c%s", subdir, G_DIR_SEPARATOR, path);
				pd.relpath_size = strlen(pd.relpath);

				if (-1 == stat(fullpath, &(pd.stat)))
					WARN("stat(%s) error : %s", fullpath, strerror(errno));
				else if (S_ISDIR(pd.stat.st_mode))
					WARN("Found dir [%s] in hash leaf: discarded", path);
				else if (S_ISREG(pd.stat.st_mode)) {
					if (0 != gridcluster_eventxattr_get_container_id(fullpath, &(pd.id), pd.str_cid, sizeof(pd.str_cid))) {
						DEBUG("Invalid event, missing XATTR (container) at [%s]", pd.relpath);
					} else if (0 != gridcluster_eventxattr_get_incoming_time(fullpath, &(pd.xattr_time))) {
						DEBUG("Invalid event, missing XATTR (time) at [%s]", pd.relpath);
					} else if (0 != gridcluster_eventxattr_get_seq(fullpath, &(pd.xattr_seq))) {
						DEBUG("Invalid event, missing XATTR (sequence) at [%s]", pd.relpath);
					} else if (event_is_delayed(info->now, info->delay, &pd)) {
						DEBUG("Delayed event at [%s]", pd.relpath);
					} else if (!info->filter || info->filter(&pd)) {
						keep_earliest_path_data(ht, &pd);
					} else {
						TRACE("CID[%s] TIME[%ld] SEQ[%"G_GINT64_FORMAT"] filtered at [%s]",
								pd.str_cid, pd.xattr_time, pd.xattr_seq, pd.relpath);
					}
				}

				g_free(fullpath);

				/* Stop the iterations as soon as the hashtable size reaches the maximum size */
				if (info->max && g_hash_table_size(ht) >= info->max) {
					g_free(hashpath);
					g_dir_close(hashdir);
					goto max_reached;
				}
			}
			g_dir_close(hashdir);
			hashdir = NULL;
		}
		g_free(hashpath);
	}
	g_dir_close(gdir);
	gdir = NULL;

max_reached:

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

	(void) get_one_event_per_container2(ht, info->basedir, info);

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

