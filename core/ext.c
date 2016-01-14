/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>

#include <glib.h>
#include <json.h>

#include "oio_core.h"
#include "internals.h"

#define PREPEND(Result,List) do { \
	next = (List)->next; \
	List->next = (Result); \
	(Result) = List; \
	List = next; \
} while (0)

time_hook_f oio_time_monotonic = NULL;
time_hook_f oio_time_real = NULL;
volatile int oio_sds_default_autocreate = 0;
volatile int oio_sds_no_shuffle = 0;
volatile int oio_dir_no_shuffle = 0;

static GSList*
gslist_merge_random (GSList *l1, GSList *l2)
{
	GSList *next, *result = NULL;

	while (l1 || l2) {
		if (l1 && l2) {
			if (g_random_boolean())
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
		else {
			if (l1)
				PREPEND(result,l1);
			else
				PREPEND(result,l2);
		}
	}

	return result;
}

static void
gslist_split_in_two (GSList *src, GSList **r1, GSList **r2)
{
	GSList *next, *l1 = NULL, *l2 = NULL;

	while (src) {
		if (src)
			PREPEND(l1, src);
		if (src)
			PREPEND(l2, src);
	}

	*r1 = l1, *r2 = l2;
}

GSList *
oio_ext_gslist_shuffle (GSList *src)
{
	GSList *l1=NULL, *l2=NULL;

	gslist_split_in_two(src, &l1, &l2);
	return gslist_merge_random(
		(l1 && l1->next) ? oio_ext_gslist_shuffle(l1) : l1,
		(l2 && l2->next) ? oio_ext_gslist_shuffle(l2) : l2);
}

void
oio_ext_array_shuffle (gpointer *array, gsize len)
{
	while (len-- > 1) {
		guint32 i = g_random_int_range (0, len+1);
		if (i == len)
			continue;
		gpointer tmp = array[i];
		array[i] = array[len];
		array[len] = tmp;
	}
}

gsize
oio_ext_array_partition (gpointer *array, gsize len,
		gboolean (*predicate)(gconstpointer))
{
	g_assert (array != NULL);
	g_assert (predicate != NULL);

	if (!len)
		return 0;

	/* qualify each item, so that we call the predicate only once */
	guchar *good = g_malloc0 (len);

	for (gsize i=0; i<len ;i++)
		good[i] = 0 != ((*predicate) (array[i]));

	/* partition the items, the predicate==TRUE first */
	for (gsize i=0; i<len ;i++) {
		if (good[i])
			continue;
		/* swap the items */
		gchar *tmp = array[len-1];
		array[len-1] = array[i];
		array[i] = tmp;
		/* swap the qualities */
		gboolean b = good[len-1];
		good[len-1] = good[i];
		good[i] = b;

		-- len;
		-- i;
	}

	g_free (good);
	return len;
}

GError *
oio_ext_extract_json (struct json_object *obj,
		struct oio_ext_json_mapping_s *tab)
{
	g_assert (obj != NULL);
	g_assert (tab != NULL);
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++)
		*(p->out) = NULL;
	if (!json_object_is_type(obj, json_type_object))
		return NEWERROR(400, "Not an object");
	for (struct oio_ext_json_mapping_s *p=tab; p->out ;p++) {
		struct json_object *o = NULL;
		if (!json_object_object_get_ex(obj, p->name, &o) || !o) {
			if (!p->mandatory)
				continue;
			return NEWERROR(400, "Missing field [%s]", p->name);
		}
		if (!json_object_is_type(o, p->type))
			return NEWERROR(400, "Invalid type for field [%s]", p->name);
		*(p->out) = o;
	}
	return NULL;
}

/* -------------------------------------------------------------------------- */

static void _free0 (gpointer p) { if (p) g_free(p); }

static GPrivate th_local_key_reqid = G_PRIVATE_INIT(_free0);

const char *
oio_ext_get_reqid (void)
{
	return g_private_get(&th_local_key_reqid);
}

void
oio_ext_set_reqid (const char *reqid)
{
	 g_private_replace (&th_local_key_reqid, g_strdup (reqid));
}

void
oio_ext_set_random_reqid (void)
{
	struct {
		pid_t pid:16;
		guint8 buf[14];
	} bulk;
	bulk.pid = getpid();
	oio_str_randomize(bulk.buf, sizeof(bulk.buf));

	char hex[33];
	oio_str_bin2hex((guint8*)&bulk, sizeof(bulk), hex, sizeof(hex));
	oio_ext_set_reqid(hex);
}

/* -------------------------------------------------------------------------- */

# ifdef HAVE_BACKTRACE
#warn "Backtrace enabled"
#include <execinfo.h>
#define STACK_MAX 8

GError *
oio_error_debug (GQuark gq, int code, const char *fmt, ...)
{
	void *frames[STACK_MAX];
	int nbframes = backtrace(frames, STACK_MAX);

	GString *gs = g_string_new("");
	char **strv = backtrace_symbols (frames, nbframes);
	if (strv) {
		for (int i=1; i<nbframes ;i++) {
			if (gs->len)
				g_string_append (gs, ",");
			char *s, *start = strv[i];
			if (NULL != (s = strchr(start, '(')))
				start = s+1;
			if (NULL != (s = strchr(start, '+')))
				*s = 0;
			if (NULL != (s = strchr(start, ')')))
				*s = 0;
			g_string_append (gs, start);
		}
		free (strv);
	}

	va_list args;
	va_start (args, fmt);
	GError *err = g_error_new_valist (gq, code, fmt, args);
	va_end (args);

	g_prefix_error (&err, "[%s] ", gs->str);
	g_string_free (gs, TRUE);
	return err;
}

#endif

gint64
oio_ext_real_time (void)
{
	if (oio_time_real)
		return (*oio_time_real)();
	return g_get_real_time();
}

gint64
oio_ext_monotonic_time (void)
{
	if (oio_time_monotonic)
		return (*oio_time_monotonic)();
	return g_get_monotonic_time();
}

void
oio_ext_init_test (int *argc, char ***argv)
{
	g_test_init (argc, argv, NULL);

	char *sep = strrchr ((*argv)[0], '/');
	g_set_prgname (sep ? sep+1 : (*argv)[0]);

	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	oio_log_init_level_from_env("G_DEBUG_LEVEL");
	g_log_set_default_handler(oio_log_stderr, NULL);
	oio_ext_set_random_reqid ();
}

/* -------------------------------------------------------------------------- */

/** @private */
struct maj_min_idle_s {
	guint major, minor;
	gint64 last_update;
	unsigned long long last_total_time;
	gdouble idle;
};

/** @private */
struct path_maj_min_s
{
	gint64 last_update;
	int major;
	int minor;
	gchar path[];
};

static GSList *io_cache = NULL;
static GMutex io_lock;

static GSList *majmin_cache = NULL;
static GMutex majmin_lock;

void _constructor_idle_cache (void);
void _destructor_idle_cache (void);


static void
_free_majmin_idle_list (GSList *l)
{
	void _clean_idle (struct maj_min_idle_s *p) {
		g_free (p);
	}
	g_slist_free_full (l, (GDestroyNotify)_clean_idle);
}

void __attribute__ ((constructor))
_constructor_idle_cache (void)
{
	static volatile guint lazy_init = 1;
	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_mutex_init (&io_lock);
			g_mutex_init (&majmin_lock);
		}
	}
}

void __attribute__ ((destructor))
_destructor_idle_cache (void)
{
	_constructor_idle_cache ();

	g_mutex_lock (&io_lock);
	_free_majmin_idle_list (io_cache);
	io_cache = NULL;
	g_mutex_unlock (&io_lock);

	g_mutex_lock (&majmin_lock);
	g_slist_free_full (majmin_cache, g_free);
	majmin_cache = NULL;
	g_mutex_unlock (&majmin_lock);
}

static gdouble
_compute_io_idle (guint major, guint minor)
{
	_constructor_idle_cache ();

	gdouble idle = 0.01;
	struct maj_min_idle_s *out = NULL;

	g_mutex_lock (&io_lock);
	gint64 now = oio_ext_monotonic_time ();

	/* locate the info in the cache */
	for (GSList *l=io_cache; l && !out ;l=l->next) {
		struct maj_min_idle_s *p = l->data;
		if (p && p->major == major && p->minor == minor)
			out = p;
	}
	if (!out) {
		out = g_malloc0 (sizeof(struct maj_min_idle_s));
		out->major = major;
		out->minor = minor;
		io_cache = g_slist_prepend (io_cache, out);
	}

	/* check its validity and reload if necessary */
	if (!out->last_update || (now - out->last_update) > G_TIME_SPAN_SECOND) {
		FILE *fst = fopen ("/proc/diskstats", "r");
		while (fst && !feof(fst) && !ferror(fst)) {
			char line[1024], name[256];
			if (!fgets (line, 1024, fst))
				break;
			guint fmajor, fminor;
			unsigned long long int
				rd, rd_merged, rd_sectors, rd_time,
				wr, wr_merged, wr_sectors, wr_time,
				total_progress, total_time, total_iotime;
			int rc = sscanf (line, "%u %u %s %llu %llu %llu %llu %llu"
					"%llu  %llu %llu %llu %llu %llu",
					&fmajor, &fminor, name,
					&rd, &rd_merged, &rd_sectors, &rd_time,
					&wr, &wr_merged, &wr_sectors, &wr_time,
					&total_progress, &total_time, &total_iotime);
			if (rc != 0) {
				gdouble spent = total_time - out->last_total_time; /* in ms */
				gdouble elapsed = now - out->last_update; /* in us */
				elapsed /= G_TIME_SPAN_MILLISECOND; /* in ms */
				out->idle = 1.0 - (spent / elapsed);
				out->last_update = now;
				out->last_total_time = total_time;
				break;
			}
		}
		if (fst)
			fclose (fst);
	}

	/* collect the up-to-date value */
	idle = out->idle;

	/* purge obsolete and exceeding entries of the cache */
	GSList *kept = NULL, *trash = NULL;
	for (GSList *l=io_cache; l ;l=l->next) {
		struct maj_min_idle_s *p = l->data;
		if ((now - p->last_update) > G_TIME_SPAN_HOUR)
			trash = g_slist_prepend (trash, p);
		else
			kept = g_slist_prepend (kept, p);
	}
	g_slist_free (io_cache);
	_free_majmin_idle_list (trash);
	io_cache = kept;
	g_mutex_unlock (&io_lock);

	return idle;
}

static int
_get_major_minor (const gchar *path, guint *pmaj, guint *pmin)
{
	_constructor_idle_cache ();

	struct path_maj_min_s *out = NULL;

	g_mutex_lock (&majmin_lock);
	gint64 now = oio_ext_monotonic_time ();
	/* ensure an entry exists */
	for (GSList *l=majmin_cache; l && !out ;l=l->next) {
		struct path_maj_min_s *p = l->data;
		if (p && !strcmp(path, p->path))
			out = p;
	}
	if (!out) {
		out = g_malloc0 (sizeof(struct path_maj_min_s) + strlen(path) + 1);
		strcpy (out->path, path);
		majmin_cache = g_slist_prepend (majmin_cache, out);
	}

	/* maybe refresh it */
	if (!out->last_update || (now - out->last_update) > 30 * G_TIME_SPAN_SECOND) {
		struct stat st;
		if (0 != stat(out->path, &st)) {
			out = NULL;
		} else {
			out->major = (guint) major(st.st_dev);
			out->minor = (guint) minor(st.st_dev);
			out->last_update = now;
		}
	}

	/* collect the up-to-date value */
	*pmaj = out->major;
	*pmin = out->minor;

	/* now purge the expired items */
	GSList *kept = NULL, *trash = NULL;
	for (GSList *l=majmin_cache; l ;l=l->next) {
		struct path_maj_min_s *p = l->data;
		if ((now - p->last_update) > G_TIME_SPAN_HOUR)
			trash = g_slist_prepend (trash, p);
		else
			kept = g_slist_prepend (kept, p);
	}
	g_slist_free_full (trash, g_free);
	g_slist_free (majmin_cache);
	majmin_cache = kept;
	g_mutex_unlock (&majmin_lock);

	return out != NULL;
}

gdouble
oio_sys_io_idle (const char *vol)
{
	guint maj, min;
	if (_get_major_minor(vol, &maj, &min))
		return _compute_io_idle(maj, min);
	return 0.01;
}

gdouble
oio_sys_space_idle (const char *vol)
{
	struct statfs sfs;
	if (statfs(vol, &sfs) < 0)
		return 0.0;
	gdouble free_inodes_d = sfs.f_ffree, total_blocks_d = sfs.f_blocks,
			free_blocks_d = sfs.f_bavail;
	if (free_blocks_d > free_inodes_d)
		free_blocks_d = free_inodes_d;
	if (free_blocks_d <= 0.0 || total_blocks_d <= 0.0)
		return 0.0;
	return free_blocks_d / total_blocks_d;
}

gdouble
oio_sys_cpu_idle (void)
{
	static gdouble ratio_idle = 0.01;
	static guint64 last_sum = 0;
	static guint64 last_idle = 0;
	static gint64 last_update = 0;
	static GMutex lock;
	static volatile guint lazy_init = 1;

	if (lazy_init) {
		if (g_atomic_int_compare_and_exchange(&lazy_init, 1, 0)) {
			g_mutex_init (&lock);
		}
	}

	gdouble out;

	g_mutex_lock (&lock);
	gint64 now = oio_ext_monotonic_time ();
	if (!last_update || ((now - last_update) > G_TIME_SPAN_SECOND)) {
		FILE *fst = fopen ("/proc/stat", "r");
		while (fst && !feof(fst) && !ferror(fst)) {
			char line[1024];
			if (!fgets (line, 1024, fst))
				break;
			if (!g_str_has_prefix(line, "cpu "))
				continue;
			char *p = g_strstrip(line + 4);
			long long unsigned int user = 0, nice = 0, sys = 0, idle = 0,
				 wait = 0, irq = 0, soft = 0, steal = 0, guest = 0,
				 guest_nice = 0;
			/* TODO linux provides 10 fields since Linux 2.6.33,
			 * and we should check the Linux verison to manage the
			 * old style with 7 fields for earlier releases. */
			int rc = sscanf(p, "%llu %llu %llu %llu %llu %llu %llu %llu"
					" %llu %llu", &user, &nice, &sys, &idle, &wait, &irq,
					&soft, &steal, &guest, &guest_nice);
			if (rc != 0) {
				guint64 sum = user + nice + sys + idle + wait + irq + soft
					+ steal + guest + guest_nice;
				if (sum > last_sum && idle > last_idle)
					ratio_idle = ((gdouble)(idle - last_idle)) /
						((gdouble)(sum - last_sum));
				last_sum = sum;
				last_idle = idle;
				last_update = now;
			}
			break;
		}
		if (fst)
			fclose (fst);
	}
	out = ratio_idle;
	g_mutex_unlock (&lock);

	return out;
}
