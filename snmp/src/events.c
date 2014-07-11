#ifndef G_LOG_DOMAIN
#  define G_LOG_DOMAIN "grid.snmp.event"
#endif

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <glib.h>

#include "events.h"


//TODO: FIXME: same function on cluster/agent/event_common.c 
static int
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

gboolean
stat_events(spooldir_stat_t *spstat, const gchar *dir)
{
	const gchar *path;
	GDir *gdir = NULL;
	GError *err = NULL;

	if (spstat == NULL)
		return FALSE;

	gdir = g_dir_open(dir, 0, &err);
	if (!gdir) {
		DEBUGMSGTL(("grid", "g_dir_open(%s) error : %s", dir, err->message));
		g_clear_error(&err);
		return FALSE;
	}

	while (NULL != (path = g_dir_read_name(gdir))) {
		gchar *fullpath;
		struct stat evt_stat;
		time_t xattr_time;
		time_t age = 0;

		fullpath = g_strconcat(dir, G_DIR_SEPARATOR_S, path, NULL);

		if (-1 == stat(fullpath, &evt_stat))
			DEBUGMSGTL(("grid", "stat(%s) error : %s", fullpath, strerror(errno)));
		else if (S_ISDIR(evt_stat.st_mode))
			stat_events(spstat, fullpath);
		else if (S_ISREG(evt_stat.st_mode)) {
			if (0 != path_get_incoming_time(fullpath, &xattr_time))
				DEBUGMSGTL(("grid", "Invalid event, missing XATTR (time) at [%s]", fullpath));
			else {
				spstat->nb_evt++;
				age = time(NULL) - xattr_time;
				spstat->total_age += age;
				if (spstat->oldest < (guint32)age)
					spstat->oldest = age;
			}
		}

		g_free(fullpath);
	}
	g_dir_close(gdir);

	return TRUE;
}

GSList*
list_ns(const gchar * dir)
{
	const gchar *path;
	GDir *gdir = NULL;
	GSList *ns_list = NULL;
	GError *err;

	err = NULL;
	gdir = g_dir_open(dir, 0, &err);
	if (!gdir) {
		DEBUGMSGTL(("grid", "g_dir_open(%s) error : %s", dir, err->message));
		g_clear_error(&err);
		return NULL;
	}

	while (NULL != (path = g_dir_read_name(gdir)))
		ns_list = g_slist_prepend(ns_list, g_strdup(path));

	g_dir_close(gdir);

	return ns_list;
}
