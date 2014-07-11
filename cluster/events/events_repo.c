#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gridcluster.events_repo"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <glib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <cluster/events/gridcluster_events.h>


static void
purify_basename(gchar *s)
{
	gchar c;

	if (!s)
		return;
	for (; (c = *s) ; s++) {
		if (!g_ascii_isprint(c) || g_ascii_isspace(c) ||
				c==G_DIR_SEPARATOR || c=='.')
			*s = '_';
	}
}


// TODO: FIXME: duplicate function with meta2v2/meta2_filters_action_events.c...
static gint64
get_id64(struct event_config_s *evt)
{
    gint64 res;

    g_mutex_lock(event_get_lock(evt));
    res = event_get_and_inc_seq(evt);
    g_mutex_unlock(event_get_lock(evt));

   return res;
}


/**
 * Write an event to the spool event manage directory
 * dirbase: directory base name, where the directory hashed+event file while be add
 */
GError*
gridcluster_event_SaveNewEvent(struct event_config_s *evt_config, gridcluster_event_t *evt)
{
	gchar tmppath[1024], dirname[1024], abspath[1024];
	GError *err = NULL;
	time_t now = time(0);
	int fd;

	GRID_INFO("Event config : [%s]", event_config_dump(evt_config));
	GRID_INFO("Writing event in [%s]", event_get_dir(evt_config));

	gchar *str_ueid     = gridcluster_event_get_string(evt, GRIDCLUSTER_EVTFIELD_UEID);
	gchar *str_aggrname = gridcluster_event_get_string(evt, GRIDCLUSTER_EVTFIELD_AGGRNAME);
	gchar *str_cid      = gridcluster_event_get_string(evt, GRIDCLUSTER_EVTFIELD_CID);
	purify_basename(str_aggrname);
	memset(tmppath, '\0', sizeof(tmppath));

	g_snprintf(dirname, sizeof(dirname), "%s%c%.2s", event_get_dir(evt_config),
			G_DIR_SEPARATOR, str_cid);
	GRID_INFO("dir path = [%s]", dirname);
	g_snprintf(abspath, sizeof(abspath), "%s%c%s", dirname, G_DIR_SEPARATOR,
			(str_aggrname ? str_aggrname : str_ueid));

retry:
	g_snprintf(tmppath, sizeof(tmppath), "%s%c.event-XXXXXX", dirname,
			G_DIR_SEPARATOR);

	GRID_INFO("tmp path for mkstemp = [%s]", tmppath);

	if (0 > (fd = g_mkstemp(tmppath))) {
		if (errno == ENOENT) {
			while (!err && 0 != g_mkdir_with_parents(dirname, 0755)) {
				if (errno != EEXIST)
					err = NEWERROR(500, "Event error (mkdir) : errno=%d (%s)",
							errno, strerror(errno));
				/* g_mkdir_with_parents() poorly manages concurency, so we try
				 * as long as we got race conditions clues. */
			}
			goto retry;
		}
		err = NEWERROR(500, "Event write error (mkstemp) : errno=%d (%s)",
				errno, strerror(errno));
	} else {
		GRID_INFO("fd opened");
		/* change file attribute */
		if (0 != fchmod(fd, 0644))
			err = NEWERROR(500, "Event error (chmod) : errno=%d (%s)",
					errno, strerror(errno));

		/* Set the file content */
		if (!err) {
			GByteArray *gba;

			if (!(gba = gridcluster_encode_event(evt, NULL)))
				err = NEWERROR(500, "Event error (encoding)");
			else {
				write(fd, gba->data, gba->len);
				g_byte_array_free(gba, TRUE);
				GRID_INFO("Event written");
			}
		}


		/* set extended attributes (XATTR) */
		if (!err) {
			GRID_INFO("Setting xattr");
			gchar str_now[64], str_seq[64];
			bzero(str_now, sizeof(str_now));
			bzero(str_seq, sizeof(str_seq));
			g_snprintf(str_now, sizeof(str_now), "%ld", now);
			g_snprintf(str_seq, sizeof(str_seq), "%"G_GINT64_FORMAT, get_id64(evt_config));
			if (   (-1 == fsetxattr(fd, GRIDCLUSTER_EVENT_XATTR_TIME, str_now, strlen(str_now), 0))
				|| (-1 == fsetxattr(fd, GRIDCLUSTER_EVENT_XATTR_SEQ,  str_seq, strlen(str_seq), 0))
				|| (-1 == fsetxattr(fd, GRIDCLUSTER_EVENT_XATTR_CID, str_cid, strlen(str_cid), 0)))
			{
				err = NEWERROR(500, "Event error (setxattr) : errno=%d (%s)",
						errno, strerror(errno));
			}
			GRID_INFO("xattr ok");
		}

		/* rename the file */
		if (!err) {
			GRID_INFO("going to rename...");
			if (0 != rename(tmppath, abspath)) {
				err = NEWERROR(500, "Event error (rename) : errno=%d (%s)",
						errno, strerror(errno));
				(void) unlink(tmppath);
			}
			GRID_INFO("Rename done, event ok");
		}

		metautils_pclose(&fd);
	}

	if (str_aggrname)
		g_free(str_aggrname);
	if (str_ueid)
		g_free(str_ueid);
	if (str_cid)
		g_free(str_cid);
	return err;
}


int
gridcluster_eventxattr_get_incoming_time(const gchar *path, time_t *t)
{
	gint64 i64;
	gssize str_len;
	gchar str[128];

	bzero(str, sizeof(str));
	str_len = getxattr(path, GRIDCLUSTER_EVENT_XATTR_TIME, str, sizeof(str));
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
gridcluster_eventxattr_get_seq(const gchar *path, gint64 *i64)
{
	gssize str_len;
	gchar str[128];

	bzero(str, sizeof(str));
	str_len = getxattr(path, GRIDCLUSTER_EVENT_XATTR_SEQ, str, sizeof(str));
	if (str_len <= 0)
		return -1;

	*i64 = g_ascii_strtoll(str, NULL, 10);
	errno = 0;
	return 0;
}


int
gridcluster_eventxattr_get_container_id(const gchar *path, container_id_t *id, gchar *str, gsize str_len)
{
	gssize len;

	g_assert(str_len >= 65);

	bzero(str, str_len);
	len = getxattr(path, GRIDCLUSTER_EVENT_XATTR_CID, str, str_len);

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

