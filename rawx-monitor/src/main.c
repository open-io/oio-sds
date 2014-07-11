#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "vol.monitor"
#endif

#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <gridinit-utils.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>

#include "filer_monitor.h"
#ifdef HAVE_NETAPP
# include "netapp.h"
#endif
#ifdef HAVE_CORAID
# include "coraid.h"
#endif
#ifdef HAVE_FUJI
# include "fuji.h"
#endif
#ifdef HAVE_HDS
# include "hds.h"
#endif
#ifdef HAVE_EMC
# include "emc.h"
#endif

#define FILER_CONFIGURED(...) (filer_info.host[0]!='\0' && filer_info.volume[0]!='\0')

#define CHILD_KEY "service"

#define TAGNAME_UP "tag.up"

#ifndef  PATH_MAXLEN
# define PATH_MAXLEN 2048
#endif

struct volume_cfg_s {
	gchar docroot[PATH_MAXLEN];
	gchar mount_point[PATH_MAXLEN];
	gchar device_path[PATH_MAXLEN];
	gchar type[32];
};

struct service_cfg_s {
	gchar str_addr[STRLEN_ADDRINFO];
	addr_info_t addr;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar type_name[LIMIT_LENGTH_SRVTYPE];
	gchar location_name[LIMIT_LENGTH_LOCNAME];
	gchar stgclass_name[LIMIT_LENGTH_STGCLASS];
};

struct filer_cfg_s {
	gchar host[512];
	gchar volume[PATH_MAXLEN];
	struct {
		struct filer_auth_s filer;
		struct snmp_auth_s snmp;
	} auth;
};

/* ------------------------------------------------------------------------- */

static gboolean pidfile_written = FALSE;
static gchar pidfile_path[PATH_MAXLEN] = {0,0,0};
static struct stat pidfile_stat;

static volatile int flag_daemon = 0;

static volatile int flag_continue = ~0;

static struct service_cfg_s service;

static struct volume_cfg_s fs_info;

static struct filer_cfg_s filer_info;

/* ------------------------------------------------------------------------- */

static void
sleep_at_most(GTimer *timer, gdouble seconds)
{
	struct timeval tv;
	gdouble d_elapsed;

	while ((d_elapsed = g_timer_elapsed(timer, NULL)) < seconds) {
		tv.tv_sec = 0;
		tv.tv_usec = floor((seconds - d_elapsed) * 1000000.0);
		select(0,NULL,NULL,NULL, &tv);
	}
	g_timer_reset(timer);
}

/* ------------------------------------------------------------------------- */

static void
_srvinfo_set_down(struct service_info_s *si)
{
	service_tag_set_value_boolean(service_info_ensure_tag(si->tags, TAGNAME_UP), FALSE);
}

static void
_srvinfo_populate_with_rawx_stats(struct service_info_s *si)
{
	/* execute rawx stat request and extract stats */

	ne_session *session=NULL;
	ne_request *request=NULL;
	GError *local_error = NULL;
	gdouble reqpersec = 0;
	gint64 reqavgtime = 0;
	gdouble putpersec = 0;
	gint64 putavgtime = 0;
	gdouble getpersec = 0;
	gint64 getavgtime = 0;
	gdouble delpersec = 0;
	gint64 delavgtime = 0;

	int stat_extractor (void *uData, const char *b, const size_t bSize) {
		(void)uData;
		(void)bSize;
		char **tok = g_strsplit(b, "\n", 0);
		for (uint i = 0; i < g_strv_length(tok); i++) {
			if(g_str_has_prefix(tok[i], "rawx.reqpersec")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					reqpersec = g_ascii_strtod(p + 1, NULL);
			}
			if(g_str_has_prefix(tok[i], "rawx.avreqtime")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					reqavgtime = g_ascii_strtoll(p + 1, NULL, 10);
			}
			if(g_str_has_prefix(tok[i], "rawx.reqputpersec")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					putpersec = g_ascii_strtod(p + 1, NULL);
			}
			if(g_str_has_prefix(tok[i], "rawx.avputreqtime")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					putavgtime = g_ascii_strtoll(p + 1, NULL, 10);
			}
			if(g_str_has_prefix(tok[i], "rawx.reqgetpersec")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					getpersec = g_ascii_strtod(p + 1, NULL);
			}
			if(g_str_has_prefix(tok[i], "rawx.avgetreqtime")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					getavgtime = g_ascii_strtoll(p + 1, NULL, 10);
			}
			if(g_str_has_prefix(tok[i], "rawx.reqdelpersec")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					delpersec = g_ascii_strtod(p + 1, NULL);
			}
			if(g_str_has_prefix(tok[i], "rawx.avdelreqtime")) {
				char *p = strrchr(tok[i], ' ');
				if(NULL != p)
					delavgtime = g_ascii_strtoll(p + 1, NULL, 10);
			}
		}
		if (NULL != tok)
			g_strfreev(tok);
		return 0;
       }


       gchar dst[128];
       guint16 port = 0;

       if (!addr_info_get_addr(&(si->addr), dst, sizeof(dst), &port)) {
	       DEBUG("Failed to extract address info from rawx");
	       goto end;
       }

       session = ne_session_create("http", dst, port);

       if (!session) {
	       DEBUG("Failed to create neon session");
	       goto end;
       }

       ne_set_connect_timeout(session, 10);
       ne_set_read_timeout(session, 30);

       request = ne_request_create (session, "GET", "/stat");
       if(!request) {
	       DEBUG("Failed to create neon request");
	       goto end;
       }

       ne_add_response_body_reader(request, ne_accept_2xx, stat_extractor, NULL);
       ne_request_dispatch(request);

       DEBUG("Stats from rawx : reqpersec = %f | reqavgtime = %"G_GINT64_FORMAT,
			reqpersec, reqavgtime);

       service_tag_set_value_float(service_info_ensure_tag(si->tags, "stat.total_reqpersec"), reqpersec);
       service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.total_avreqtime"), reqavgtime);
       service_tag_set_value_float(service_info_ensure_tag(si->tags, "stat.put_reqpersec"), putpersec);
       service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.put_avreqtime"), putavgtime);
       service_tag_set_value_float(service_info_ensure_tag(si->tags, "stat.get_reqpersec"), getpersec);
       service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.get_avreqtime"), getavgtime);
       service_tag_set_value_float(service_info_ensure_tag(si->tags, "stat.del_reqpersec"), delpersec);
       service_tag_set_value_i64(service_info_ensure_tag(si->tags, "stat.del_avreqtime"), delavgtime);

end:
       if(NULL != local_error)
	       g_clear_error(&local_error);
       if (NULL != request)
	       ne_request_destroy (request);
       if (NULL != session)
	       ne_session_destroy (session);
}

static void
_srvinfo_populate_with_filer_info(struct service_info_s *si, struct filer_s *filer, const char *filer_volume)
{
	GError *error_local;
	struct volume_s *vol;
	struct volume_statistics_s vol_stats;
	struct enterprise_s *enterprise;

	error_local = NULL;
	enterprise = filer->enterprise;

	XTRACE("Monitoring round...");

	if (!enterprise->refresh_filer(filer, &error_local)) {
		WARN("Filer refresh failure for [%s] : %s", filer->str_addr,
			gerror_get_message(error_local));
		_srvinfo_set_down(si);
	}
	else {
		vol = enterprise->get_named_volume(filer, filer_volume, &error_local);
		if (!vol) {
			ERROR("Volume not found [%s]:[%s] : %s", filer->str_addr, filer_volume,
					gerror_get_message(error_local));
			_srvinfo_set_down(si);
		}
		else {
			bzero(&vol_stats, sizeof(vol_stats));
			if (!enterprise->monitor_volume(vol, &vol_stats, &error_local)) {
				ERROR("Failed to monitor [%s]:[%s] : %s", filer->str_addr, filer_volume,
						gerror_get_message(error_local));
				_srvinfo_set_down(si);
			}
			else {
				gint64 space_total, space_idle;

				space_total = vol_stats.free_space + vol_stats.used_space;
				space_idle = (100LL * vol_stats.free_space) / space_total;

				service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_IOIDLE_NAME),
						MIN(vol_stats.cpu_idle, MIN(vol_stats.io_idle, vol_stats.perf_idle)));
				service_tag_set_value_i64(service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME),
						space_idle);
			}
		}
	}

	if (error_local)
		g_clear_error(&error_local);
}

static gpointer
thread_function_monitor(gpointer p)
{
	GTimer *timer;
	struct service_info_s *si;
	struct filer_s *filer;

	metautils_ignore_signals();
	si = p;
	filer = NULL;
	timer = g_timer_new();

	if (strlen(fs_info.docroot) > 0) {
		INFO("Starting the monitoring of %s at [%s] in [%s]", service.type_name,
				service.str_addr, fs_info.docroot);
	} else {
		INFO("Starting the monitoring of %s at [%s]", service.type_name,
		                service.str_addr);
	}

	/* Prepare the filer monitoring if necessary */
	if (!FILER_CONFIGURED())
		INFO("No need to monitor a filer");
	else {
		INFO("Initiating the filer monitoring");
		while (flag_continue && !filer) {
			GError *error_local = NULL;

			filer = filer_init(filer_info.host, &(filer_info.auth.snmp),
				&(filer_info.auth.filer), &error_local);
			if (!filer) {
				ERROR("Failed to init the filer : %s", gerror_get_message(error_local));
				_srvinfo_set_down(si);
				sleep_at_most(timer, 1.0);
			}
			if (error_local)
				g_clear_error(&error_local);
		}
	}

	/* Start the monitoring loop */
	while (flag_continue) {

		/* There is only 1 child registered. Then if the count of process
		 * the signal 0 could be sent is greater than 0, this means the
		 * child is still up. */
		if (!supervisor_children_killall(0)) {
			/* The RAWX service is down, nevermind its filer's state */
			DEBUG("%s service is down", service.type_name);
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, TAGNAME_UP), FALSE);
			register_namespace_service(si, NULL);
		}
		else {
			GError *error_local = NULL;

			/* The RAWX seems UP, then check its storage state. */
			TRACE("%s service is up", service.type_name);
			service_tag_set_value_boolean(service_info_ensure_tag(si->tags, TAGNAME_UP), TRUE);
			if (FILER_CONFIGURED())
				_srvinfo_populate_with_filer_info(si, filer, filer_info.volume);

			_srvinfo_populate_with_rawx_stats(si);

			if (!register_namespace_service(si, &error_local)) {
				WARN("Failed to register the %s: %s", service.type_name,
						gerror_get_message(error_local));
			}

			if (error_local)
				g_clear_error(&error_local);
		}

		sleep_at_most(timer, 1.0);
	}

	if (filer)
		filer_fini(filer);
	g_timer_reset(timer);
	return p;
}

/* Path utilities ---------------------------------------------------------- */

static gboolean
_path_dereference_symlinks(const gchar *path, gchar *dst, gsize dst_size, GError **error)
{
	gsize dst_offset;
	gchar **tokens, **tok;
	gchar current_path[1024], current_link[512];

	memset(dst, 0x00, dst_size);
	dst_offset = 0;

	/* Sanity checks. Hereafter, the we shuld be sure the path exists and
	 * contains no circular dependencies */
	if (!path || !*path) {
		GSETERROR(error, "No path");
		return FALSE;
	}
	if (*path != '/') {
		GSETERROR(error, "Path is not absolute");
		return FALSE;
	}
	if (!g_file_test(path, G_FILE_TEST_EXISTS)) {
		GSETERROR(error, "%s : %s", path, strerror(errno));
		return FALSE;
	}

	/* Now work on the path elements */
	tokens = g_strsplit(path,"/",0);
	if (!tokens) {
		GSETERROR(error, "Failed to split path with '/'");
		return FALSE;
	}
	for (tok=tokens; *tok ;tok++) {

		if (!**tok) /* ignores '/' sequences */
			continue;

		int offset_int = dst_offset;
		g_snprintf(current_path, sizeof(current_path), "%.*s/%s", offset_int, dst, *tok);

		if (!g_file_test(current_path, G_FILE_TEST_EXISTS))
			return FALSE;

		if (g_file_test(current_path, G_FILE_TEST_IS_SYMLINK)) {
			memset(current_link, 0x00, sizeof(current_link));
			readlink(current_path, current_link, sizeof(current_link));

			if (*current_link == '/')
				dst_offset += g_snprintf(dst, dst_size, "%s", current_link);
			else
				dst_offset += g_snprintf(dst+dst_offset, dst_size-dst_offset, "/%s", current_link);
		}
		else {
			dst_offset += g_snprintf(dst+dst_offset, dst_size-dst_offset, "/%s", *tok);
		}
	}

	return TRUE;
}

static gboolean
_path_get_mountpoint(const gchar *path, struct volume_cfg_s *mfs, GError **error)
{
	FILE *stream_proc;

	bzero(mfs, sizeof(*mfs));
	if (!_path_dereference_symlinks(path, mfs->docroot, sizeof(mfs->docroot)-1, error)) {
		GSETERROR(error, "Failed to dereference symlinks for [%s]", path);
		return FALSE;
	}
	INFO("Docroot real path is [%s]", mfs->docroot);


	stream_proc = fopen("/proc/mounts", "r");
	if (!stream_proc) {
		GSETERROR(error, "fopen(/proc/mounts) error : %s", strerror(errno));
		return FALSE;
	}
	while (!feof(stream_proc) && !ferror(stream_proc)) {
		gchar line[1024], **tokens;
		const gchar *mp;
		const gchar *type;
		const gchar *dev;

		if (!fgets(line, sizeof(line), stream_proc))
			break;
		tokens = g_strsplit(line, " ", 4);
		dev = tokens[0];
		mp = tokens[1];
		type = tokens[2];

		/*TODO we could ensure /proc/mounts only contains names with*/
		if (g_str_has_prefix(mfs->docroot, mp)) {
			DEBUG("potential match : [%s] <- [%s]", mp, dev);
			if (!*(mfs->mount_point) || strlen(mp) > strlen(mfs->mount_point)) {
				/* new best-match found */

				bzero(mfs->type, sizeof(mfs->type));
				g_strlcpy(mfs->type, type, sizeof(mfs->type)-1);

				bzero(mfs->mount_point, sizeof(mfs->mount_point));
				g_strlcpy(mfs->mount_point, mp, sizeof(mfs->mount_point)-1);

				bzero(mfs->device_path, sizeof(mfs->device_path));
				g_strlcpy(mfs->device_path, dev, sizeof(mfs->device_path)-1);
			}
		}
		g_strfreev(tokens);
	}
	fclose(stream_proc);

	DEBUG("Volume config : docroot=%s mountpoint=%s device=%s", mfs->docroot, mfs->mount_point, mfs->device_path);
	return TRUE;
}

/* ------------------------------------------------------------------------- */

static gboolean
_cfg_check(GError **error)
{
	char filer_addr[sizeof(fs_info.device_path)];
	char filer_volume[sizeof(fs_info.device_path)];

	if (0 == g_ascii_strcasecmp(fs_info.type,"nfs")) {
		int len;
		char *str;

		len = strlen(fs_info.device_path);
		str = strrchr(fs_info.device_path, ':');
		if (!str || len < 3) {
			GSETERROR(error, "Invalid NFS docroot");
			return FALSE;
		}
		bzero(filer_addr, sizeof(filer_addr));
		bzero(filer_volume, sizeof(filer_volume));
		g_strlcpy(filer_addr, fs_info.device_path, fs_info.device_path - str);
		g_strlcpy(filer_volume, str+1, sizeof(filer_volume)-1);
	}

	TRACE("Configuration OK");
	return TRUE;
}

static gboolean
_cfg_value_is_true(const gchar *val)
{
	return val && (
		   0==g_ascii_strcasecmp(val,"true")
		|| 0==g_ascii_strcasecmp(val,"yes")
		|| 0==g_ascii_strcasecmp(val,"enable")
		|| 0==g_ascii_strcasecmp(val,"enabled")
		|| 0==g_ascii_strcasecmp(val,"on"));
}

static gboolean
_cfg_section_volume(GKeyFile *kf, const gchar *section, GError **error)
{
	gchar *str, docroot[PATH_MAXLEN];

	/* Get the mandatory docroot */
	str = g_key_file_get_value(kf, section, "docroot", NULL);
	if (!str) {
		GSETERROR(error, "Key 'docroot' not found (mandatory!)");
		return FALSE;
	}
	bzero(docroot, sizeof(docroot));
	g_strlcpy(docroot, str, sizeof(docroot)-1);
	g_free(str);

	/* ... then investigate about a possible filer mount */
	INFO("Configured docroot [%s]", docroot);
	if (!_path_get_mountpoint(docroot, &fs_info, error)) {
		GSETERROR(error, "No mount point found for %s", docroot);
		return FALSE;
	}

	INFO("Docroot mountpoint is [%s]", fs_info.docroot);
	return TRUE;
}

static gboolean
_cfg_section_child(GKeyFile *kf, const gchar *section, GError **error)
{
	gboolean rc;
	gchar *str;

	/* First test the onl mandatory field */
	str = g_key_file_get_value(kf, section, "command", error);
	if (!str) {
		GSETERROR(error, "Key 'command' not found (mandatory!)");
		return FALSE;
	}
	rc = supervisor_children_register(CHILD_KEY, str, error);
	g_free(str);
	if (!rc) {
		GSETERROR(error, "Canot register a new child");
		return FALSE;
	}

	supervisor_children_enable(CHILD_KEY, 1);
	supervisor_children_status(CHILD_KEY, 1);
	supervisor_children_set_respawn(CHILD_KEY, 0);
	supervisor_children_set_delay(CHILD_KEY, 0);

	/* Should the rawx-monitor make the Service respawn ?
	 * Default : NO ! Remember the rawx-monitor will exit
	 * if the underlying service stops and is not respawned */
	if (NULL != (str = g_key_file_get_value(kf, section, "respawn", NULL))) {
		supervisor_children_set_respawn(CHILD_KEY, _cfg_value_is_true(str));
		g_free(str);
	}

	/* Set the rawx-monitor resource limits. It uses the  */
	struct {
		long core_size;
		long stack_size;
		long max_files;
	} rlimits;

	str = g_key_file_get_value(kf, section, "rlimit.core_size", NULL);
	if (!str)
		str = g_strdup("-1");
	rlimits.core_size = atol(str);
	g_free(str);

	str = g_key_file_get_value(kf, section, "rlimit.stack_size", NULL);
	if (!str)
		str = g_strdup("1024");
	rlimits.stack_size = atol(str);
	g_free(str);

	str = g_key_file_get_value(kf, section, "rlimit.max_files", NULL);
	if (!str)
		str = g_strdup("32768");
	rlimits.max_files = atol(str);
	g_free(str);

	supervisor_limit_set(SUPERV_LIMIT_THREAD_STACK, rlimits.stack_size);
	supervisor_limit_set(SUPERV_LIMIT_CORE_SIZE, rlimits.core_size);
	supervisor_limit_set(SUPERV_LIMIT_MAX_FILES, rlimits.max_files);

	return TRUE;
}

static gboolean
_cfg_section_service(GKeyFile *kf, const gchar *section, GError **error)
{
	gchar *str;

	/* Load the 3 mandatory keys of such a section */
	str = g_key_file_get_value(kf, section, "ns", error);
	if (!str) {
		GSETERROR(error, "Key 'ns' not found (mandatory!)");
		return FALSE;
	}
	bzero(service.ns_name, sizeof(service.ns_name));
	g_strlcpy(service.ns_name, str, sizeof(service.ns_name)-1);
	g_free(str);

	str = g_key_file_get_value(kf, section, "addr", error);
	if (!str) {
		GSETERROR(error, "Key 'addr' not found (mandatory!)");
		return FALSE;
	}
	bzero(service.str_addr, sizeof(service.str_addr));
	g_strlcpy(service.str_addr, str, sizeof(service.str_addr)-1);
	g_free(str);

	str = g_key_file_get_value(kf, section, "type", error);
	if (!str) {
		GSETERROR(error, "Key 'type' not found (mandatory!)");
		return FALSE;
	}
	bzero(service.type_name, sizeof(service.type_name));
	g_strlcpy(service.type_name, str, sizeof(service.type_name)-1);
	g_free(str);

	str = g_key_file_get_value(kf, section, "location", error);
	bzero(service.location_name, sizeof(service.location_name));
	/* allow service to start without location url */
	if (NULL != str) {
		g_strlcpy(service.location_name, str, sizeof(service.location_name)-1);
		g_free(str);
	} else {
		g_clear_error(error);
	}

	/* allow to start without storage class */
	str = g_key_file_get_value(kf, section, "stgclass", error);
	bzero(service.stgclass_name, sizeof service.stgclass_name);
	if (str != NULL) {
		g_strlcpy(service.stgclass_name, str, sizeof service.stgclass_name);
		g_free(str);
	} else {
		g_clear_error(error);
	}

	/* Check the address exists */
	if (!l4_address_init_with_url(&(service.addr), service.str_addr, error)) {
		GSETERROR(error, "Invalid service address");
		return FALSE;
	}

	return TRUE;
}

static gboolean
_cfg_section_default(GKeyFile *kf, const gchar *section, GError **error)
{
	gchar *str;

	(void) error;

	str = g_key_file_get_value(kf, section, "daemon", NULL);
	if (str) {
		flag_daemon = ((0 == g_ascii_strcasecmp(str, "true"))
			|| (0 == g_ascii_strcasecmp(str, "on"))
			|| (0 == g_ascii_strcasecmp(str, "yes"))
			|| (0 == g_ascii_strcasecmp(str, "enable"))
			|| (0 == g_ascii_strcasecmp(str, "enabled")));
		g_free(str);
	}
	INFO("Daemonize set to [%s]", flag_daemon?"ENABLED":"DISABLED");

	str = g_key_file_get_value(kf, section, "pidfile", NULL);
	if (!str) {
		bzero(pidfile_path, sizeof(pidfile_path));
	}
	else {
		/* Removes a preceeding pidfile if it changed */
		if (*pidfile_path && g_ascii_strcasecmp(pidfile_path, str)
			&& g_file_test(pidfile_path, G_FILE_TEST_IS_REGULAR|G_FILE_TEST_EXISTS))
				g_remove(pidfile_path);

		/* Save the latest */
		bzero(pidfile_path, sizeof(pidfile_path));
		g_strlcpy(pidfile_path, str, sizeof(pidfile_path)-1);
		g_free(str);

		INFO("Pidfile path set to [%s]", pidfile_path);
	}

	return TRUE;
}

static gboolean
_cfg_read(const gchar *cfg_path, GError **error)
{
	GKeyFile *kf = NULL;
	gboolean rc = FALSE;
	gchar **sections, **p_section;

	kf = g_key_file_new();
	if (!g_key_file_load_from_file(kf, cfg_path, G_KEY_FILE_NONE, error)) {
		g_key_file_free(kf);
		GSETERROR(error, "Invalid file", cfg_path);
		return FALSE;
	}

	sections = g_key_file_get_groups(kf, NULL);
	if (sections) {
		for (p_section=sections; *p_section ;p_section++) {
			if (!g_ascii_strcasecmp(*p_section, "default")) {
				INFO("Loading main configuration from section [%s]", *p_section);
				if (!_cfg_section_default(kf, *p_section, error)) {
					GSETERROR(error, "Error in section [%s]", *p_section);
					goto label_exit;
				}
			}
			else if (!g_ascii_strcasecmp(*p_section, "service")) {
				INFO("Loading service configuration from section [%s]", *p_section);
				if (!_cfg_section_service(kf, *p_section, error)) {
					GSETERROR(error, "Error in section [%s]", *p_section);
					goto label_exit;
				}
			}
			else if (!g_ascii_strcasecmp(*p_section, "volume")) {
				INFO("Loading volume configuration from section [%s]", *p_section);
				if (!_cfg_section_volume(kf, *p_section, error)) {
					GSETERROR(error, "Error in section [%s]", *p_section);
					NOTICE("If you are running a rainx, please don't set [Volume] section.");
					goto label_exit;
				}
			}
			else if (!g_ascii_strcasecmp(*p_section, "child")) {
				INFO("Loading child configuration from section [%s]", *p_section);
				if (!_cfg_section_child(kf, *p_section, error)) {
					GSETERROR(error, "Error in section [%s]", *p_section);
					goto label_exit;
				}
			}
			else {
				NOTICE("Configuration section ignored [%s]", *p_section);
			}
		}
		g_strfreev(sections);
	}
	rc = TRUE;

label_exit:
	g_key_file_free(kf);
	return rc;
}

static void
main_write_pid_file(void)
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
delete_pid_file(void)
{
	struct stat current_pidfile_stat;

	if (!pidfile_written) {
		INFO("No pidfile to delete");
		return;
	}
	if (-1 == stat(pidfile_path, &current_pidfile_stat)) {
		WARN("Unable to remove pidfile at [%s] : %s", pidfile_path, strerror(errno));
		return;
	}
	if (current_pidfile_stat.st_ino != pidfile_stat.st_ino) {
		WARN("Current and old pidfile differ, it is unsafe to delete it");
		return;
	}

	if (-1 == unlink(pidfile_path))
		WARN("Failed to unlink [%s] : %s", pidfile_path, strerror(errno));
	else {
		NOTICE("Deleted [%s]", pidfile_path);
		pidfile_written = FALSE;
	}
}

static void
main_sighandler_noop(int s)
{
	signal(s, main_sighandler_noop);
}

static void
main_sighandler(int s)
{
	signal(s, main_sighandler);
	switch (s) {
		case SIGCHLD:
		case SIGQUIT:
		case SIGINT:
		case SIGTERM:
		case SIGHUP:
		case SIGABRT:
			flag_continue = FALSE;
			return;
	}
}

static struct service_info_s*
main_prepare_srvinfo(void)
{
	struct service_info_s *si;

	/* Prepare the Gridcluster service description. Prepare the tags with
	 * some basic fields */
	si = g_malloc0(sizeof(struct service_info_s));
	g_strlcpy(si->ns_name, service.ns_name, sizeof(si->ns_name)-1);
	g_strlcpy(si->type, service.type_name, sizeof(si->type)-1);
	memcpy(&(si->addr), &(service.addr), sizeof(addr_info_t));

	si->tags = g_ptr_array_sized_new(6U);

	service_tag_set_value_macro(service_info_ensure_tag(si->tags,NAME_MACRO_CPU_NAME),
			NAME_MACRO_CPU_TYPE, NULL);
	if (strlen(fs_info.docroot) > 0) {
		service_tag_set_value_macro(
				service_info_ensure_tag(si->tags, NAME_MACRO_IOIDLE_NAME),
				NAME_MACRO_IOIDLE_TYPE, fs_info.docroot);
		service_tag_set_value_macro(
				service_info_ensure_tag(si->tags, NAME_MACRO_SPACE_NAME),
				NAME_MACRO_SPACE_TYPE, fs_info.docroot);
		service_tag_set_value_string(
				service_info_ensure_tag(si->tags, NAME_TAGNAME_RAWX_VOL),
				fs_info.docroot);
	}
	if (strlen(service.location_name) > 0) {
		service_tag_set_value_string(service_info_ensure_tag(si->tags,
				NAME_TAGNAME_RAWX_LOC), service.location_name);
	}
	if (strlen(service.stgclass_name) > 0) {
		service_tag_set_value_string(service_info_ensure_tag(si->tags,
				NAME_TAGNAME_RAWX_STGCLASS), service.stgclass_name);
	}

	_srvinfo_set_down(si);

	return si;
}

static void
service_info_down_and_clean(service_info_t *si)
{
	GError *error_local = NULL;
	if (!si)
		return;
	_srvinfo_set_down(si);
	if (!register_namespace_service(si, &error_local))
		WARN("Failed to register the %s: %s", service.type_name,
				gerror_get_message(error_local));
	if (error_local)
		g_clear_error(&error_local);
	service_info_clean(si);
}

static void
_main_init(void)
{
	bzero(pidfile_path, sizeof(pidfile_path));
	bzero(&pidfile_stat, sizeof(pidfile_stat));
	bzero(&fs_info, sizeof(fs_info));
	bzero(&filer_info, sizeof(filer_info));
	bzero(&service, sizeof(service));

	freopen( "/dev/null", "r", stdin);

	signal(SIGTERM, main_sighandler);
	signal(SIGINT,  main_sighandler);
	signal(SIGALRM, main_sighandler);
	signal(SIGQUIT, main_sighandler);
	signal(SIGHUP,  main_sighandler);
	signal(SIGPIPE, main_sighandler);
	signal(SIGUSR1, main_sighandler);
	signal(SIGUSR2, main_sighandler);
	signal(SIGCHLD, main_sighandler);

	if (!g_thread_supported ())
		g_thread_init (NULL);
	if (log4c_init())
		g_printerr("No log4c available : %s\n", strerror(errno));
}

static void
_main_ignore_signals(void)
{
	signal(SIGTERM, main_sighandler_noop);
	signal(SIGINT,  main_sighandler_noop);
	signal(SIGALRM, main_sighandler_noop);
	signal(SIGQUIT, main_sighandler_noop);
	signal(SIGHUP,  main_sighandler_noop);
	signal(SIGPIPE, main_sighandler_noop);
	signal(SIGUSR1, main_sighandler_noop);
	signal(SIGUSR2, main_sighandler_noop);
	signal(SIGCHLD, main_sighandler_noop);
	metautils_ignore_signals();
}

int
main(int argc, char ** argv)
{
	int rc = -1;
	struct service_info_s *si = NULL;
	GThread *th = NULL;
	GError *error_local = NULL;

	_main_init();
	enterprises_init();
	supervisor_children_init();
	init_snmp(argv[0]);
	(void) supervisor_rights_init("root", "root", NULL);/* nevermind it fails */

	/* Loads the logging capabilities then the config */
	if (argc < 2) {
		g_printerr("Usage: %s CFGPATH [LOG4CPATH]\n", argv[0]);
		return -1;
	}
	else if (argc == 3) {
		if (log4c_load(argv[2]))
			g_printerr("Could not load the log4crc at [%s] : %s\n",
				argv[2], strerror(errno));
	}

	if (!_cfg_read(argv[1], &error_local)) {
		GSETERROR(&error_local, "Invalid configuration in file [%s]", argv[1]);
		goto label_error;
	}
	if (!_cfg_check(&error_local)) {
		GSETERROR(&error_local, "Invalid configuration for the grid version this progra was compiled for");
		goto label_error;
	}

	if (flag_daemon) {
		close(2);
		daemon(1,0);
		main_write_pid_file();
	}

#ifdef HAVE_NETAPP
	enterprises_register(&enterprise_NETAPP);
#endif

	/* start the filer monitoring */
	si = main_prepare_srvinfo();/* Does not return if it fails (ENOMEM) */
	th = g_thread_create(thread_function_monitor, si, TRUE, &error_local);
	if (!th) {
		GSETERROR(&error_local, "Failed to start the monitoring thread");
		goto label_error;
	}

	/* start the service child and wait for events to happen, or the child to die */
	(void) supervisor_children_start_enabled(NULL, NULL);
	while (flag_continue) {

		(void) supervisor_children_kill_disabled();
		if (!flag_continue)
			break;

		(void) supervisor_children_start_enabled(NULL, NULL);
		if (!flag_continue)
			break;

		alarm(1);
		select(0,NULL,NULL,NULL, NULL);
	}

	rc = 0;

label_error:
	if (error_local) {
		GSETERROR(&error_local, "An error occured");
		ERROR("error : %s", gerror_get_message(error_local));
		g_error_free(error_local);
		error_local = NULL;
	}

	/* wait for the monitoring thread's termination */
	flag_continue = 0;
	if(th)
		(void) g_thread_join(th);
	service_info_down_and_clean(si);

	_main_ignore_signals();
        (void) supervisor_children_stopall(1);
	(void) supervisor_children_catharsis(NULL, NULL);

	supervisor_children_cleanall();
	supervisor_children_fini();

	INFO("Exiting!");
	log4c_fini();
	delete_pid_file();
	if (error_local)
		g_error_free(error_local);
	return rc;
}

