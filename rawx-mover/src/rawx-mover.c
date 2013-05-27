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

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef  LOG_DOMAIN
# define LOG_DOMAIN "rawx.mover"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <signal.h>
#include <attr/xattr.h>


#include <math.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <openssl/md5.h>
#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#ifdef HAVE_COMPAT
# include <metautils_compat.h>
#endif
#include <metautils.h>
#include <metacomm.h>
#include <gridcluster.h>
#include <meta2_remote.h>
#include <rawx.h>
#include <grid_client.h>

#ifndef  VOLUME_LOCK_XATTR_NAME
# define VOLUME_LOCK_XATTR_NAME "user.grid.rawx-mover.lock"
#endif

#ifndef  LIMIT_LENGTH_NSNAME
# define LIMIT_LENGTH_NSNAME 32
#endif

#ifdef HAVE_COMPAT
# include <grid_location.h>
# define RAW_CONTENT_GET_CID(R) (R)->cID
#else
# define RAW_CONTENT_GET_CID(R) (R)->container_id
#endif

static gboolean pidfile_written = FALSE;
static gchar pidfile_path[1024] = {0,0,0};
static struct stat pidfile_stat;

static gchar lock_xattr_name[256] = VOLUME_LOCK_XATTR_NAME;
static addr_info_t rawx_addr;
static gchar path_log4c[1024] = "";
static gchar ns_name[LIMIT_LENGTH_NSNAME] = "";
static gchar rawx_str_addr[STRLEN_ADDRINFO] = "";
static gchar rawx_vol[LIMIT_LENGTH_VOLUMENAME] = "";
static gs_grid_storage_t *gs_client = NULL;

static gboolean flag_stop_unless_action = TRUE;
static gboolean flag_check_score = TRUE;
static gboolean flag_check_names = TRUE;
static gboolean flag_sparse = FALSE;
static gboolean flag_unlink = TRUE;
static gboolean flag_dereference = TRUE;
static gboolean flag_loop = FALSE;
static gboolean flag_exit_on_error = FALSE;
static gboolean flag_download = FALSE;
static gboolean flag_fake = FALSE;
static gboolean flag_prune_dirs = FALSE;
static gdouble vol_usage_goal = 0.0;

static time_t interval_update_services = 10L;
static time_t interval_update_statfs = 2L;
static time_t interval_sleep = 200L;
static gint64 max_chunks = 0LLU;

static gboolean flag_running = TRUE;
static gboolean flag_debug = FALSE;
static gboolean flag_quiet = FALSE;
static gboolean flag_daemon = FALSE;

struct upload_info_s {
	int fd;
	struct stat64 fd_stat;
	
	/* destination info */
	struct service_info_s *service;
	gchar dst_path[LIMIT_LENGTH_VOLUMENAME + STRLEN_CHUNKID];
	gchar *dst_host;
	gint dst_port;
	gchar *dst_volume;
	gchar dst_descr[2048]; /* handy namespace url*/

	/* Source info, the rawx info is in static fields*/
	const gchar *src_path;
	gchar *src_basename;
	gchar src_descr[2048];/* handy namespace url */
	
	/* Chunk attributes under several forms */
	struct chunk_textinfo_s chunk;
	struct content_textinfo_s content;
	struct meta2_raw_content_s *raw_new;
	struct meta2_raw_content_s *raw_old;
	struct gs_container_location_s *location;

	/* Compression informations to set in request query part */
	gchar *comp;
	gchar *algo;
	gchar *blocksize;
	
	GByteArray *chunk_buffer;
};

struct mover_stats_s {
	gint64 chunk_success;
	gint64 chunk_skipped;
	gint64 chunk_failure;
	gint64 dirs_run;
	gint64 dirs_pruned;
};

struct str_s {
	gchar *ptr;
	gsize size;
};

struct opt_s {
	char *name;
	enum { OT_BOOL=1, OT_INT, OT_INT64, OT_DOUBLE, OT_TIME, OT_STRING } type;
	void *data;
	char *descr;
};

static struct str_s lock_xattr_name_descr = { lock_xattr_name, sizeof(lock_xattr_name)};

static struct opt_s options[] = {
	{"CheckScore", OT_BOOL, &flag_check_score,
		"Regularily checks the source RAWX service is well zero-scored"},
	{"CheckChunkName", OT_BOOL, &flag_check_names,
		"Only manage chunk files whose name complies [A-Fa-f0-9]{64}"},
	{"ChunkUnlink", OT_BOOL, &flag_unlink,
		"Removes each successfully migrated chunk from the RAWX storage"},
	{"ChunkDereference", OT_BOOL, &flag_dereference,
		"Removes each successfully migrated chunk's reference from the META2. Has no effect unless ChunkUnlink=yes"},
	{"ChunkDownload", OT_BOOL, &flag_download,
		"Download each chunk and check its MD5sum"},
	{"RunSparseChunks", OT_BOOL, &flag_sparse,
		"Perform a sparse file run, one file for each directory"},
	{"RunLoop", OT_BOOL, &flag_loop,
		"Loop until the FS usage fulfills"},
	{"RunMaxChunks", OT_INT64, &max_chunks,
		"Stop the execution after this number of chunks. A negative value means no limit"},
	{"RunPruneDirs", OT_BOOL, &flag_prune_dirs,
		"Prune empty directories along running the volume"},
	{"RunStopUnlessAction", OT_BOOL, &flag_stop_unless_action,
		"Do not use"},
	{"FakeChunkAction", OT_BOOL, &flag_fake,
		"Only loads the chunks, but does nothing on them"},
	{"ExitOnError", OT_BOOL, &flag_exit_on_error,
		"Stop the execution upon the first error"},

	{"UsageGoal", OT_DOUBLE, &vol_usage_goal,
		"Stop the execution when the volume used space falls below this limit"},
	{"InterChunksSleepMilli", OT_TIME, &interval_sleep,
		"Service refresh period"},
	{"IntervalUpdateService", OT_TIME, &interval_update_services,
		"Service refresh period"},
	{"LockXattrName", OT_STRING, &lock_xattr_name_descr,
		"Xattr name used for locks"},
	{"IntervalUpdateFS", OT_TIME, &interval_update_statfs,
		"Do not use"},

	{NULL, 0, NULL, NULL}
};

static void main_usage(const char *prog);
static void main_stop(gboolean l);
static const char* main_set_option(const gchar *str_opt);
static int main_init(int argc, char **args, GError **gerr);
static void main_fini(void);
static void main_write_pid_file(void);
static void main_delete_pid_file(void);
static void main_sighandler_stop(int s);
static void main_sighandler_noop(int s);
static void main_install_sighandlers(void);

/* ------------------------------------------------------------------------- */

static time_t volumes_last_update = 0L;
static GSList *volumes = NULL;
static GSList *volumes_pointer = NULL;

static void
sleep_inter_chunk(void)
{
	struct timeval tv;

	tv.tv_sec = interval_sleep / 1000L;
	tv.tv_usec = interval_sleep % 1000L;
	select(0, NULL, NULL, NULL, &tv);
}

static gboolean 
get_volume_usage(gdouble *result)
{
	static gdouble vol_usage = 1.0;
	static time_t last_update = 0L;

	struct statfs sfs;
	time_t now;
	
	now = time(0);
	if (!last_update || now > (last_update  + interval_update_statfs)) {
		gdouble d_blocks, d_bavail;

		bzero(&sfs, sizeof(sfs));
		if (-1 == statfs(rawx_vol, &sfs)) {
			ERROR_DOMAIN(LOG_DOMAIN".usage", "statfs(%s) = %s", rawx_vol, strerror(errno));
			return FALSE;
		}
	
		d_blocks = sfs.f_blocks;
		d_bavail = sfs.f_bavail;
		vol_usage = 1.0 - (d_bavail / d_blocks);
		last_update = now;
		DEBUG("Volume usage computed : %.3f at time %ld (avail=%ld total=%ld)",
			vol_usage, last_update, sfs.f_bavail, sfs.f_blocks);
	}

	*result = vol_usage;
	return TRUE;
}

static gboolean
may_continue(int depth, struct mover_stats_s *stats)
{
	gdouble vol_usage = 0.0;
	(void) depth;

	if (!flag_running) {
		DEBUG("Explicit stop");
		return FALSE;
	}

	get_volume_usage(&vol_usage);
	if (vol_usage <= vol_usage_goal) {
		INFO("Limit matched : Usage : current(%f) < goal(%f)", vol_usage, vol_usage_goal);
		return 0;
	}
	if (max_chunks > 0LL) {
		gint64 total_chunk = stats->chunk_success + stats->chunk_failure;
		if (total_chunk >= max_chunks) {
			INFO("Limit matched : Chunks : total(%"G_GINT64_FORMAT") >= max(%"G_GINT64_FORMAT")",
				total_chunk, max_chunks);
			return 0;
		}
	}
	return 1;
}

static gboolean
chunk_path_is_valid(const gchar *basename)
{
	guint count = 0;
	const gchar *s;
	register gchar c;

	for (s=basename; (c = *s) ;s++) {
		if ((c < 'a' || c > 'f') && (c < 'A' || c > 'F') && (c < '0' || c > '9'))
			return FALSE;
		if (++count > 64)
			return FALSE;
	}

	return count == 64U;
}

/* ------------------------------------------------------------------------- */

static inline gboolean
rawx_addr_is_source(addr_info_t *ai)
{
	return 0 == memcmp(ai, &rawx_addr, sizeof(addr_info_t));
}

static inline gboolean
rawx_srv_is_source(service_info_t *si)
{
	return rawx_addr_is_source(&(si->addr));
}

static guint
count_valid(GSList *list, guint max)
{
	guint count;
	GSList *l;
	
	for (count=0,l=list; l ;l=l->next) {
		struct service_info_s *si = l->data;
		if (si->score.value == 0)
			return count;
		if (rawx_srv_is_source(si)) /* Skip the source */
			continue;
		if (++count >= max)
			return count;
	}
	return count;
}

static gboolean
rawx_source_is_locked(GSList *list_of_services)
{
	GSList *l;

	for (l=list_of_services; l ;l=l->next) {
		service_info_t *si = l->data;
		if (si->score.value > 0 && rawx_srv_is_source(si))
			return FALSE;
	}

	return TRUE;
}

static gboolean
load_volumes(void)
{
	GError *err = NULL;
	GSList *new_services = NULL;

	DEBUG("Reloading the volumes list");

	new_services = list_namespace_services(ns_name, "rawx", &err);
	if (!new_services && err) {
		if (err) {
			ERROR("reload error : %s", gerror_get_message(err));
			g_error_free(err);
		}
		return FALSE;
	}

	/* Check the source RAWX still has a zeroed score */
	if (flag_check_score && !rawx_source_is_locked(new_services)) {
		INFO("Source RAWX is not locked as expected");
		main_stop(TRUE);
	}

	g_slist_foreach(volumes, service_info_gclean, NULL);
	g_slist_free(volumes);
	volumes_pointer = volumes = g_slist_sort(new_services, service_info_sort_by_score);
	volumes_last_update = time(NULL);
	DEBUG("Received %u volumes", g_slist_length(volumes));
	return TRUE;
}

static service_info_t*
get_available_volume_from_conscience(void)
{
        time_t now;
        service_info_t *result;

        now = time(0);
        if (!volumes || now > (volumes_last_update+interval_update_services))
                (void) load_volumes();

        if (count_valid(volumes, 3) < 1) {
                DEBUG_DOMAIN(LOG_DOMAIN".lb", "count_valid test failed, break without getting available volume from conscience");
                return NULL;
        }

	/* End of list, reset it */
	if (volumes_pointer == NULL)
		volumes_pointer = volumes;

	while ( volumes_pointer != NULL ) {

		result = volumes_pointer->data;
		volumes_pointer = volumes_pointer->next;

                /* Keep the current RAWX if available and different from the source */
                if (!rawx_srv_is_source(result) && result->score.value > 0)
                        return result;

		/* End of available services, reset the list. The test with
		 * cout_valid ensures there is at least one RAWX */
		if (result->score.value <= 0)
			volumes_pointer = volumes;
        }

        return NULL;
}

static service_info_t*
wait_until_volume(void)
{
	service_info_t *result;

	while (!(result = get_available_volume_from_conscience())) {
		INFO("no volume available, sleeping 5s and retry");
		sleep(5);
	}
	
	return result;
}

/* ------------------------------------------------------------------------- */

static gchar*
rawx_get_volume(struct service_info_s *si)
{
	gchar volname[1024];
	struct service_tag_s *tag;

	if (!si->tags)
		return g_strdup("/");

	tag = service_info_get_tag(si->tags, NAME_TAGNAME_RAWX_VOL);
	if (!tag)
		return g_strdup("/");

	if (!service_tag_get_value_string(tag, volname, sizeof(volname), NULL))
		return g_strdup("/");
	
	return g_strdup(volname);
}

static gchar*
rawx_get_host(struct service_info_s *si)
{
	gchar *str, str_addr[STRLEN_ADDRINFO];
	
	if (!si)
		return g_strdup("");

	bzero(str_addr, sizeof(str_addr));
	addr_info_to_string(&(si->addr), str_addr, sizeof(str_addr));
	str = strrchr(str_addr, ':');
	if (str)
		*str = '\0';
	return g_strdup(str_addr);
}

static int
save_canonical_volume(const char *vol)
{
	int i, slash;
	char *path;
	size_t path_len;

	path_len = strlen(vol)+1;
	path = g_alloca(path_len);
	bzero(path, path_len);

	/* skip intermediate sequences of path separators */
	for (i=0,slash=0; *vol ; vol++) {
		if (*vol != '/') {
			path[i++] = *vol;
			slash = 0;
		}
		else {
			if (!slash)
				path[i++] = *vol;
			slash = 1;
		}
	}
	
	/* erase trailing slashes */
	while (i>=0 && path[--i] == '/')
		path[i] = '\0';

	if (sizeof(rawx_vol) <= g_strlcpy(rawx_vol, path, sizeof(rawx_vol)-1))
		return 0;

	return 1;
}

static gchar*
rawx_get_real_volume_name(addr_info_t *addr)
{
	GSList *l;
	for (l=volumes; l ;l=l->next) {
		struct service_info_s *si = l->data;
		if (0 == memcmp(addr, &(si->addr), sizeof(addr_info_t)))
			return rawx_get_volume(si);
	}
	return NULL;
}

/* ------------------------------------------------------------------------- */

static int
run_directory(const gchar *basedir, int depth, struct mover_stats_s *stats)
{
	const gchar *path;
	gchar fullpath[2048];
	size_t fullpath_len;
	GDir *gdir = NULL;
	GError *gerr = NULL;

	if (!may_continue(depth, stats)) {
		DEBUG("Directory : not rescursing in [%s], termination condition met", basedir);
		return 1;
	}
	
	gdir = g_dir_open(basedir, 0, &gerr);
	if (!gdir) {
		WARN("g_dir_open(%s) = %s", basedir, gerror_get_message(gerr));
		if (gerr)
			g_clear_error(&gerr);
		return flag_exit_on_error ? 0 : 1 ;
	}
	
	while (NULL != (path = g_dir_read_name(gdir))) {
		int path_len = strlen(path);
		fullpath_len = g_snprintf(fullpath, sizeof(fullpath), "%s/%.*s", basedir, path_len, path);
		
		if (path[0]=='.' && (path_len==1 || (path_len==2 && path[1]=='.'))) {
			/* Skip too-long paths and dummy ones */
			continue;
		}

		if (fullpath_len >= sizeof(fullpath)) {/* Path too long */
			WARN("path too long for a chunk [%s/%.*s]", basedir, path_len, path);
			if (flag_exit_on_error) {
				stats->chunk_failure ++;
				goto label_error;
			}
			else {
				stats->chunk_skipped ++;
			}
		}
		else if (g_file_test(fullpath, G_FILE_TEST_IS_REGULAR)) {
			/* Possible chunk */
			if (!chunk_path_is_valid(path)) {
				DEBUG("Skipping non-chunk file %s", fullpath);
				stats->chunk_skipped ++;
			}
			else {
				if (move_chunk(fullpath)) {
					stats->chunk_success ++;
					if (flag_sparse) {
						if (may_continue(depth, stats))
							sleep_inter_chunk();
						goto label_exit;
					}
				}
				else {
					stats->chunk_failure ++;
					if (flag_exit_on_error)
						goto label_error;
				}
				if (!may_continue(depth, stats))
					goto label_exit;
				sleep_inter_chunk();
			}
		}
		else if (g_file_test(fullpath, G_FILE_TEST_IS_DIR)) {
			/* Subdir to recurse in */
			if (!run_directory(fullpath, depth + 1, stats) && flag_exit_on_error)
				goto label_error;

			if (!may_continue(depth, stats))
				goto label_exit;

			if (flag_prune_dirs && !flag_fake) {
				GDir *g_subdir = g_dir_open(fullpath, 0, NULL);
				if (g_subdir) {
					if (!g_dir_read_name(g_subdir)) {
						if (0 != g_rmdir(fullpath))
							WARN("Failed to prune dir=[%s] : %s", fullpath, strerror(errno));
						else {
							NOTICE("Pruned dir=[%s]", fullpath);
							stats->dirs_pruned ++;
						}
					}
					g_dir_close(g_subdir);
				}
			}
		}
		else {
			stats->chunk_skipped ++;
			INFO("Path skipped [%.*s] : not a regular file nor a directory", fullpath_len, fullpath);
		}
	}

label_exit:
	g_dir_close(gdir);
	stats->dirs_run ++;
	return 1;

label_error:
	g_dir_close(gdir);
	stats->dirs_run ++;
	return 0;
}

/* ------------------------------------------------------------------------- */

void
main_usage(const char *prog)
{
	struct opt_s *o;

	g_printerr("Usage: %s [OPTIONS...] VOLUME\n", prog);

	g_printerr("\nOPTIONS:\n");
	g_printerr("  -h         help, displays this section\n");
	g_printerr("  -d         daemonizes the process (default FALSE)\n");
	g_printerr("  -q         quiet mode, supress output on stdout stderr \n");
	g_printerr("  -p PATH    pidfile path, no pidfile if unset\n");
	g_printerr("  -n NS      force a namespace to be used. This allows to run through volumes\n"
			   "             without the namespace set in xattr. for the volume carrying this\n"
			   "             attribute, the given namespace must match exactly.\n");
	g_printerr("  -v [PATH]  verbose mode, this activiates log4c traces (default FALSE)\n"
			   "             If a path is used, the target file is loaded as\n"
			   "             a log4crc config file\n");
	g_printerr("  -O XOPT    set extra options.\n");

	g_printerr("\nEXTRA OPTIONS with default value:\n");
	for (o=options; o->name ;o++) {
		gchar name[1024];
		if (o->type == OT_BOOL)
			g_snprintf(name, sizeof(name), "%s=%s", o->name, (*((gboolean*)o->data)?"on":"off"));
		else if (o->type == OT_INT)
			g_snprintf(name, sizeof(name), "%s=%d", o->name, *((gint*)o->data));
		else if (o->type == OT_INT64)
			g_snprintf(name, sizeof(name), "%s=%"G_GINT64_FORMAT, o->name, *((gint64*)o->data));
		else if (o->type == OT_TIME)
			g_snprintf(name, sizeof(name), "%s=%ld", o->name, *((time_t*)o->data));
		else if (o->type == OT_DOUBLE)
			g_snprintf(name, sizeof(name), "%s=%f", o->name, *((gdouble*)o->data));
		else if (o->type == OT_STRING) {
			int i_size = ((struct str_s*)o->data)->size;
			g_snprintf(name, sizeof(name), "%s=%.*s", o->name, i_size, ((struct str_s*)o->data)->ptr);
		}

		g_print("\t%s\n\t\t%s\n", name, o->descr);
	}
}

void
main_stop(gboolean log_allowed)
{
	if (log_allowed)
		NOTICE("Stopping rawx-mover!");
	flag_running = FALSE;
	flag_loop = FALSE;
}

const char*
main_set_option(const gchar *str_opt)
{
	static gchar errbuff[1024];

	gchar **tokens;
	struct opt_s *opt;

	bzero(errbuff, sizeof(errbuff));

	tokens = g_strsplit(str_opt, "=", 2);
	if (!tokens) {
		g_snprintf(errbuff, sizeof(errbuff), "Invalid option format '%s', expected 'Key=Value'", str_opt);
		return errbuff;
	}
	for (opt=options; opt->name ;opt++) {
		if (0 == g_ascii_strcasecmp(opt->name, tokens[0])) {
			if (opt->type == OT_BOOL) {
				if (!metautils_cfg_get_bool(tokens[1], opt->data))
					g_snprintf(errbuff, sizeof(errbuff), "Invalid boolean value for option '%s'", opt->name);
			}
			else if (opt->type == OT_INT) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((int*)opt->data) = i64;
			}
			else if (opt->type == OT_INT64) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((gint64*)opt->data) = i64;
			}
			else if (opt->type == OT_TIME) {
				gint64 i64;
				i64 = g_ascii_strtoll(tokens[1], NULL, 10);
				*((time_t*)opt->data) = i64;
			}
			else if (opt->type == OT_DOUBLE) {
				*((gdouble*)opt->data) = g_ascii_strtod(tokens[1], NULL);
			}
			else if (opt->type == OT_STRING) {
				struct str_s *str_descr = opt->data;
				g_strlcpy(str_descr->ptr, tokens[1], str_descr->size);
			}
			else
				g_snprintf(errbuff, sizeof(errbuff), "Internal error for option '%s'", opt->name);

			goto exit;
		}
	}
	g_snprintf(errbuff, sizeof(errbuff), "Option '%s' not supported", tokens[0]);

exit:
	g_strfreev(tokens);
	return (*errbuff ? errbuff : NULL);
}

int
main_init(int argc, char **args, GError **gerr)
{
	gs_error_t *gserr;
	gchar *str;
	gchar forced_ns_name[sizeof(ns_name)];

	bzero(path_log4c, sizeof(path_log4c));
	bzero(forced_ns_name, sizeof(forced_ns_name));
	bzero(ns_name, sizeof(ns_name));
	bzero(rawx_vol, sizeof(rawx_vol));
	bzero(&rawx_addr, sizeof(rawx_addr));

	for (;;) {
		int c = getopt(argc, args, "O:hdv:qn:p:");
		if (c == -1)
			break;
		switch (c) {
			case 'O':
				if (!optarg) {
					GSETERROR(gerr, "Missing '-O' argument\n");
					main_usage(args[0]);
					return 0;
				}
				else {
					const char *errmsg = main_set_option(optarg);
					if (errmsg) {
						GSETERROR(gerr, "Invalid option : %s\n", errmsg);
						main_usage(args[0]);
						return 0;
					}
				}
				break;
			case 'd':
				flag_daemon = TRUE;
				break;
			case 'h':
				main_usage(args[0]);
				exit(0);
				break;
			case 'n':
				if (!optarg) {
					GSETERROR(gerr, "Missing '-n' argument\n");
					main_usage(args[0]);
					return 0;
				}
				bzero(forced_ns_name, sizeof(forced_ns_name));
				if (sizeof(forced_ns_name) <= g_strlcpy(forced_ns_name, optarg,
						sizeof(forced_ns_name)-1)) {
					GSETERROR(gerr, "Invalid '-n' argument : too long\n");
					main_usage(args[0]);
					return 0;
				}
				NOTICE("Explicitely configured namespace=[%s]", forced_ns_name);
				break;
			case 'p':
				if (!optarg) {
					GSETERROR(gerr, "Missing '-p' argument\n");
					main_usage(args[0]);
					return 0;
				}
				bzero(pidfile_path, sizeof(pidfile_path));
				if (sizeof(pidfile_path) <= g_strlcpy(pidfile_path, optarg, sizeof(pidfile_path)-1)) {
					GSETERROR(gerr, "Invalid '-p' argument : too long\n");
					main_usage(args[0]);
					return 0;
				}
				NOTICE("Explicitely configured pidfile_path=[%s]", pidfile_path);
				break;
			case 'q':
				flag_quiet = TRUE;
				break;
			case 'v':
				bzero(path_log4c, sizeof(path_log4c));
				flag_debug = TRUE;
				if (optarg)
					g_strlcpy(path_log4c, optarg, sizeof(path_log4c)-1);
				break;
			case '?':
				if (optopt == 'v') { /* -v without argument */
					flag_debug = TRUE;
					break;
				}
				else {
					GSETERROR(gerr, "Unexpected option at position %d ('%c')\n", optind, optopt);
					return 0;
				}
			default:
				GSETERROR(gerr, "Unknown option at position %d ('%c')\n", optind, optopt);
				return 0;
		}
	}

	if (optind >= argc) {
		main_usage(args[0]);
		exit(0);
	}
	if (flag_quiet) {
		(void) freopen("/dev/null", "a", stdout);
		(void) freopen("/dev/null", "a", stderr);
	}
	if (flag_debug) {
		log4c_init();
		if (*path_log4c)
			log4c_load(path_log4c);
	}

	/* Save the volume's name and introspects the volumes XATTR for
	 * a namespaces name and a RAWX url */
	if (!save_canonical_volume(args[optind])) {
		GSETERROR(gerr, "Volume name too long");
		return 0;
	}

	if (!rawx_get_lock_info(rawx_vol, rawx_str_addr, sizeof(rawx_str_addr), ns_name, sizeof(ns_name), gerr)) {
		GSETERROR(gerr, "The volume doesn't seem to be a RAWX volume");
		return 0;
	}
	DEBUG("Info got from RAWX xattr : NS=[%s] URL=[%s]", ns_name, rawx_str_addr);

	/* Check the URL */
	if (!*rawx_str_addr) {
		GSETERROR(gerr, "Missing RAWX url in xattr of [%s]", rawx_vol);
		return 0;
	}
	if (!l4_address_init_with_url(&rawx_addr, rawx_str_addr, gerr)) {
		GSETERROR(gerr, "Invalid RAWX url [%s] in xattr of [%s]", rawx_str_addr, rawx_vol);
		return 0;
	}

	/* Check the conscience of the introspected namespace can be found */
	if (!*ns_name && !*forced_ns_name) {
		GSETERROR(gerr, "No namespace found for [%s] (not in xattr, none forced with -n)", rawx_vol);
		return 0;
	}
	if (*forced_ns_name) {
		if (*ns_name && 0 != strcmp(forced_ns_name, ns_name)) {
			GSETERROR(gerr, "The forced namespace [%s] does not match the namespace in xattr [%s]",
					forced_ns_name, ns_name);
			return 0;
		}
		memcpy(ns_name, forced_ns_name, sizeof(ns_name));
	}
	
	/* Now check the namespace is known locally */
	gserr = NULL;
	gs_client = gs_grid_storage_init2(ns_name, 10000, 60000, &gserr);
	if (!gs_client) {
		GSETERROR(gerr, "Invalid RAWX namespace [%s] : %s", ns_name, gs_error_get_message(gserr));
		gs_error_free(gserr);
		return 0;
	}

	addr_info_to_string(&rawx_addr, rawx_str_addr, sizeof(rawx_str_addr));
	DEBUG("Using NS=[%s] RAWX=[%s] VOL=[%s]", ns_name, rawx_str_addr, rawx_vol);
	
	/* Preload the volume list and look for the real volume name */
	if (!load_volumes()) {
		GSETERROR(gerr, "No RAWX available in NS=[%s]", ns_name);
		return 0;
	}

	if (!(str = rawx_get_real_volume_name(&rawx_addr))) {
		WARN("No RAWX service found for url [%s] in namesapce [%s]",
				rawx_str_addr, ns_name);
		if (flag_exit_on_error) {
			GSETERROR(gerr, "No RAWX service found for url [%s] in namesapce [%s]",
					rawx_str_addr, ns_name);
			return 0;
		}
	}
	else {
		if (0 != g_ascii_strcasecmp(str, rawx_vol)) {
			GSETERROR(gerr, "RAWX volume mismatch for url [%s] in namespace [%s] : given(%s) != found(%s)",
					rawx_str_addr, ns_name, rawx_vol, str);
			g_free(str);
			return 0;
		}
		g_free(str);
	}
	
	return 1;
}

void
main_fini(void)
{
	if (gs_client) {
		gs_grid_storage_free(gs_client);
		gs_client = NULL;
	}

	log4c_fini();
}

void
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

void
main_delete_pid_file(void)
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

void
main_sighandler_stop(int s)
{
	main_stop(FALSE);
	signal(s, main_sighandler_stop);
}

void
main_sighandler_noop(int s)
{
	signal(s, main_sighandler_noop);
}

void
main_install_sighandlers(void)
{
	signal(SIGHUP, main_sighandler_stop);
	signal(SIGINT, main_sighandler_stop);
	signal(SIGQUIT, main_sighandler_stop);
	signal(SIGKILL, main_sighandler_stop);
	signal(SIGTERM, main_sighandler_stop);

	signal(SIGPIPE, main_sighandler_noop);
	signal(SIGUSR1, main_sighandler_noop);
	signal(SIGUSR2, main_sighandler_noop);
}

int
main(int argc, char **args)
{
	int rc = 0;
	GError *gerr = NULL;
	struct mover_stats_s stats;

	main_install_sighandlers();
	freopen("/dev/null", "r", stdin);

	if (!g_thread_supported ())
		g_thread_init (NULL);

	if (!main_init(argc, args, &gerr)) {
		if (!flag_quiet)
			g_printerr("Invalid configuration specified :\n\t%s\n", gerror_get_message(gerr));
		if (gerr)
			g_clear_error(&gerr);
		main_fini();
		return 1;
	}

	/* Config abstract */
	if (!flag_quiet) {
		gdouble vol_usage;
		struct opt_s *o;
	
		if (!get_volume_usage(&vol_usage)) {
			main_fini();
			return 1;
		}

		g_print("Running volume [%s] with options:\n", rawx_vol);
		g_print("\t%-32s %s\n", "NS", ns_name);
		g_print("\t%-32s %s\n", "RAWX", rawx_str_addr);
		g_print("\t%-32s %.3f%%\n", "Usage", vol_usage);
		g_print("\t%-32s %s\n", "Debug", flag_debug ? "on" : "off");
		for (o=options; o->name ;o++) {
			if (o->type == OT_BOOL)
				g_print("\t%-32s %s\n", o->name, (*((gboolean*)o->data)?"on":"off"));
			else if (o->type == OT_INT)
				g_print("\t%-32s %d\n", o->name, *((gint*)o->data));
			else if (o->type == OT_INT64)
				g_print("\t%-32s %"G_GINT64_FORMAT"\n", o->name, *((gint64*)o->data));
			else if (o->type == OT_TIME)
				g_print("\t%-32s %ld\n", o->name, *((time_t*)o->data));
			else if (o->type == OT_DOUBLE)
				g_print("\t%-32s %f\n", o->name, *((gdouble*)o->data));
			else if (o->type == OT_STRING) {
				int i_size = ((struct str_s*)o->data)->size;
				g_print("\t%-32s %.*s\n", o->name, i_size, ((struct str_s*)o->data)->ptr);
			}
		}
	}
	
	if (flag_daemon) {
		if (-1 == daemon(1,0)) {
			g_printerr("daemonize error : %s\n", strerror(errno));
			main_fini();
			return 1;
		}
		main_write_pid_file();
		freopen("/dev/null", "w", stdout);
		freopen("/dev/null", "w", stderr);
	}

	/* Main loop */
	flag_running = TRUE;
	bzero(&stats, sizeof(stats));
	for (;;) {
		gint64 nb_chunks_before, nb_chunks_after;

		/* Check the volume lock */
		if (*rawx_vol && *lock_xattr_name) {
			if (!volume_lock_set(rawx_vol, lock_xattr_name)) {
				ERROR("Volume cannot be locked");
				break;
			}
		}

		/* Count the number of chunks currently met */
		nb_chunks_before = stats.chunk_success + stats.chunk_failure;
		rc = run_directory(rawx_vol, 0, &stats);
		nb_chunks_after = stats.chunk_success + stats.chunk_failure;

		if (flag_stop_unless_action && nb_chunks_before == nb_chunks_after) {
			NOTICE("No chunks have been met this turn, we cannot do more.");
			break;
		}

		if (!(rc && flag_loop && may_continue(0, &stats)))
			break;
		sleep(1);
	}

	if (*rawx_vol && *lock_xattr_name) {
		if (volume_lock_get(rawx_vol, lock_xattr_name) == getpid())
			volume_lock_release(rawx_vol, lock_xattr_name);
	}

	/* Run statistics */
	if (!flag_quiet) {
		g_print("Volume run %s\n", rc ? "ok" : "KO");
		g_print("\tchunk.success %"G_GINT64_FORMAT"\n", stats.chunk_success);
		g_print("\tchunk.skipped %"G_GINT64_FORMAT"\n", stats.chunk_skipped);
		g_print("\tchunk.failure %"G_GINT64_FORMAT"\n", stats.chunk_failure);
		g_print("\tdirs.run      %"G_GINT64_FORMAT"\n", stats.dirs_run);
		g_print("\tdirs.pruned   %"G_GINT64_FORMAT"\n", stats.dirs_pruned);
	}

	main_delete_pid_file();
	main_fini();
	return rc ? 0 : 1;
}

