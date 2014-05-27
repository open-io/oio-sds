#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs_chunk_crawler"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <signal.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>
#include <rules-motor/lib/motor.h>

#include "./lock.h"
#include "./volume_scanner.h"
#include "../lib/chunk_db.h"
#include "../lib/chunk_check.h"
#include "../lib/content_check.h"

#ifndef  CHUNK_CRAWLER_XATTRLOCK
# define CHUNK_CRAWLER_XATTRLOCK "user.grid.chunk-crawler.pid"
#endif

#ifndef CHUNK_CRAWLER_XATTR_STAMP
# define CHUNK_CRAWLER_XATTR_STAMP "user.grid.chunk-crawler.last-run"
#endif

int volume_busy = 0;
// motor_env and rules_reload_time_interval declared in motor.h
struct rules_motor_env_s* motor_env = NULL;
gint rules_reload_time_interval = 1L;

// m2v1_list declared in libintegrity
GSList *m2v1_list = NULL;

struct crawler_stats_s {
	gint    chunk_total;
	guint64 chunk_skipped;
	guint64 chunk_success;
	guint64 chunk_failures;
	guint64 chunk_recently_scanned;
};

static GString *lock_xattr_name = NULL;
static GString *stamp_xattr_name = NULL;

static gchar path_root[LIMIT_LENGTH_VOLUMENAME] = "";
static gchar rawx_str_addr[STRLEN_ADDRINFO] = "";
static gchar ns_name[LIMIT_LENGTH_NSNAME] = "";

static time_t interval_sleep = 200L;


static gboolean flag_loop = FALSE;
static gboolean flag_timestamp = FALSE;
static gboolean flag_exit_on_error = FALSE;
static gint  nbChunkMax = 0;

/* ------------------------------------------------------------------------- */


static gboolean
chunk_path_is_valid(const gchar *fullpath)
{
	size_t len, i;
	const gchar *ptr;

	i = 0;
	len = strlen(fullpath);
	ptr = fullpath + len - 1;

	for (; ptr >= fullpath ; ptr--, i++) {
		register gchar c = *ptr;
		if (c == '/')
			break;
		if (!g_ascii_isxdigit(c))
			return FALSE;
	}

	/* too short */
	return (i == 64);
}

static GError *
chunk_check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	GError *err = NULL;
	if (!check_chunk_info(chunk, &err) || !check_content_info(content, &err)) {
		return err;
	}
	return NULL;
}

/* ------------------------------------------------------------------------- */

static void
sleep_inter_chunk(void)
{
	usleep(1000L * interval_sleep);
}

static enum scanner_traversal_e
manage_dir_enter(const gchar *path_dir, guint depth, gpointer data)
{
	if (!grid_main_is_running())
		return SCAN_STOP_ALL;

	(void) depth;
	(void) data;
	GRID_DEBUG("Entering dir [%s]", path_dir);
	return grid_main_is_running() ? SCAN_CONTINUE : SCAN_ABORT;
}

static enum scanner_traversal_e
manage_dir_exit(const gchar *path_dir, guint depth, gpointer data)
{
	if (!grid_main_is_running())
		return SCAN_STOP_ALL;

	(void) depth;
	(void) data;

	if (!grid_main_is_running()) {
		GRID_DEBUG("Exiting dir [%s], no timestamp because of an abort", path_dir);
		return SCAN_ABORT;
	}

	if (flag_timestamp) {
		gchar str_stamp[256];
		GTimeVal gnow;

		g_get_current_time(&gnow);
		g_snprintf(str_stamp, sizeof(str_stamp), "%ld.%06ld", gnow.tv_sec, gnow.tv_usec);
		setxattr(path_dir, stamp_xattr_name->str, str_stamp, strlen(str_stamp), 0);
		GRID_DEBUG("Exiting dir [%s], timestamp(%s) = %d (%s)", path_dir, str_stamp,
			errno, strerror(errno));
	}
	else {
		GRID_DEBUG("Exiting dir [%s]", path_dir);
	}

	sleep_inter_chunk();
	return SCAN_CONTINUE;
}

static gboolean
accept_chunk(const gchar *dirname, const gchar *bn, void *data)
{
	size_t len;

	(void) dirname;
	(void) data;

	if (!bn || !*bn)
		return FALSE;
	if (!grid_main_is_running())
		return FALSE;

	len = strlen(bn);

	if (bn[0]=='.' && (len==1 || (len==2 && bn[1] == '.')))
		return FALSE;

	return metautils_str_ishexa(bn, len);  
}


static enum scanner_traversal_e
manage_chunk(const gchar * chunk_path, void *data, struct rules_motor_env_s** motor)
{
	struct crawler_stats_s *stats;
	GError *local_error = NULL;
	struct content_textinfo_s content_info;
	struct chunk_textinfo_s chunk_info;
	struct chunk_textinfo_extra_s chunk_info_extra;
	struct crawler_chunk_data_pack_s *data_block;
	struct stat chunk_stat;


	data_block = malloc(sizeof(struct crawler_chunk_data_pack_s));	
	bzero(&chunk_info, sizeof(chunk_info));
	bzero(&content_info, sizeof(content_info));
	bzero(&chunk_stat, sizeof(chunk_stat));
	stats = data;

	if (!chunk_path_is_valid(chunk_path)) {
		GRID_DEBUG("Skipping non-chunk file [%s]", chunk_path);
		stats->chunk_skipped ++;
		goto label_exit;
	}

    /* Execute action if nb max container wasn't already managed */
    if (nbChunkMax > 0){
        stats->chunk_total++;
        if (nbChunkMax < stats->chunk_total) {
	        GRID_WARN("stop because %d max container manage !", nbChunkMax);
        	return SCAN_STOP_ALL;
		}
	}



	/* Read content info from chunk attributes */
	if (!get_rawx_info_in_attr(chunk_path, &local_error, &content_info, &chunk_info) ||\
		!get_extra_chunk_info(chunk_path, &local_error, &chunk_info_extra)) {
		GRID_ERROR("Failed to read rawx info from chunk [%s] : %s", chunk_path, local_error->message);
		g_clear_error(&local_error);
		stats->chunk_failures ++;
		goto label_exit;
	}
	

	do {
		GError *err = chunk_check_attributes(&chunk_info, &content_info);
		if (NULL != err) {
			GRID_ERROR("chunk with invalid attributes [%s] : %s", chunk_path, err->message);
			g_clear_error(&err);
			stats->chunk_failures ++;
			goto label_exit;
		}
	} while (0);
	

	/* Save chunk_path in content and container db */
	if (add_chunk_to_db(path_root, chunk_path, content_info.path, content_info.container_id, &local_error)) {
		GRID_DEBUG("Saved chunk in RAWX databases [%s]", chunk_path);
		stats->chunk_success ++;
	}
	else {
		GRID_ERROR("Failed to add chunk in integrity db [%s] : %s", chunk_path, local_error->message);
		g_clear_error(&local_error);
		stats->chunk_failures ++;
	}
	
	/* pass data_block to python */
	struct motor_args args;
	stat(chunk_path, &chunk_stat);
	chunk_crawler_data_block_init(data_block, &content_info, &chunk_info, &chunk_info_extra, &chunk_stat, chunk_path);
	motor_args_init(&args, (gpointer)data_block, (gint8)CHUNK_TYPE_ID, motor, ns_name);
	pass_to_motor((gpointer)(&args));
	/* stamp_a_chunk(chunk_path, ATTR_NAME_CHUNK_LAST_SCANNED_TIME);*/
label_exit:
	chunk_textinfo_free_content(&chunk_info);
	chunk_textinfo_extra_free_content(&chunk_info_extra);
	content_textinfo_free_content(&content_info);
	free(data_block);
	return SCAN_CONTINUE;
}


static enum scanner_traversal_e
manage_chunk_and_sleep(const gchar * chunk_path, void *data, struct rules_motor_env_s** motor)
{
	enum scanner_traversal_e rc;
	
	if (!grid_main_is_running())
		return SCAN_STOP_ALL;

	rc = manage_chunk(chunk_path, data, motor);
	sleep_inter_chunk();
	return rc;
}

static gboolean
main_save_canonical_volume(const char *vol)
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

	if (sizeof(path_root) <= g_strlcpy(path_root, path, sizeof(path_root)-1))
		return FALSE;

	return TRUE;
}


/* ------------------------------------------------------------------------- */

static void
main_set_defaults(void)
{
	bzero(path_root, sizeof(path_root));
	bzero(rawx_str_addr, sizeof(rawx_str_addr));
	bzero(ns_name, sizeof(ns_name));
	lock_xattr_name = g_string_new(CHUNK_CRAWLER_XATTRLOCK);
	stamp_xattr_name = g_string_new(CHUNK_CRAWLER_XATTR_STAMP);
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"RunLoop", OT_BOOL, {.b=&flag_loop},
			"Loop until the FS usage fulfills"},
		{"RunStampDirs", OT_BOOL, {.b=&flag_timestamp},
			"Timestamp each directory after each successful run"},
		{"ExitOnError", OT_BOOL, {.b=&flag_exit_on_error},
			"Stop the execution upon the first error"},
		{"nbChunkMax",  OT_INT, {.i =  &nbChunkMax},
		    "Stop after N chunks"},
		{"InterChunksSleepMilli", OT_TIME, {.t=&interval_sleep},
			"Sleep between each chunk"},
		{"LockXattrName", OT_STRING, {.str=&lock_xattr_name},
			"Xattr name used for locks"},
		{"StampXattrName", OT_STRING, {.str=&stamp_xattr_name},
			"Xattr name used for timestamps"},
		{"RulesReloadTimeInterval", OT_INT, {.i=&rules_reload_time_interval},
			"Update rules every n seconds"},

		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if(volume_busy)
		return;
	if (*path_root && lock_xattr_name->str[0]) {
		if (volume_lock_get(path_root, lock_xattr_name->str) == getpid())
			volume_lock_release(path_root, lock_xattr_name->str);
	}
}

static gboolean
main_configure(int argc, char **args)
{
	GError *local_error = NULL;

	if (!argc) {
		GRID_ERROR("Missing argument");
		return FALSE;
	}

	/* Save the volume's name and introspects the volumes XATTR for
	 * a namespaces name and a RAWX url */
	if (!main_save_canonical_volume(args[0])) {
		GRID_ERROR("Volume name too long");
		return FALSE;
	}

	if (!rawx_get_lock_info(path_root, rawx_str_addr, sizeof(rawx_str_addr), ns_name, sizeof(ns_name), &local_error)) {
		GRID_ERROR("The volume doesn't seem to be a RAWX volume : %s",
			gerror_get_message(local_error));
		g_clear_error(&local_error);
		return FALSE;
	}
	if (!*ns_name || !*rawx_str_addr) {
		GRID_ERROR("The volume doesn't seem to be a RAWX volume. Check that attributes are set on volume [%s]", path_root);
		return FALSE;
	}

	return TRUE;
}

static void
main_action(void)
{
	struct crawler_stats_s scan_stats;
	struct volume_scanning_info_s scan_info;

	bzero(&scan_info, sizeof(scan_info));
	scan_info.volume_path = path_root;
	scan_info.file_match = accept_chunk;
	scan_info.file_action = manage_chunk_and_sleep;
	scan_info.dir_enter = manage_dir_enter;
	scan_info.dir_exit = manage_dir_exit;

	bzero(&scan_stats, sizeof(scan_stats));
	scan_info.callback_data = &scan_stats;

	if (*path_root && lock_xattr_name->str) {
		if (!volume_lock_set(path_root, lock_xattr_name->str)) {
			GRID_ERROR("Lock error");
			volume_busy = ~0;
			return;
		}
	}

	motor_env_init();
	do {
		prepare_chunks_db(path_root);
		scan_volume(&scan_info, &motor_env);
		commit_chunks_db(path_root);
	} while (flag_loop && grid_main_is_running());

	rollback_chunks_db(path_root);
	destroy_motor_env(&motor_env);

	if (*path_root && lock_xattr_name->str) {
		if (volume_lock_get(path_root, lock_xattr_name->str) == getpid())
			volume_lock_release(path_root, lock_xattr_name->str);
	}
}

static const gchar*
main_get_usage(void)
{
	static gchar xtra_usage[] =
		"\tExpected argument: an absolute path a a valid RAWX volume\n"
		;
	return xtra_usage;
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

