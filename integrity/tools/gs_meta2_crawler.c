#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs_meta2_crawler"
#endif

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>
#include <meta2/remote/meta2_remote.h>
#include <rawx-lib/src/rawx.h>
#include <rules-motor/lib/motor.h>

#include "./lock.h"
#include "./volume_scanner.h"

#define LIMIT_LENGTH_URL 23


#ifndef META2LOCK_ATTRNAME_URL
#define META2LOCK_ATTRNAME_URL "user.meta2_server.address"
#endif

#ifndef META2_ATTRNAME_NAMESPACE
#define META2_ATTRNAME_NAMESPACE "user.meta2_server.namespace"
#endif

#ifndef META2_CRAWLER_XATTRLOCK
#define META2_CRAWLER_XATTRLOCK "user.grid.meta2-crawler.pid"
#endif

int volume_busy = 0;

struct meta2_crawler_stats_s{
	gint    container_total;   
	guint64 container_skipped;
	guint64 container_success; // not used
	guint64 container_failures;// not used
	guint64 container_recently_scanned; // not used
};

static gchar lock_xattr_name[256] = META2_CRAWLER_XATTRLOCK;
static gchar path_root[LIMIT_LENGTH_VOLUMENAME] = "";
static gchar meta2_str_addr[STRLEN_ADDRINFO] = "";

static gchar meta2_url[LIMIT_LENGTH_URL] = "";
static gchar ns_name[LIMIT_LENGTH_NSNAME] = "";

static gboolean flag_loop = FALSE;
static gboolean flag_crawl_content = FALSE;
static gint nbContainerMax = 0;

// motor_env and rules_reload_time_interval declared in motor.h
struct rules_motor_env_s* motor_env = NULL;
gint rules_reload_time_interval = 1L;

// m2v1_list declared in libintegrity
GSList *m2v1_list = NULL;

static time_t interval_sleep = 200L;

static void
sleep_inter_container(void)
{
	usleep(1000L * interval_sleep);
}

static void
main_specific_stop(void)
{
}

static void
main_set_defaults(void){
	bzero(path_root, sizeof(path_root));
	bzero(meta2_str_addr, sizeof(meta2_str_addr));
	bzero(meta2_url, LIMIT_LENGTH_URL);
	bzero(ns_name, LIMIT_LENGTH_NSNAME);
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"RunLoop", OT_BOOL, {.b = &flag_loop},
			"Loop until the FS usage fulfills"},
		{"InterContainerSleepMilli", OT_TIME, {.t=&interval_sleep},
			"Sleep between each container"},
		{"RulesReloadTimeInterval", OT_INT, {.i = &rules_reload_time_interval},
			"Update rules every n seconds"},
		{"CrawlContents", OT_BOOL, {.b = &flag_crawl_content},
			"Also crawl contents in containers"},
		{"nbContainerMax", OT_INT, {.i =  &nbContainerMax},
			"Stop after N containers"},
		{NULL, 0, {.str = NULL}, NULL}
	};

	return options;
}

static const gchar*
main_get_usage(void){
	static gchar xtra_usage[] =
		"\tExpected argument: an absolute path of a valid meta2 directory\n";
	return xtra_usage;
}

static void
main_specific_fini(void){
	if(volume_busy)
		return;
	if(*path_root && *lock_xattr_name) {
		if (volume_lock_get(path_root, lock_xattr_name) == getpid())
			volume_lock_release(path_root, lock_xattr_name);
	}
}

static gboolean
main_save_canonical_directory(const char *dir){
	int i, slash;
	char *path;
	size_t path_len;

	path_len = strlen(dir)+1;
	path = g_alloca(path_len);
	bzero(path, path_len);

	for(i=0,slash=0; *dir; dir++){
		if(*dir != '/'){
			path[i++] = *dir;
			slash = 0;
		}
		else{
			if(!slash)
				path[i++] = *dir;
			slash = 1;
		}
	}

	while(i >= 0 && path[--i] == '/')
		path[i] = '\0';

	if (sizeof(path_root) <= g_strlcpy(path_root, path, sizeof(path_root)-1))
		return FALSE;
	return TRUE;
}

static gboolean
meta2_get_lock_info(const char *vol, gchar *dst_host, gsize dst_host_size, GError **gerr){
	ssize_t size;
	size_t usize;

	if(!vol || !dst_host || !dst_host_size){
		SETERRCODE(gerr, EINVAL, "Invalid parameter");
		return FALSE;
	}

	bzero(dst_host, dst_host_size);
	bzero(ns_name, LIMIT_LENGTH_NSNAME);

	switch(size = getxattr(vol, META2LOCK_ATTRNAME_URL, meta2_url, LIMIT_LENGTH_URL)) {
		case -1:
			if (errno != ENOATTR) {
				SETERRCODE(gerr, errno, "getxattr(%s) : %s", META2LOCK_ATTRNAME_URL, strerror(errno));
				return FALSE;
			}
			break;
		case 0:
			SETERRCODE(gerr, ENOTSUP, "getxattr(%s) : operation not supported", META2LOCK_ATTRNAME_URL);
			return FALSE;
		default:
			usize = size;
			if (usize > dst_host_size) {
				SETERRCODE(gerr, EINVAL, "getxattr(%s) : xattr value too long", META2LOCK_ATTRNAME_URL);
				return FALSE;
			}
			getxattr(vol, META2LOCK_ATTRNAME_URL, dst_host, dst_host_size);
			break;
	}

	GRID_DEBUG("Attr [%s] found with value [%s]", META2LOCK_ATTRNAME_URL, meta2_url);

	switch (size = getxattr(vol, META2_ATTRNAME_NAMESPACE, NULL, 0)) {
		case -1:
			if (errno != ENOATTR) {
				SETERRCODE(gerr, errno, "getxattr(%s) : %s", META2_ATTRNAME_NAMESPACE, strerror(errno));
				return FALSE;
			}
			break;
		case 0:
			SETERRCODE(gerr, ENOTSUP, "getxattr(%s) : operation not supported", META2_ATTRNAME_NAMESPACE);
			return FALSE;
		default:
			usize = size;
			if (usize > LIMIT_LENGTH_NSNAME) {
				SETERRCODE(gerr, EINVAL, "getxattr(%s) : xattr value too long", META2_ATTRNAME_NAMESPACE);
				return FALSE;
			}
			getxattr(vol, META2_ATTRNAME_NAMESPACE, ns_name, LIMIT_LENGTH_NSNAME);
			break;
	}

	GRID_DEBUG("Attr [%s] found with value [%s]", META2_ATTRNAME_NAMESPACE, ns_name);

	errno = 0;
	return TRUE;
}

static gboolean
main_configure(int argc, char **args){
	GError *local_error = NULL;

	if(!argc){
		GRID_ERROR("Missing arguments");
		return FALSE;
	}

	if(!main_save_canonical_directory(args[0])){
		GRID_ERROR("Volume name too long");
		return FALSE;
	}

	if (!meta2_get_lock_info(path_root, meta2_str_addr, sizeof(meta2_str_addr), &local_error)) {
		GRID_ERROR("The direcotry doesn't seem to be a meta2 directory: %s",
			gerror_get_message(local_error));
		g_clear_error(&local_error);
		return FALSE;
	}
	if (!*ns_name || !*meta2_str_addr) {
		GRID_ERROR("The volume doesn't seem to be a META2 volume. Check that attributes [%s] and [%s] are set on volume [%s]", META2_ATTRNAME_NAMESPACE, META2LOCK_ATTRNAME_URL, path_root);
		return FALSE;
	}
	return TRUE;
}


static gboolean
accept_meta2(const gchar *dirname, const gchar *bn, void *data){
	(void) dirname;
	(void) data;

	size_t len;

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
manage_dir_enter(const gchar *path_dir, guint depth, gpointer data){
	(void) depth;
	(void) data;

	GRID_DEBUG("Entering dir [%s]", path_dir);
	return grid_main_is_running() ? SCAN_CONTINUE : SCAN_ABORT;
}

static gboolean
meta2_path_is_valid(const gchar *fullpath){
	size_t len,i;
	const gchar *ptr;

	i = 0;
	len = strlen(fullpath);
	ptr = fullpath + len - 1;

	for(; ptr >= fullpath; ptr--, i++){
		register char c = *ptr;
		if(c == '/')
			break;
		if(!g_ascii_isxdigit(c))
			return FALSE;
	}
	return (i == 64);
}

static enum scanner_traversal_e
manage_meta2(const gchar *container_path, void *data, struct rules_motor_env_s** motor)
{
	struct meta2_crawler_stats_s *stats;
        GError *err = NULL;

	stats = (struct meta2_crawler_stats_s*)data;

	if (!meta2_path_is_valid(container_path)) {
		GRID_DEBUG("Skipping non-container file [%s]", container_path);
		stats->container_skipped++;
		return SCAN_CONTINUE;
	}

	/* Execute action if nb max container wasn't already managed */
	if (nbContainerMax > 0){
		stats->container_total++;
		if (nbContainerMax < stats->container_total) {
			GRID_WARN("stop because %d max container manage !", nbContainerMax);
			return SCAN_STOP_ALL;
		}	
	}

	/* Execute python script over container */
	do {
		struct crawler_meta2_data_pack_s *data_block;
		struct motor_args args;
		data_block = g_malloc0(sizeof(struct crawler_meta2_data_pack_s));
		meta2_crawler_data_block_init(data_block, container_path, meta2_url);
		motor_args_init(&args, (gpointer)data_block, (gint8)META2_TYPE_ID, motor, ns_name);
		pass_to_motor((gpointer)(&args));
		destroy_crawler_meta2_data_block(data_block);
	} while(0);

	/* Start content crawling */
	if (flag_crawl_content) {
		container_id_t container_id;
		addr_info_t meta2_addr;
		gchar *container_id_str = NULL;
		GSList *contents_list = NULL;
		gint meta2_connection_timeout = 500;
		struct content_textinfo_s content_info;

		memset(&meta2_addr, 0x00, sizeof(addr_info_t));
		l4_address_init_with_url(&meta2_addr, meta2_url, &err);
		container_id_str = g_path_get_basename(container_path);
		container_id_hex2bin(container_id_str, strlen(container_id_str), &container_id, &err);

		contents_list = meta2_remote_container_list(&meta2_addr, meta2_connection_timeout, &err, container_id);
		if (err != NULL) {
			GRID_ERROR("Failed to list contents of container [%s] : %s", container_id_str, err->message);
			g_clear_error(&err);
			g_free(container_id_str);
			return SCAN_CONTINUE;
		}

		for (GSList *l = contents_list; l != NULL; l = l->next) {
			path_info_t *info = l->data;
			GRID_DEBUG("Crawling content [%s]", info->path);

			/* Create content_info from path_info */
			bzero(&content_info, sizeof(struct content_textinfo_s));
			content_info.container_id = g_strdup(container_id_str);
			content_info.path = g_strdup(info->path);
			content_info.size = g_strdup_printf("%"G_GINT64_FORMAT, info->size);
			if (info->user_metadata)
				content_info.metadata = g_strndup((gchar*)info->user_metadata->data, info->user_metadata->len);
			if (info->system_metadata)
				content_info.system_metadata = g_strndup((gchar*)info->system_metadata->data, info->system_metadata->len);

			/* Execute python script over content */
			do {
				struct crawler_chunk_data_pack_s *data_block;
				struct motor_args args;
				data_block = g_malloc0(sizeof(struct crawler_chunk_data_pack_s));
				chunk_crawler_data_block_init(data_block, &content_info, NULL, NULL, NULL, NULL);
				motor_args_init(&args, (gpointer)data_block, (gint8)CONTENT_TYPE_ID, motor, ns_name);
				pass_to_motor((gpointer)(&args));
			} while(0);

			/* Free content */
			content_textinfo_free_content(&content_info);
		}

		if (contents_list) {
			g_slist_foreach(contents_list, path_info_gclean, NULL);
			g_slist_free(contents_list);
		}
		g_free(container_id_str);
	}

	stats->container_success++;

	return SCAN_CONTINUE;
}

static enum scanner_traversal_e
manage_meta2_and_sleep(const gchar *container_path, void *data, struct rules_motor_env_s** motor)
{
	enum scanner_traversal_e rc;
	
	if (!grid_main_is_running())
		return SCAN_STOP_ALL;

	rc = manage_meta2(container_path, data, motor);
	sleep_inter_container();
	return rc;
}

static enum scanner_traversal_e
manage_dir_exit(const gchar *path_dir, guint depth, void *data){
	(void) depth;
	(void) data;

	if(!grid_main_is_running()){
		GRID_DEBUG("Exiting dir [%s]", path_dir);
		return SCAN_ABORT;
	}

	sleep_inter_container();
	return SCAN_CONTINUE;
}

static void
main_action(void) {
	struct meta2_crawler_stats_s scan_stats;
	struct volume_scanning_info_s scan_info;

	bzero(&scan_stats, sizeof(scan_stats));
	bzero(&scan_info, sizeof(scan_info));

	scan_info.volume_path = path_root;
	scan_info.file_match = accept_meta2;
	scan_info.file_action = manage_meta2_and_sleep;
	scan_info.dir_enter = manage_dir_enter;
	scan_info.dir_exit = manage_dir_exit;
	scan_info.callback_data = &scan_stats;

	if (*path_root && *lock_xattr_name) {
		if (!volume_lock_set(path_root, lock_xattr_name)) {
			GRID_ERROR("Lock error");
			volume_busy = ~0;
			return;
		}
	}

	motor_env_init();

	do{
		scan_volume(&scan_info, &motor_env);
	}while(flag_loop && grid_main_is_running());


	destroy_motor_env(&motor_env);
	if (*path_root && *lock_xattr_name) {
		if (volume_lock_get(path_root, lock_xattr_name) == getpid())
			volume_lock_release(path_root, lock_xattr_name);
	}
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
	g_setenv("GS_DEBUG_ENABLE", "0", TRUE);
	return grid_main_cli(argc, argv, &cb);
}

