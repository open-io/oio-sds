#ifndef  G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.mover"
#endif
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <attr/xattr.h>

#include <fnmatch.h>
#include <math.h>

// TODO FIXME replce by the GLib equivalent
#include <openssl/md5.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include <client/c/lib/grid_client.h>
#include <client/c/lib/gs_internals.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <resolver/hc_resolver.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>
#include <meta2v2/meta2v2_remote.h>
#include <rawx-lib/src/rawx.h>
#include <integrity/lib/check.h>

#include "lock.h"

#ifndef  VOLUME_LOCK_XATTR_NAME
# define VOLUME_LOCK_XATTR_NAME "user.grid.rawx-mover.lock"
#endif

#ifndef  LIMIT_LENGTH_NSNAME
# define LIMIT_LENGTH_NSNAME 32
#endif

#define RAW_CONTENT_GET_CID(R) (R)->container_id

static GString *lock_xattr_name = NULL;
static GString *forced_namespace = NULL;
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

static GSList *patterns = NULL;

#define MY_TRACE(I,FMT,...)  do { int i = (I).fd_stat.st_ino; (void)i; GRID_TRACE("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_DEBUG(I,FMT,...)  do { int i = (I).fd_stat.st_ino;  GRID_DEBUG("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_INFO(I,FMT,...)   do { int i = (I).fd_stat.st_ino;   GRID_INFO("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_NOTICE(I,FMT,...) do { int i = (I).fd_stat.st_ino; GRID_NOTICE("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_WARN(I,FMT,...)   do { int i = (I).fd_stat.st_ino;   GRID_WARN("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_ERROR(I,FMT,...)  do { int i = (I).fd_stat.st_ino;  GRID_ERROR("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_FATAL(I,FMT,...)  do { int i = (I).fd_stat.st_ino;  FATAL("id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define MY_CRIT(I,FMT,...)   do { int i = (I).fd_stat.st_ino;   CRIT("id=%d "FMT, i, ##__VA_ARGS__); } while (0)

#define FINAL_INFO(I,FMT,...)  do { int i = (I).fd_stat.st_ino; INFO_DOMAIN( G_LOG_DOMAIN".success","id=%d "FMT, i, ##__VA_ARGS__); } while (0)
#define FINAL_ERROR(I,FMT,...) do { int i = (I).fd_stat.st_ino; ERROR_DOMAIN(G_LOG_DOMAIN".error",  "id=%d "FMT, i, ##__VA_ARGS__); } while (0)

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


static struct grid_main_option_s rawx_mover_options[] = {
	{"CheckScore", OT_BOOL, {.b=&flag_check_score},
		"Regularily checks the source RAWX service is well zero-scored"},
	{"CheckChunkName", OT_BOOL, {.b=&flag_check_names},
		"Only manage chunk files whose name complies [A-Fa-f0-9]{64}"},
	{"ChunkUnlink", OT_BOOL, {.b=&flag_unlink},
		"Removes each successfully migrated chunk from the RAWX storage"},
	{"ChunkDereference", OT_BOOL, {.b=&flag_dereference},
		"Removes each successfully migrated chunk's reference from the META2. Has no effect unless ChunkUnlink=yes"},
	{"ChunkDownload", OT_BOOL, {.b=&flag_download},
		"Download each chunk and check its MD5sum"},
	{"RunSparseChunks", OT_BOOL, {.b=&flag_sparse},
		"Perform a sparse file run, one file for each directory"},
	{"RunLoop", OT_BOOL, {.b=&flag_loop},
		"Loop until the FS usage fulfills"},
	{"RunMaxChunks", OT_INT64, {.i64=&max_chunks},
		"Stop the execution after this number of chunks. A negative value means no limit"},
	{"RunPruneDirs", OT_BOOL, {.b=&flag_prune_dirs},
		"Prune empty directories along running the volume"},
	{"RunStopUnlessAction", OT_BOOL, {.b=&flag_stop_unless_action},
		"Do not use"},
	{"FakeChunkAction", OT_BOOL, {.b=&flag_fake},
		"Only loads the chunks, but does nothing on them"},
	{"ExitOnError", OT_BOOL, {.b=&flag_exit_on_error},
		"Stop the execution upon the first error"},

	{"UsageGoal", OT_DOUBLE, {.d=&vol_usage_goal},
		"Stop the execution when the volume used space falls below this limit"},
	{"InterChunksSleepMilli", OT_TIME, {.t=&interval_sleep},
		"Service refresh period"},
	{"IntervalUpdateService", OT_TIME, {.t=&interval_update_services},
		"Service refresh period"},
	{"LockXattrName", OT_STRING, {.str=&lock_xattr_name},
		"Xattr name used for locks"},
	{"IntervalUpdateFS", OT_TIME, {.t=&interval_update_statfs},
		"Do not use"},
	{"ForceNamespace", OT_STRING, {.str=&forced_namespace},
		"Force a namespace to be used. This allows to run through volumes\n"
		"		without the namespace set in xattr. For volumes carrying this\n"
		"		attribute, the given namespace must match exactly."},

	{NULL, 0, {NULL}, NULL}
};

static void rawx_mover_stop(void);
static gboolean rawx_mover_configure(int argc, char **args);
static void rawx_mover_fini(void);
static gchar* rawx_get_volume(struct service_info_s *si);
static void rawx_mover_action(void);

/* ------------------------------------------------------------------------- */

static time_t volumes_last_update = 0L;
/* We need to maintain this list because lbpool
 * doesn't keep zero-scored services */
static GSList *volumes = NULL; // FIXME: make it a GHashTable
static struct grid_lbpool_s *lbpool = NULL;

static void
_free_raw_chunk_content(struct meta2_raw_chunk_s *chunk)
{
	if (!chunk)
		return;
	if (chunk->metadata)
		g_byte_array_free(chunk->metadata, TRUE);
	memset(chunk, 0x00, sizeof(struct meta2_raw_chunk_s));
}

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
			GRID_ERROR("statfs(%s) = %s", rawx_vol, strerror(errno));
			return FALSE;
		}

		d_blocks = sfs.f_blocks;
		d_bavail = sfs.f_bavail;
		vol_usage = 1.0 - (d_bavail / d_blocks);
		last_update = now;
		GRID_DEBUG("Volume usage computed: %.3f at time %ld (avail=%ld total=%ld)",
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
		GRID_DEBUG("Explicit stop");
		return FALSE;
	}

	get_volume_usage(&vol_usage);
	if (vol_usage <= vol_usage_goal) {
		GRID_INFO("Limit matched: Usage: current(%f) < goal(%f)",
				vol_usage, vol_usage_goal);
		return 0;
	}
	if (max_chunks > 0LL) {
		gint64 total_chunk = stats->chunk_success + stats->chunk_failure;
		if (total_chunk >= max_chunks) {
			GRID_INFO("Limit matched: Chunks: total(%"G_GINT64_FORMAT") >= max(%"G_GINT64_FORMAT")",
				total_chunk, max_chunks);
			return 0;
		}
	}
	return 1;
}

static gboolean
chunk_path_is_valid(const gchar *bn)
{
	guint count = 0;
	const gchar *s;
	register gchar c;

	for (s=bn; (c = *s) ;s++) {
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
	return addr_info_equal(ai, &rawx_addr);
}

static inline gboolean
rawx_srv_is_source(service_info_t *si)
{
	return rawx_addr_is_source(&(si->addr));
}

static service_info_t *
get_service_from_url(const gchar *url)
{
	GError *err = NULL;
	addr_info_t addr;
	if (!l4_address_init_with_url(&addr, url, &err)) {
		GRID_WARN("%s", err->message);
		g_clear_error(&err);
		return NULL;
	}
	for (GSList *l = volumes; l; l = l->next) {
		service_info_t *si = l->data;
		if (addr_info_equal(&addr, &(si->addr)))
			return si;
	}
	return NULL;
}

static gboolean
rawx_source_is_locked()
{
	for (GSList *l = volumes; l; l = l->next) {
		service_info_t *si = l->data;
		if (rawx_srv_is_source(si))
			return (si->score.value == 0);
	}
	return TRUE;
}

static gboolean
load_volumes(void)
{
	GError *err = NULL;
	GSList *new_services = NULL;

	GRID_INFO("Reloading the volume list");

	new_services = list_namespace_services2(ns_name, "rawx", &err);
	if (!new_services) {
		GRID_WARN("Failed to reload volume list (not fatal)");
	} else {
		g_slist_free_full(volumes, (GDestroyNotify) service_info_clean);
		volumes = new_services;
	}

	GRID_INFO("Reloading and reconfiguring load-balancer");
	err = gridcluster_reload_lbpool(lbpool);
	if (err != NULL) {
		GRID_ERROR("Failed to reload load-balancer volume list: %s",
				err->message);
		g_clear_error(&err);
		return FALSE;
	}

	err = gridcluster_reconfigure_lbpool(lbpool);
	if (err != NULL) {
		GRID_ERROR("Failed to reconfigure load-balancer: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	/* Check the source RAWX still has a zeroed score */
	if (flag_check_score && !rawx_source_is_locked()) {
		GRID_ERROR("Source RAWX is not locked as expected");
		return FALSE;
	}

	volumes_last_update = time(NULL);
	return TRUE;
}

/**
 * Find a suitable rawx volume for storage of a chunk.
 *
 * @param url_str
 * @param chunk_info
 * @param meta2
 * @return The service_info_t* description of a rawx server,
 *   or NULL if none found
 */
static service_info_t*
find_volume(struct hc_url_s *url, check_info_t *check_info,
			const gchar *meta2)
{
	GError *err = NULL;
	service_info_t *result = NULL;
	struct storage_policy_s *policy = NULL;
	const struct storage_class_s *stgclass = NULL;
	const struct data_security_s *datasec = NULL;
	namespace_info_t *nsinfo = NULL;
	// chunks sharing same position in same content (aka duplicates)
	GSList *friend_chunk_ids = NULL;
	GSList *friend_chunk_srvinfo = NULL;

	GRID_TRACE("Looking for matching aliases in container [%s]",
			hc_url_get(url, HCURL_WHOLE));

	err = find_storage_policy_and_friend_chunks(meta2, url, check_info, &friend_chunk_ids);
	if (err) {
		GRID_ERROR("Failed to find storage policy and/or friend chunks: %s",
				err->message);
		g_clear_error(&err);
		return NULL;
	}

	nsinfo = get_namespace_info(check_info->ns_name, &err);
	if (err != NULL) {
		GRID_ERROR("Could not get namespace info: %s", err->message);
		g_clear_error(&err);
		return NULL;
	}
	if (!check_info->ct_info->storage_policy) {
		check_info->ct_info->storage_policy = namespace_storage_policy(
				nsinfo, check_info->ns_name);
		GRID_INFO("No storage policy defined for content, will use default from namespace: %s",
				check_info->ct_info->storage_policy);
	}
	GRID_TRACE("Will use storage policy [%s]", check_info->ct_info->storage_policy);
	policy = storage_policy_init(nsinfo, check_info->ct_info->storage_policy);

	if (policy == NULL) {
		GRID_ERROR("Unknown storage policy '%s'",
				check_info->ct_info->storage_policy);
		goto end_label;
	}

	for (GSList *cursor = friend_chunk_ids; cursor; cursor = cursor->next) {
		gchar **tokens = NULL;
		service_info_t *srvinfo = NULL;
		tokens = g_regex_split_simple(
				"(([[:digit:]]{1,3}\\.){3}[[:digit:]]{1,3}:[[:digit:]]{1,5})",
				cursor->data, 0, 0);
		if (tokens == NULL || tokens[1] == NULL) {
			GRID_WARN("Failed to extract rawx address from '%s'"
					" (bad regex?)", (gchar*)cursor->data);
			g_strfreev(tokens);
			tokens = NULL;
			continue;
		}
		srvinfo = get_service_from_url(tokens[1]);
		if (srvinfo == NULL) {
			GRID_WARN("Did not find rawx matching address %s",
					(gchar*)cursor->data);
			g_strfreev(tokens);
			tokens = NULL;
			continue;
		}
		friend_chunk_srvinfo = g_slist_prepend(friend_chunk_srvinfo,
				srvinfo);

		g_strfreev(tokens);
		tokens = NULL;
	}

	stgclass = storage_policy_get_storage_class(policy);
	datasec = storage_policy_get_data_security(policy);

	// TODO: extract and use _policy_parameter() from meta2v2/meta2_utils.c
	const gchar *reqdist_str = data_security_get_param(datasec, DS_KEY_DISTANCE);

	struct lb_next_opt_ext_s opt_ext;
	memset(&opt_ext, 0, sizeof(opt_ext));
	opt_ext.req.duplicates = FALSE;
	opt_ext.req.max = 1; // we want just one to replace current chunk
	opt_ext.req.distance = reqdist_str? atoi(reqdist_str): 0;
	opt_ext.req.stgclass = stgclass;
	opt_ext.req.strict_stgclass = FALSE; // Accept ersatzes
	opt_ext.srv_inplace = friend_chunk_srvinfo;

	service_info_t **new_rawx = NULL;
	if (!grid_lb_iterator_next_set2(grid_lbpool_get_iterator(lbpool, "rawx"),
				&new_rawx, &opt_ext)) {
		GRID_ERROR("Failed to find a replacement rawx:(");
	} else {
		result = service_info_dup(new_rawx[0]);
		gchar *vol = rawx_get_volume(result);
		GRID_DEBUG("Found replacement rawx %s", vol);
		g_free(vol);
	}

end_label:
	service_info_cleanv(new_rawx, FALSE);
	namespace_info_free(nsinfo);
	nsinfo = NULL;

	g_slist_free(friend_chunk_srvinfo);
	g_slist_free_full(friend_chunk_ids, g_free);
	storage_policy_clean(policy);
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
rawx_get_real_volume_name()
{
	service_info_t *si = NULL;

	/* Search in this volume list because lbpool
	 * does not contain zero-scored services */
	for (GSList *l = volumes; l; l = l->next) {
		service_info_t *si2 = l->data;
		if (rawx_srv_is_source(si2)) {
			si = si2;
		}
	}

	if (!si)
		return NULL;
	return rawx_get_volume(si);
}

/* ------------------------------------------------------------------------- */

static void
populate_request_headers(ne_request *request, struct chunk_textinfo_s *chunk,
	struct content_textinfo_s *content)
{
	inline void set_header(const char *n, const char *v) {
		if (v)
			ne_add_request_header(request, n, v);
	}

	/* add v1.1 headers */
	set_header("chunkid",     chunk->id);
	set_header("chunkhash",   chunk->hash);
	set_header("containerid", content->container_id);
	set_header("contentpath", content->path);
	set_header("contentmetadata",     content->metadata);
	set_header("contentmetadata-sys", content->system_metadata);
	set_header("chunkpos",    chunk->position);
	set_header("chunknb",     content->chunk_nb);
	set_header("chunksize",   chunk->size);
	set_header("contentsize", content->size);

	/* overwrite with v1.4 rawx headers */
	set_header("content_path",         content->path);
	set_header("content_size",         content->size);
	set_header("content_chunksnb",     content->chunk_nb);
	set_header("content_metadata",     content->metadata);
	set_header("content_metadata-sys", content->system_metadata);
	set_header("content_containerid",  content->container_id);

	set_header("chunk_id",          chunk->id);
	set_header("chunk_path",        chunk->path);
	set_header("chunk_size",        chunk->size);
	set_header("chunk_hash",        chunk->hash);
	set_header("chunk_position",    chunk->position);
	set_header("chunk_metadata",    chunk->metadata);
	set_header("chunk_containerid", chunk->container_id);

	set_header("namespace",         ns_name);
}

static gchar *
build_request_uri(struct upload_info_s *info)
{
	return g_strdup_printf("%s?comp=%s&algo=%s&bs=%s", info->dst_path,
			info->comp, info->algo, info->blocksize);
}

static const char *
check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	if (!chunk->path)
		return "Missing mandatory content path";

	if (!chunk->id)
		return "Missing mandatory chunk ID";

	if (!chunk->size)
		return "Missing mandatory chunk size";

	if (!chunk->hash)
		return "Missing mandatory chunk hash";

	if (!chunk->position)
		return "Missing mandatory chunk position";

	if (!content->path)
		return "Missing mandatory content path";

	if (!content->size)
		return "Missing mandatory content size";

	if (!content->chunk_nb)
		return "Missing mandatory chunk number";

	if (!content->container_id)
		return "Missing mandatory container identifier";

	return NULL;
}

static GError *
validate_chunk_in_one_meta2(struct upload_info_s *info, const char *str_addr,
	struct meta2_raw_content_s *raw_old, struct meta2_raw_content_s *raw_new)
{
	gboolean m2_rc=FALSE;
	GError *gerr = NULL;
	struct metacnx_ctx_s ctx;
	gchar m2_descr[2048];
	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, ns_name);
	hc_url_set(url, HCURL_HEXID, info->content.container_id);
	hc_url_set(url, HCURL_PATH, info->content.path);

	bzero(m2_descr, sizeof(m2_descr));
	g_snprintf(m2_descr, sizeof(m2_descr), "%s|meta2|%s|%s",
			ns_name, str_addr, info->content.container_id);
	//		ns_name, str_addr, info->location->container_name);

	MY_DEBUG(*info, "About to validate the reference in meta2 at [%s]", m2_descr);

	// Call only if asked to dereference old chunk, and meta2v2
	if (flag_dereference && !is_m2v1(str_addr)) {
		chunk_hash_t bin_hash;
		gchar tmp[STRLEN_ADDRINFO];
		gchar *new_url, *old_url;

		// Create beans necessary for the m2v2 request
		struct bean_CHUNKS_s *new = _bean_create(&descr_struct_CHUNKS);
		struct bean_CHUNKS_s *old = _bean_create(&descr_struct_CHUNKS);

		g_snprintf(tmp, STRLEN_ADDRINFO, "%s:%d", info->dst_host, info->dst_port);
		new_url = assemble_chunk_id(tmp, info->dst_volume, info->chunk.id);
		// FIXME: binary hash is probably somewhere already
		hex2bin(info->chunk.hash, bin_hash, sizeof(chunk_hash_t), NULL);
		CHUNKS_set2_id(new, new_url);
		CHUNKS_set2_hash(new, bin_hash, sizeof(chunk_hash_t));
		CHUNKS_set_size(new, g_ascii_strtoll(info->chunk.size, NULL, 10));
		// FIXME: set ctime?

		old_url = assemble_chunk_id(rawx_str_addr, rawx_vol, info->chunk.id);
		CHUNKS_set2_id(old, old_url); // This is the only required field

		GRID_DEBUG("Call meta2 %s for substitution of %s by %s",
				str_addr, old_url, new_url);
		gerr = m2v2_remote_execute_SUBST_CHUNKS_single(str_addr, NULL, url,
				new, old, FALSE);
		if (gerr) {
			m2_rc = FALSE;
			// Host is meta2v1 but we didn't know
			if (gerr->code == CODE_NOT_FOUND) {
				add_to_m2v1_list(str_addr);
				g_clear_error(&gerr);
			}
		} else {
			m2_rc = TRUE;
		}
		g_free(new_url);
		g_free(old_url);
	}

	// If meta2v1 or dereference disabled
	if (!gerr && !m2_rc) {
		metacnx_clear(&ctx);
		if (!metacnx_init_with_url(&ctx, str_addr, &gerr)) {
			MY_WARN(*info, "invalid meta2 location [%s]: %s",
					m2_descr, gerror_get_message(gerr));
			goto label_cleanup;
		}
		ctx.timeout.cnx = 30000;
		ctx.timeout.req = 60000;

		GRID_DEBUG("New chunk container version: %ld", raw_new->version);

		// FIXME: with m2v2, use m2v2_remote_execute_SUBST_CHUNKS_single()
		/* Insert the new chunk */
		m2_rc = meta2raw_remote_update_chunks(&ctx, &gerr, raw_new, TRUE, NULL);
		if (!m2_rc) {
			MY_ERROR(*info, "Chunk reference insertion failed in [%s]: %s",
					m2_descr, gerror_get_message(gerr));
			goto label_cleanup;
		}

		if (flag_unlink && flag_dereference) {
			/* Delete the old chunk */
			m2_rc = meta2raw_remote_delete_chunks(&ctx, &gerr, raw_old);
			if (!m2_rc) {
				MY_ERROR(*info, "Chunk reference removal failed in [%s]: %s",
						m2_descr, gerror_get_message(gerr));
				goto label_cleanup;
			}
		}

		MY_INFO(*info, "Reference updated in [%s] src[%s] dst[%s]",
				m2_descr, info->src_descr, info->dst_descr);
		m2_rc = TRUE;
	}

label_cleanup:
	metacnx_close(&ctx);
	return gerr;
}

static struct meta2_raw_content_s*
load_raw_chunk(const char *what, struct upload_info_s *info,
		check_info_t *check_info, addr_info_t *addr, const gchar *vol)
{
	GError *gerr = NULL;
	struct meta2_raw_chunk_s raw_chunk;
	struct meta2_raw_content_s *raw_content;

	(void) what;
	raw_content = g_malloc0(sizeof(*raw_content));
	bzero(&raw_chunk, sizeof(raw_chunk));

	if (!convert_content_text_to_raw(check_info->ct_info, raw_content, &gerr)) {
		MY_ERROR(*info, "Invalid content fields: %s", gerror_get_message(gerr));
		g_error_free(gerr);
		goto label_error;
	}
	if (gerr)
		g_clear_error(&gerr);

	if (NULL != (gerr = generate_raw_chunk(check_info, &raw_chunk))) {
		MY_ERROR(*info, "Invalid chunk fields: %s", gerror_get_message(gerr));
		g_error_free(gerr);
		goto label_error;
	}
	if (gerr)
		g_clear_error(&gerr);

	g_strlcpy(raw_chunk.id.vol, vol, sizeof(raw_chunk.id.vol)-1);
	memcpy(&(raw_chunk.id.addr), addr, sizeof(addr_info_t));

	/* COPY the chunk then destroy the original */
	meta2_maintenance_add_chunk(raw_content, &raw_chunk);
	_free_raw_chunk_content(&raw_chunk);

	if (GRID_TRACE_ENABLED()) {
		gchar str[2048];
		struct meta2_raw_chunk_s *rc = raw_content->raw_chunks->data;
		chunk_id_to_string(&(rc->id), str, sizeof(str));
		MY_TRACE(*info, "%s CHUNK [%.*s]", what, (int)sizeof(str), str);
	}

	return raw_content;

label_error:
	_free_raw_chunk_content(&raw_chunk);
	meta2_maintenance_destroy_content(raw_content);
	return NULL;
}

static GError *
validate_chunk_in_all_meta2(struct upload_info_s *info)
{
	gchar **url;
	GError *err = NULL;

	/* Update the reference and clean the old directly in the META2 */
	for (url=info->location->m2_url; url && *url ;url++) {
		GError *err2 = validate_chunk_in_one_meta2(info, *url,
				info->raw_old, info->raw_new);
		if (err2 != NULL) {
			MY_WARN(*info, "M2V2 error [%s] : (%d) %s",
					*url, err2->code, err2->message);
			if (err == NULL)
				g_propagate_error(&err, err2);
			else
				g_clear_error(&err2);
		}
	}

	return err;
}

static int
ne_reader__md5_computer(void *userdata, const char *buf, size_t len)
{
	if (buf && len)
		MD5_Update((MD5_CTX*)userdata, buf, len);
	return 0;
}

static int
download_and_check_chunk(struct upload_info_s *info)
{
	int rc = 0;
	MD5_CTX md5_ctx;
	ne_session *session;
	ne_request *request;

	MY_DEBUG(*info, "Downloading dst[%s]", info->dst_descr);

	session = ne_session_create("http", info->dst_host, info->dst_port);
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "GET", info->dst_path);
	populate_request_headers(request, &(info->chunk), &(info->content));
	ne_add_response_body_reader(request, ne_accept_2xx,
			ne_reader__md5_computer, &md5_ctx);

	MD5_Init(&md5_ctx);
	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2) {
				MY_INFO(*info, "Download done, checking MD5 sum...");
				rc = ~0;
				break;
			}
			MY_WARN(*info, "Server error: %s", ne_get_error(session));
			break;
		case NE_AUTH:
			MY_WARN(*info, "Unexpected authentication: %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			MY_WARN(*info, "Connection/Read timeout: %s", ne_get_error(session));
			break;
		case NE_ERROR:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		default:
			MY_WARN(*info, "Unexpected error: %s", ne_get_error(session));
			break;
	}

	if (rc) {
		guint8 md5_hash[16];
		gchar md5_hash_str[33];
		bzero(md5_hash, sizeof(md5_hash));
		bzero(md5_hash_str, sizeof(md5_hash_str));
		MD5_Final(md5_hash, &md5_ctx);
		buffer2str(md5_hash, sizeof(md5_hash), md5_hash_str, sizeof(md5_hash_str));
		if (0 != g_ascii_strcasecmp(md5_hash_str, info->chunk.hash)) {
			FINAL_ERROR(*info, "MD5SUM mismatch (%s/%s) src[%s] dst[%s]",
				info->chunk.hash, md5_hash_str, info->src_descr, info->dst_descr);
			rc = 0;
		}
		else
			MY_DEBUG(*info, "MD5SUM match after upload then download");
	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static int
delete_uploaded_chunk(struct upload_info_s *info)
{
	int rc = 0;
	ne_session *session;
	ne_request *request;

	(void) info;

	MY_DEBUG(*info, "Deleting %s from [%s:%d]", info->dst_path,
			info->dst_host, info->dst_port);

	session = ne_session_create("http", info->dst_host, info->dst_port);
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "DELETE", info->dst_path);
	ne_set_request_body_fd(request, info->fd, 0, info->fd_stat.st_size);

	populate_request_headers(request, &(info->chunk), &(info->content));

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2) {
				MY_INFO(*info, "Deleted %s", info->dst_descr);
				rc = ~0;
				break;
			}
			MY_WARN(*info, "Server error: %s", ne_get_error(session));
			break;
		case NE_AUTH:
			MY_WARN(*info, "Unexpected authentication: %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			MY_WARN(*info, "Connection/Read timeout: %s", ne_get_error(session));
			break;
		case NE_ERROR:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		default:
			MY_WARN(*info, "Unexpected error: %s", ne_get_error(session));
			break;

	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static int
upload_chunk(struct upload_info_s *info)
{
	int rc = 0;
	ne_session *session;
	ne_request *request;

	MY_DEBUG(*info, "Uploading to [%s:%d]", info->dst_host, info->dst_port);

	session = ne_session_create("http", info->dst_host, info->dst_port);
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);


	if(info->comp && 0 == g_ascii_strcasecmp("true", info->comp)){
		gchar *uri = NULL;
		uri = build_request_uri(info);
		request = ne_request_create(session, "PUT", uri);
		if(uri)
			g_free(uri);
	} else
		request = ne_request_create(session, "PUT", info->dst_path);

	gsize bufsize = 0;
	bufsize = info->chunk_buffer->len;
	ne_set_request_body_buffer(request, ((char *)info->chunk_buffer->data), bufsize);

	populate_request_headers(request, &(info->chunk), &(info->content));

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2) {
				MY_INFO(*info, "Upload done!");
				rc = ~0;
				break;
			}
			MY_WARN(*info, "Server error: %s", ne_get_error(session));
			break;
		case NE_AUTH:
			MY_WARN(*info, "Unexpected authentication: %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			MY_WARN(*info, "Connection/Read timeout: %s", ne_get_error(session));
			break;
		case NE_ERROR:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		default:
			MY_WARN(*info, "Unexpected error: %s", ne_get_error(session));
			break;

	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static int
ne_reader__chunk_computer(void *userdata, const char *buf, size_t len)
{
	if (buf && len)
		g_byte_array_append((GByteArray*)userdata, (guint8*)buf, len);
	return 0;
}

static int
download_old_chunk(const gchar *path, struct upload_info_s *info)
{
	int rc = 0;
	ne_session *session;
	ne_request *request;
	MY_DEBUG(*info, "Downloading src compressed chunk [%s]", path);

	gchar *str, str_addr[STRLEN_ADDRINFO];
	guint16 src_port;

	bzero(str_addr, sizeof(str_addr));
	addr_info_to_string(&rawx_addr, str_addr, sizeof(str_addr));
	str = strrchr(str_addr, ':');
	if (str)
		*str = '\0';

	src_port = ntohs(rawx_addr.port);

	session = ne_session_create("http", str_addr, src_port);
	ne_set_connect_timeout(session, 60);
	ne_set_read_timeout(session, 60);

	request = ne_request_create(session, "GET", path);
	populate_request_headers(request, &(info->chunk), &(info->content));
	ne_add_response_body_reader(request, ne_accept_2xx,
			ne_reader__chunk_computer, info->chunk_buffer);

	switch (ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass == 2) {
				MY_INFO(*info, "Download done");
				rc = ~0;
				break;
			}
			MY_WARN(*info, "Server error: %s", ne_get_error(session));
			break;
		case NE_AUTH:
			MY_WARN(*info, "Unexpected authentication: %s", ne_get_error(session));
			break;
		case NE_CONNECT:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		case NE_TIMEOUT:
			MY_WARN(*info, "Connection/Read timeout: %s", ne_get_error(session));
			break;
		case NE_ERROR:
			MY_WARN(*info, "Connection error: %s", ne_get_error(session));
			break;
		default:
			MY_WARN(*info, "Unexpected error: %s", ne_get_error(session));
			break;
	}

	ne_request_destroy(request);
	ne_session_destroy(session);
	return rc;
}

static int
load_chunk(const gchar *path, struct upload_info_s *info)
{
	GError *err;
	gs_error_t *gserr;
	int rc = 1;
	char *full_nsname = NULL;

	memset(info, 0, sizeof(*info));
	info->fd = -1;

	info->chunk_buffer = g_byte_array_new();
	info->src_path = path;
	info->src_basename = g_path_get_basename(path);
	g_snprintf(info->src_descr, sizeof(info->src_descr), "%s|rawx|%s|%s",
		ns_name, rawx_str_addr, info->src_path);

	/* Ensure the file can be opened */
	info->fd = open(path, O_LARGEFILE|O_RDONLY);
	if (info->fd < 0) {
		FINAL_ERROR(*info, "open/read error (%d %s) on src[%s]",
			errno, strerror(errno), info->src_descr);
		return 0;
	}
	fstat64(info->fd, &(info->fd_stat));

	MY_INFO(*info, "Migration started src[%s]", info->src_descr);

	/* Now load the chunk's attributes */
	err = NULL;
	if (!get_rawx_info_in_attr(path, &err, &(info->content), &(info->chunk))) {
		FINAL_ERROR(*info, "attributes error (%s) src[%s] dst[%s]",
			gerror_get_message(err), info->src_descr, info->dst_descr);
		g_clear_error(&err);
		rc = 0;
		goto end_label;
	}
	else {
		const char *str_err;
		if (NULL != (str_err = check_attributes(&(info->chunk),
						&(info->content)))) {
			FINAL_ERROR(*info, "attributes conversion error (%s)"
					" src[%s] dst[%s]",
					str_err, info->src_descr, info->dst_descr);
			rc = 0;
			goto end_label;
		}
	}
	gserr = NULL;
	info->location = gs_locate_container_by_hexid_v2(gs_client,
			info->content.container_id, &full_nsname, &gserr);
	if (!info->location || !info->location->m2_url
			|| !info->location->m2_url[0]) {
		FINAL_ERROR(*info, "container not found [%s/%s] (%s) src[%s] dst[%s]",
			ns_name, info->content.container_id, gs_error_get_message(gserr),
			info->src_descr, info->dst_descr);
		gs_error_free(gserr);
		rc = 0;
		goto end_label;
	}

	if (!full_nsname)
		full_nsname = g_strdup(ns_name);

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, full_nsname);
	hc_url_set(url, HCURL_HEXID, info->content.container_id);

	check_info_t check_info;
	memset(&check_info, 0, sizeof(check_info));
	check_info.ck_info = &(info->chunk);
	check_info.ct_info = &(info->content);
	g_strlcpy(check_info.ns_name, full_nsname, sizeof(check_info.ns_name));
	g_strlcpy(check_info.rawx_str_addr, rawx_str_addr, sizeof(check_info.rawx_str_addr));
	g_strlcpy(check_info.rawx_vol, rawx_vol, sizeof(check_info.rawx_vol));
	g_strlcpy(check_info.source_path, path, sizeof(check_info.source_path));

	/* Get a service from the conscience, mandatory for the next steps */
	info->service = find_volume(url, &check_info, info->location->m2_url[0]);

	hc_url_clean(url);

	if (!info->service) {
		FINAL_ERROR(*info, "no target volume src[%s]", info->src_path);
		rc = 0;
		goto end_label;
	}

	info->dst_volume = rawx_get_volume(info->service);
	info->dst_host = rawx_get_host(info->service);
	info->dst_port = ntohs(info->service->addr.port);

	g_snprintf(info->dst_path, sizeof(info->dst_path), "%s/%s",
			info->dst_volume, info->src_basename);

	g_snprintf(info->dst_descr, sizeof(info->dst_descr), "%s|%s|%s:%d|%s",
			info->service->ns_name, info->service->type,
			info->dst_host, info->dst_port, info->dst_path);

	MY_DEBUG(*info, "RAWX polled: dst[%s]", info->dst_descr);



	/* Compression purpose */
	info->comp = g_strdup("false");
	info->algo = g_strdup("none");
	info->blocksize = g_strdup("65536");

	do {
		GHashTable *compress_opt = NULL;

		compress_opt = g_hash_table_new_full(g_str_hash, g_str_equal,
				g_free, g_free);

#ifdef HAVE_COMPRESSION
		if (!get_compression_info_in_attr(path, &err, &compress_opt)) {
			if (err) {
				GRID_WARN("Failed to load the compression information for [%s]: %s",
					path, err->message);
				g_clear_error(&err);
			}
		}
		else {
			gchar *tmp;

			tmp = g_hash_table_lookup(compress_opt, NS_COMPRESSION_OPTION);
			if (tmp && g_ascii_strcasecmp(tmp, NS_COMPRESSION_ON) == 0) {

				g_free(info->comp);
				info->comp = g_strdup("true");

				tmp = g_hash_table_lookup(compress_opt, NS_COMPRESS_ALGO_OPTION);
				if(tmp) {
					g_free(info->algo);
					info->algo = g_strdup(tmp);
				}

				tmp = g_hash_table_lookup(compress_opt, NS_COMPRESS_BLOCKSIZE_OPTION);
				if(tmp) {
					g_free(info->blocksize);
					info->blocksize = g_strdup(tmp);
				}
			}
		}
#endif

		g_hash_table_destroy(compress_opt);
	} while (0);

	if(download_old_chunk(path, info) == 0){
		FINAL_ERROR(*info, "Failed to download old chunk [%s]",
				path);
		rc = 0;
		goto end_label;
	}

	/* for further META2 request, we will need the raw_content forms of the
	 * source and destination chunk */
	info->raw_old = load_raw_chunk("OLD", info, &check_info, &rawx_addr, rawx_vol);
	info->raw_new = load_raw_chunk("NEW", info, &check_info, &(info->service->addr),
			info->dst_volume);
	if (!info->raw_old || !info->raw_new) {
		FINAL_ERROR(*info, "invalid attributes src[%s] dst[%s]",
				info->src_descr, info->dst_descr);
		rc = 0;
		goto end_label;
	}

	/* Check the sizes match between the local chunks stats and its attributes */
	do {
		gint64 chunk_size = -1;
#ifdef HAVE_COMPRESSION
		if(0 == g_ascii_strcasecmp(info->comp, "false")) {
#endif
			chunk_size = ((struct meta2_raw_chunk_s*)info->raw_new->raw_chunks->data)->size;
			if (info->fd_stat.st_size != chunk_size) {
				FINAL_ERROR(*info, "Local/Meta2 sizes mismatch"
						" (local=%"G_GINT64_FORMAT" xattr=%"G_GINT64_FORMAT") src[%s] dst[%s]",
						info->fd_stat.st_size, chunk_size, info->src_descr, info->dst_descr);
				printf("Local/Meta2 sizes mismatch => compressed -_-\n");
				rc = 0;
				goto end_label;
			}
#ifdef HAVE_COMPRESSION
		}
		else {
			guint32 size32 = info->fd_stat.st_size;
			guint32 attr_size = 0;
			if(!get_chunk_compressed_size_in_attr(path ,&err, &attr_size) || (size32 != attr_size)) {
				FINAL_ERROR(*info, "Local/Meta2 sizes mismatch"
						" (local=%"G_GINT64_FORMAT" xattr=%"G_GINT64_FORMAT") src[%s] dst[%s]",
						info->fd_stat.st_size, chunk_size, info->src_descr, info->dst_descr);
				printf("Local/Meta2 sizes mismatch => compressed -_-\n");
				rc = 0;
				goto end_label;
			}
		}
#endif
	} while (0);

	MY_DEBUG(*info, "Content located [%s/%s/%s] at [%s|meta2|%s]",
		full_nsname, info->content.container_id, info->content.path,
		full_nsname, info->location->m2_url[0]);
end_label:
	g_free(full_nsname);
	return rc;
}

static void
free_chunk(struct upload_info_s *info)
{
	if (info->fd >= 0)
		metautils_pclose(&(info->fd));

	// do NOT free info->src_path
	g_free(info->src_basename);
	g_free(info->dst_host);
	g_free(info->dst_volume);

	chunk_textinfo_free_content(&(info->chunk));
	content_textinfo_free_content(&(info->content));

	meta2_maintenance_destroy_content(info->raw_old);
	meta2_maintenance_destroy_content(info->raw_new);

	gs_container_location_free(info->location);

	g_free(info->comp);
	g_free(info->algo);
	g_free(info->blocksize);

	if (info->chunk_buffer)
		g_byte_array_free(info->chunk_buffer, TRUE);

	service_info_clean(info->service);

	memset(info, 0, sizeof(*info));
	info->fd = -1;
}

static int
move_chunk(const gchar *path)
{
	int rc = 0;
	GError *err = NULL;
	struct upload_info_s info;

	if ((volumes_last_update + interval_update_services) <= time(NULL)) {
		if (!load_volumes()) {
			MY_WARN(info, "Failed to reload volume list, load balancing may be wrong");
		}
	}

	if (!load_chunk(path, &info))
		goto label_exit;

	if (flag_fake) { /* The flag fake only run and resolve the chunks */
		FINAL_INFO(info, "chunk=[%s] resolved", path);
		free_chunk(&info);
		return 1;
	}

	if (!upload_chunk(&info)) {
		FINAL_ERROR(info, "Upload error src[%s] dst[%s]",
				info.src_descr, info.dst_descr);
		goto label_exit;
	}

	if (flag_download && !download_and_check_chunk(&info)) {
		FINAL_ERROR(info, "Download failed src[%s] dst[%s]",
				info.src_descr, info.dst_descr);
		delete_uploaded_chunk(&info);
		goto label_exit;
	}

	/* Manage the upload's success: validates the new chunk in the META2 */
	if ((err = validate_chunk_in_all_meta2(&info))) {
		/* XXX: before, we thought that Validation potentially PARTIALLY FAILED,
		 * so do not delete neither the local nor the remote chunk. This is an
		 * error and lead to loop replicaion of chunks when their single meta2
		 * is broken. */
		if (err->code == ERRCODE_READ_TIMEOUT) {
			// This case happened in meta2 databases with missing chunk index
			MY_INFO(info, "Last error was a timeout, preserve new chunk in "
					"case meta2 operation succeeds (but is really slow)");
		} else {
			FINAL_ERROR(info, "META2 operation failed src[%s] dst[%s]",
					info.src_descr, info.dst_descr);
			delete_uploaded_chunk(&info);
		}
		goto label_exit;
	}

	/* FIXME: https://jira.itsm.atosworldline.com/jira/browse/TO-HONEYCOMB-673
	 * Call m2v2_remote_execute_GET_BY_CHUNK without limit and
	 * update chunks with m2v2_remote_execute_OVERWRITE */

	if (!flag_unlink)
			MY_NOTICE(info, "Removal disabled");
	else {
		if (-1 == unlink(path))
			MY_WARN(info, "unlink failed (%d %s) src[%s] dst[%s]",
				errno, strerror(errno), info.src_descr, info.dst_descr);
		else
			MY_INFO(info, "Unlinked %s", path);
	}

	rc = 1;

label_exit:
	if (rc)
		FINAL_INFO(info, "Migration successful src[%s] dst[%s] (stgclass: %s)",
				info.src_descr, info.dst_descr,
				service_info_get_stgclass(info.service, "unknown"));
	free_chunk(&info);
	return rc;
}

static gboolean
_does_basename_match_a_pattern(const gchar *bn)
{
	GSList *l;

	if (!patterns)
		return TRUE;

	for (l=patterns; l ;l=l->next) {
		if (!fnmatch((gchar*)(l->data), bn, 0)) {
			return TRUE;
		}
	}

	return FALSE;
}

static gboolean
run_directory(const gchar *basedir, int depth, struct mover_stats_s *stats)
{
	const gchar *path;
	gchar fullpath[2048];
	size_t fullpath_len;
	GDir *gdir = NULL;
	GError *gerr = NULL;

	if (!may_continue(depth, stats)) {
		GRID_DEBUG("Directory: not rescursing in [%s],"
				" termination condition met", basedir);
		return TRUE;
	}

	gdir = g_dir_open(basedir, 0, &gerr);
	if (!gdir) {
		GRID_WARN("g_dir_open(%s) = %s", basedir, gerror_get_message(gerr));
		if (gerr)
			g_clear_error(&gerr);
		return !flag_exit_on_error;
	}

	while (NULL != (path = g_dir_read_name(gdir))) {
		int path_len = strlen(path);
		fullpath_len = g_snprintf(fullpath, sizeof(fullpath), "%s/%.*s",
				basedir, path_len, path);

		if ((path[0]=='.' && (path_len==1 || (path_len==2 && path[1]=='.'))) ||
			0 == g_ascii_strcasecmp(path, REDC_LOSTFOUND_FOLDER)) {
			INFO("Skip %s", path);
			continue;
		}

		if (depth == 0 && !_does_basename_match_a_pattern(path)) {
			GRID_TRACE("IGNORE [%s]", fullpath);
			continue;
		}

		if (fullpath_len >= sizeof(fullpath)) {/* Path too long */
			GRID_WARN("path too long for a chunk [%s/%.*s]",
					basedir, path_len, path);
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
				GRID_DEBUG("Skipping non-chunk file %s", fullpath);
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
							GRID_WARN("Failed to prune dir=[%s]: %s",
									fullpath, strerror(errno));
						else {
							GRID_NOTICE("Pruned dir=[%s]", fullpath);
							stats->dirs_pruned ++;
						}
					}
					g_dir_close(g_subdir);
				}
			}
		}
		else {
			stats->chunk_skipped ++;
			GRID_INFO("Path skipped [%.*s]: not a regular file nor a directory",
					(int)fullpath_len, fullpath);
		}
	}

label_exit:
	g_dir_close(gdir);
	stats->dirs_run ++;
	return TRUE;

label_error:
	g_dir_close(gdir);
	stats->dirs_run ++;
	return FALSE;
}

/* ------------------------------------------------------------------------- */

static const char*
rawx_mover_usage(void)
{
	return "\tVOLUME [PATTERN...]";
}

void
rawx_mover_stop(void)
{
	flag_running = FALSE;
}

gboolean
rawx_mover_configure(int argc, char **args)
{
	if (argc < 1) {
		GRID_ERROR("Missing argument: rawx volume");
		return FALSE;
	}

	if (forced_namespace != NULL) {
		GRID_NOTICE("Explicitely configured namespace=[%s]",
				forced_namespace->str);
	}

	/* Save the volume's name and introspects the volumes XATTR for
	 * a namespaces name and a RAWX url */
	if (!save_canonical_volume(args[0])) {
		GRID_ERROR("Volume name too long");
		return FALSE;
	}

	/* Save potential patterns */
	gint i = 1;
	for (; i < argc ;++i) {
		patterns = g_slist_append(patterns, args[i]);
	}
	return TRUE;
}

static gboolean
rawx_mover_init(void)
{
	GError *gerr = NULL;
	gs_error_t *gserr = NULL;
	gchar *str = NULL;

	if (!rawx_get_lock_info(rawx_vol, rawx_str_addr, sizeof(rawx_str_addr),
			ns_name, sizeof(ns_name), &gerr)) {
		GRID_ERROR("The volume %s doesn't seem to be a RAWX volume: %s",
				rawx_str_addr, gerr->message);
		g_clear_error(&gerr);
		return FALSE;
	}
	GRID_DEBUG("Info got from RAWX xattr: NS=[%s] URL=[%s]",
			ns_name, rawx_str_addr);

	/* Check the URL */
	if (!*rawx_str_addr) {
		GRID_ERROR("Missing RAWX url in xattr of [%s]", rawx_vol);
		return FALSE;
	}
	if (!l4_address_init_with_url(&rawx_addr, rawx_str_addr, &gerr)) {
		GRID_ERROR("Invalid RAWX url [%s] in xattr of [%s]: %s",
				rawx_str_addr, rawx_vol, gerr->message);
		g_clear_error(&gerr);
		return FALSE;
	}

	/* Check the conscience of the introspected namespace can be found */
	if (!*ns_name && (!forced_namespace || !forced_namespace->len)) {
		GRID_ERROR("No namespace found for [%s] (not in xattr, none forced with '-O Namespace=')",
				rawx_vol);
		return FALSE;
	}
	if (forced_namespace && forced_namespace->len) {
		if (*ns_name && 0 != strcmp(forced_namespace->str, ns_name)) {
			GRID_ERROR("Forced namespace [%s] does not match namespace in xattr [%s]",
					forced_namespace->str, ns_name);
			return FALSE;
		}
		memcpy(ns_name, forced_namespace->str, LIMIT_LENGTH_NSNAME);
	}

	/* Now check the namespace is known locally */
	gserr = NULL;
	gs_client = gs_grid_storage_init2(ns_name, 10000, 60000, &gserr);
	if (!gs_client) {
		GRID_ERROR("Invalid RAWX namespace [%s]: %s",
				ns_name, gs_error_get_message(gserr));
		gs_error_free(gserr);
		return FALSE;
	}

	lbpool = grid_lbpool_create(ns_name);
	if (!load_volumes()) {
		return FALSE;
	}

	addr_info_to_string(&rawx_addr, rawx_str_addr, sizeof(rawx_str_addr));
	GRID_DEBUG("Using NS=[%s] RAWX=[%s] VOL=[%s]",
			ns_name, rawx_str_addr, rawx_vol);

	if (!(str = rawx_get_real_volume_name())) {
		if (flag_exit_on_error) {
			GRID_ERROR("No RAWX service found for url [%s] in namespace [%s]",
				rawx_str_addr, ns_name);
			return FALSE;
		} else {
			GRID_WARN("No RAWX service found for url [%s] in namespace [%s]",
				rawx_str_addr, ns_name);
		}
	} else {
		if (0 != g_ascii_strcasecmp(str, rawx_vol)) {
			GRID_ERROR("RAWX volume mismatch for url [%s] in namespace [%s]: given(%s) != found(%s)",
					rawx_str_addr, ns_name, rawx_vol, str);
			g_free(str);
			return FALSE;
		}
		g_free(str);
	}


	return TRUE;
}

void
rawx_mover_fini(void)
{
	if (gs_client) {
		gs_grid_storage_free(gs_client);
		gs_client = NULL;
	}

	if (lbpool) {
		grid_lbpool_destroy(lbpool);
		lbpool = NULL;
	}

	if (volumes) {
		g_slist_free_full(volumes, (GDestroyNotify)service_info_clean);
		volumes = NULL;
	}

	if (patterns)
		g_slist_free(patterns);

	free_m2v1_list();
}

void
rawx_mover_action(void)
{
	gboolean rc = TRUE;
	struct mover_stats_s stats;

	rc = rawx_mover_init();
	if (!rc) {
		grid_main_set_status(1);
		return;
	}

	/* Config abstract */
	if (GRID_INFO_ENABLED()) {
		gdouble vol_usage;
		struct grid_main_option_s *o;

		if (!get_volume_usage(&vol_usage)) {
			grid_main_set_status(1);
			return;
		}

		GRID_INFO("Running volume [%s] with rawx_mover_options:\n", rawx_vol);
		GRID_INFO("-\t%-32s %s\n", "NS", ns_name);
		GRID_INFO("-\t%-32s %s\n", "RAWX", rawx_str_addr);
		GRID_INFO("-\t%-32s %.3f%%\n", "Usage", vol_usage);
		GRID_INFO("-\t%-32s %s\n", "Debug", flag_debug ? "on" : "off");
		for (o=rawx_mover_options; o->name ;o++) {
			if (o->type == OT_BOOL)
				GRID_INFO("-\t%-32s %s\n", o->name, (*(o->data.b)?"on":"off"));
			else if (o->type == OT_INT)
				GRID_INFO("-\t%-32s %d\n", o->name, *(o->data.i));
			else if (o->type == OT_INT64)
				GRID_INFO("-\t%-32s %"G_GINT64_FORMAT"\n", o->name,
						*(o->data.i64));
			else if (o->type == OT_TIME)
				GRID_INFO("-\t%-32s %ld\n", o->name, *(o->data.t));
			else if (o->type == OT_DOUBLE)
				GRID_INFO("-\t%-32s %f\n", o->name, *(o->data.d));
			else if (o->type == OT_STRING) {
				GRID_INFO("-\t%-32s %s\n", o->name,
						(*(o->data.str))? (*(o->data.str))->str : NULL);
			}
		}
	}

	/* Main loop */
	memset(&stats, 0, sizeof(stats));
	for (;;) {
		gint64 nb_chunks_before, nb_chunks_after;

		/* Check the volume lock */
		// FIXME TODO several services and crawler need something like this
		if (*rawx_vol && lock_xattr_name && lock_xattr_name->len) {
			if (!volume_lock_set(rawx_vol, lock_xattr_name->str)) {
				break;
			}
		}

		/* Count the number of chunks currently met */
		nb_chunks_before = stats.chunk_success + stats.chunk_failure;
		rc = run_directory(rawx_vol, 0, &stats);
		nb_chunks_after = stats.chunk_success + stats.chunk_failure;

		if (flag_stop_unless_action && nb_chunks_before == nb_chunks_after) {
			GRID_NOTICE("No chunks have been met this turn,"
					" we cannot do more.");
			break;
		}

		if (!(rc && flag_loop && may_continue(0, &stats)))
			break;
		sleep(1);
	}

	// FIXME TODO several services and crawler need something like this
	if (*rawx_vol && lock_xattr_name && lock_xattr_name->len) {
		if (volume_lock_get(rawx_vol, lock_xattr_name->str) == getpid())
			volume_lock_release(rawx_vol, lock_xattr_name->str);
	}

	/* Run statistics */
	if (GRID_INFO_ENABLED()) {
		GRID_INFO("Volume run %s\n", rc ? "ok" : "KO");
		GRID_INFO("-\tchunk.success %"G_GINT64_FORMAT"\n", stats.chunk_success);
		GRID_INFO("-\tchunk.skipped %"G_GINT64_FORMAT"\n", stats.chunk_skipped);
		GRID_INFO("-\tchunk.failure %"G_GINT64_FORMAT"\n", stats.chunk_failure);
		GRID_INFO("-\tdirs.run      %"G_GINT64_FORMAT"\n", stats.dirs_run);
		GRID_INFO("-\tdirs.pruned   %"G_GINT64_FORMAT"\n", stats.dirs_pruned);
	}
}

static struct grid_main_option_s *
rawx_mover_get_options(void)
{
	return rawx_mover_options;
}

static void
rawx_mover_set_defaults(void)
{
	memset(path_log4c, 0, sizeof(path_log4c));
	memset(ns_name, 0, LIMIT_LENGTH_NSNAME);
	memset(rawx_vol, 0, LIMIT_LENGTH_VOLUMENAME);
	memset(&rawx_addr, 0, sizeof(addr_info_t));
	lock_xattr_name = g_string_new(VOLUME_LOCK_XATTR_NAME);

	return;
}

static struct grid_main_callbacks rawx_mover_callbacks =
{
	.options = rawx_mover_get_options,
	.action = rawx_mover_action,
	.set_defaults = rawx_mover_set_defaults,
	.specific_fini = rawx_mover_fini,
	.configure = rawx_mover_configure,
	.usage = rawx_mover_usage,
	.specific_stop = rawx_mover_stop,
};

int
main(int argc, char **argv)
{
	/* Prevents log disabling by gs_grid_storage_init2()
	 * but does not enable log4c */
	setenv(ENV_LOG4C_ENABLE, "0", TRUE);
	return grid_main(argc, argv, &rawx_mover_callbacks);
}

