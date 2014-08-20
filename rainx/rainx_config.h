#ifndef _RAINX_CONFIG_H_
#define _RAINX_CONFIG_H_

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <mod_dav.h>

// TODO FIXME replace this by the APR equivalent
#include <openssl/md5.h>

#include <rawx-lib/src/rawx.h>
#include <rainx/rainx_stats_rrd.h>

struct rainx_stats_s {
	apr_uint64_t req_all;
	apr_uint64_t req_chunk_get;
	apr_uint64_t req_chunk_put;
	apr_uint64_t req_chunk_del;
	apr_uint64_t req_stat;
	apr_uint64_t req_info;
	apr_uint64_t req_raw;
	apr_uint64_t req_other;
	apr_uint64_t rep_2XX;
	apr_uint64_t rep_4XX;
	apr_uint64_t rep_5XX;
	apr_uint64_t rep_other;
	apr_uint64_t rep_403;
	apr_uint64_t rep_404;
	apr_uint64_t rep_bread;
	apr_uint64_t rep_bwritten;
	apr_uint64_t time_all;
	apr_uint64_t time_put;
	apr_uint64_t time_get;
	apr_uint64_t time_del;
	struct rainx_stats_rrd_s rrd_req_sec;
	struct rainx_stats_rrd_s rrd_duration;
	struct rainx_stats_rrd_s rrd_req_put_sec;
	struct rainx_stats_rrd_s rrd_put_duration;
	struct rainx_stats_rrd_s rrd_req_get_sec;
	struct rainx_stats_rrd_s rrd_get_duration;
	struct rainx_stats_rrd_s rrd_req_del_sec;
	struct rainx_stats_rrd_s rrd_del_duration;
};

struct shm_stats_s {

	struct {
		apr_uint32_t version;
		apr_uint32_t padding[3];
	} header;

	struct rainx_stats_s body;

	apr_uint64_t padding[16];
};

typedef struct dav_rainx_server_conf_s dav_rainx_server_conf;
 
struct dav_rainx_server_conf_s {
	apr_pool_t *pool;
	char docroot[1024];
	char ns_name[LIMIT_LENGTH_NSNAME];
	int hash_depth;
	int hash_width;
	int fsync_on_close;
	apr_uint32_t headers_scheme;
	apr_interval_time_t socket_timeout;

	/* Statistics involved data */
	struct {
		char path[128];
		apr_file_t *fh;
		apr_global_mutex_t *handle;
	} lock;
	struct {
		char path[128];
		apr_file_t *fh;
		apr_shm_t *handle;
	} shm;

	void (*cleanup)(dav_rainx_server_conf *conf);

	int enabled_acl;
	rawx_conf_t* rainx_conf;
	ssize_t FILE_buffer_size; /**< negative or zero means 'unset', positive set the buffer size to this value, but we force a maximum of '131072' */
};

/**
 *
 *
 *
 */
apr_status_t server_init_master_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

/**
 *
 *
 *
 */
void server_master_stat_fini(dav_rainx_server_conf *conf, apr_pool_t *plog);

/**
 *
 *
 *
 */
apr_status_t server_init_child_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

/**
 *
 *
 *
 */
apr_status_t server_child_stat_fini(dav_rainx_server_conf *conf, apr_pool_t *plog);

/**
 *
 *
 *
 */
void server_add_stat(dav_rainx_server_conf *conf, const char *n, apr_uint64_t value, apr_uint64_t duration);

/**
 *
 *
 *
 */
void server_inc_stat(dav_rainx_server_conf *conf, const char *n, apr_time_t duration);

/**
 *
 *
 *
 */
void server_inc_request_stat(dav_rainx_server_conf *conf, const char *n, apr_time_t duration);

/**
 *
 *
 *
 */
void server_inc_daverror_stat(dav_rainx_server_conf *conf, dav_error *derr);

/**
 *
 *
 *
 */
dav_error *server_create_and_stat_error(dav_rainx_server_conf *conf, apr_pool_t *p, int status, int error_id, const char *desc);

/**
 *
 *
 *
 */
void server_getall_stat(dav_rainx_server_conf *conf, apr_pool_t *pool, struct rainx_stats_s *stats);

/**
 *
 *
 *
 */
apr_uint64_t server_get_reqperseq(dav_rainx_server_conf *conf);

/**
 *
 *
 *
 */
apr_uint64_t server_get_reqavgtime(dav_rainx_server_conf *conf);


/***************** UTILS FUNCTIONS *************************/

/**
 *
 *
 *
 */
char * _get_compression_algorithm(apr_pool_t *p, namespace_info_t *ns_info);

/**
 *
 *
 *
 */
apr_int64_t _get_compression_block_size(apr_pool_t *p, namespace_info_t *ns_info);

/**
 *
 *
 *
 */
GSList * _get_acl(apr_pool_t *p, namespace_info_t *ns_info);

/**
 *
 *
 *
 */
gboolean update_rainx_conf(apr_pool_t* p, rawx_conf_t **rainx_conf, const gchar* ns_name);

/**
 * Update the rainx configuration if it's older than a fixed delay
 */
gboolean update_rainx_conf_if_necessary(apr_pool_t* p, rawx_conf_t **rainx_conf);

#endif /*  _RAINX_CONFIG_H_ */
