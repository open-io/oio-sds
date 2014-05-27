#ifndef _RAWX_CONFIG_H_
#define _RAWX_CONFIG_H_

// TODO FIXME replace with APR equivalent
#include <openssl/md5.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>

#include <mod_dav.h>

#include <rawx-lib/src/rawx.h>

#include "rawx_stats_rrd.h"

#define FSYNC_ON_CHUNK 1
#define FSYNC_ON_CHUNK_DIR 2

struct rawx_stats_s {
	apr_uint32_t req_all;
	apr_uint32_t req_chunk_get;
	apr_uint32_t req_chunk_put;
	apr_uint32_t req_chunk_del;
	apr_uint32_t req_stat;
	apr_uint32_t req_info;
	apr_uint32_t req_raw;
	apr_uint32_t req_other;
	apr_uint32_t rep_2XX;
	apr_uint32_t rep_4XX;
	apr_uint32_t rep_5XX;
	apr_uint32_t rep_other;
	apr_uint32_t rep_403;
	apr_uint32_t rep_404;
	apr_uint32_t rep_bread;
	apr_uint32_t rep_bwritten;
	apr_uint32_t time_all;
	apr_uint32_t time_put;
	apr_uint32_t time_get;
	apr_uint32_t time_del;
	struct rawx_stats_rrd_s rrd_req_sec;
	struct rawx_stats_rrd_s rrd_duration;
	struct rawx_stats_rrd_s rrd_req_put_sec;
	struct rawx_stats_rrd_s rrd_put_duration;
	struct rawx_stats_rrd_s rrd_req_get_sec;
	struct rawx_stats_rrd_s rrd_get_duration;
	struct rawx_stats_rrd_s rrd_req_del_sec;
	struct rawx_stats_rrd_s rrd_del_duration;
};

struct shm_stats_s {

	struct {
		apr_uint32_t version;
		apr_uint32_t padding[3];
	} header;

	struct rawx_stats_s body;

	apr_uint64_t padding[16];
};

typedef struct dav_rawx_server_conf_s dav_rawx_server_conf;

struct dav_rawx_server_conf_s {
	apr_pool_t *pool;
	char docroot[1024];
	char ns_name[LIMIT_LENGTH_NSNAME];
	int hash_depth;
	int hash_width;
	int fsync_on_close;
	apr_uint32_t headers_scheme;

	/* Statistics involved data */
	struct {
		apr_global_mutex_t *handle;
	} lock;
	struct {
		char path[128];
		apr_shm_t *handle;
	} shm;

	void (*cleanup)(dav_rawx_server_conf *conf);

	int enabled_acl;
	rawx_conf_t* rawx_conf;
	ssize_t FILE_buffer_size; /**< negative or zero means 'unset', positive set the buffer size to this value, but we force a maximum of '131072' */
};

/**
 *
 *
 *
 */
apr_status_t server_init_master_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

/**
 *
 *
 *
 */
void server_master_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog);

/**
 *
 *
 *
 */
apr_status_t server_init_child_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

/**
 *
 *
 *
 */
apr_status_t server_child_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog);

/**
 *
 *
 *
 */
void server_add_stat(dav_rawx_server_conf *conf, const char *n, apr_uint32_t value, apr_uint32_t duration);

/**
 *
 *
 *
 */
void server_inc_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration);

/**
 *
 *
 *
 */
void server_inc_request_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration);

/**
 *
 *
 *
 */
void server_inc_daverror_stat(dav_rawx_server_conf *conf, dav_error *derr);

/**
 *
 *
 *
 */
dav_error *server_create_and_stat_error(dav_rawx_server_conf *conf, apr_pool_t *p, int status, int error_id, const char *desc);

/**
 *
 *
 *
 */
apr_uint64_t server_get_reqperseq(dav_rawx_server_conf *conf);

/**
 *
 *
 *
 */
apr_uint64_t server_get_reqavgtime(dav_rawx_server_conf *conf);


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
gboolean update_rawx_conf(apr_pool_t* p, rawx_conf_t **rawx_conf, const gchar* ns_name);

#endif /*  _RAWX_CONFIG_H_ */
