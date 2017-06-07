/*
OpenIO SDS rawx-apache2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__rawx_apache2__src__rawx_config_h
# define OIO_SDS__rawx_apache2__src__rawx_config_h 1

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>

#include <mod_dav.h>

#include <rawx-lib/src/rawx.h>

#include "rawx_event.h"

#define FSYNC_ON_CHUNK 1
#define FSYNC_ON_CHUNK_DIR 2

#define RAWX_STATNAME_REQ_ALL       "q0"
#define RAWX_STATNAME_REQ_CHUNKGET  "q1"
#define RAWX_STATNAME_REQ_CHUNKPUT  "q2"
#define RAWX_STATNAME_REQ_CHUNKDEL  "q3"
#define RAWX_STATNAME_REQ_STAT      "q4"
#define RAWX_STATNAME_REQ_INFO      "q5"
#define RAWX_STATNAME_REQ_RAW       "q6"
#define RAWX_STATNAME_REQ_OTHER     "q7"

#define RAWX_STATNAME_REP_2XX       "r1"
#define RAWX_STATNAME_REP_4XX       "r2"
#define RAWX_STATNAME_REP_5XX       "r3"
#define RAWX_STATNAME_REP_OTHER     "r4"
#define RAWX_STATNAME_REP_403       "r5"
#define RAWX_STATNAME_REP_404       "r6"
#define RAWX_STATNAME_REP_BREAD     "r7"
#define RAWX_STATNAME_REP_BWRITTEN  "r8"

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
	apr_uint32_t time_stat;
	apr_uint32_t time_info;
	apr_uint32_t time_raw;
	apr_uint32_t time_other;
};

struct shm_stats_s {

	struct {
		apr_uint32_t version;
		apr_uint32_t padding[3];
	} header;

	struct rawx_stats_s body;

	apr_uint64_t padding[16];
};

enum rawx_checksum_mode_e {
	CHECKSUM_ALWAYS = 0, /* by default */
	CHECKSUM_SMART, /* not for EC/ */
	CHECKSUM_NEVER,
};

typedef struct dav_rawx_server_conf_s dav_rawx_server_conf;

struct dav_rawx_server_conf_s {
	char rawx_id[64]; /* enough for @ipv6:port */
	apr_pool_t *pool;
	char docroot[1024];
	char ns_name[LIMIT_LENGTH_NSNAME];
	unsigned int hash_depth;
	unsigned int hash_width;
	unsigned int fsync_on_close;
	unsigned int fallocate;
	unsigned int enabled_compression;

	char event_agent_addr[RAWX_EVENT_ADDR_SIZE];

	enum rawx_checksum_mode_e checksum_mode;

	/* Statistics involved data */
	struct {
		char path[128];
		apr_shm_t *handle;
	} shm;

	void (*cleanup)(dav_rawx_server_conf *conf);
};

apr_status_t server_init_master_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

void server_master_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog);

apr_status_t server_init_child_stat(dav_rawx_server_conf *conf, apr_pool_t *pool, apr_pool_t *plog);

apr_status_t server_child_stat_fini(dav_rawx_server_conf *conf, apr_pool_t *plog);

void server_add_stat(dav_rawx_server_conf *conf, const char *n, apr_uint32_t value, apr_uint32_t duration);

void server_inc_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration);

void server_inc_request_stat(dav_rawx_server_conf *conf, const char *n, apr_time_t duration);

void server_inc_daverror_stat(dav_rawx_server_conf *conf, dav_error *derr);

dav_error *server_create_and_stat_error(dav_rawx_server_conf *conf, apr_pool_t *p, int status, int error_id, const char *desc);

apr_uint64_t server_get_reqperseq(dav_rawx_server_conf *conf);

apr_uint64_t server_get_reqavgtime(dav_rawx_server_conf *conf);

#endif /*OIO_SDS__rawx_apache2__src__rawx_config_h*/
