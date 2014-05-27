#ifndef _RAWX_REPO_CORE_H_
#define _RAWX_REPO_CORE_H_

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <mod_dav.h>

#include <openssl/md5.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>
#include <rawx-lib/src/compression.h>

#include "rawx_config.h"

/* context needed to identify a resource */
struct dav_resource_private {
	apr_pool_t *pool;        /* memory storage pool associated with request */
	request_rec *request;

	char dirname[1024];
	char hex_chunkid[STRLEN_CHUNKID];
	gboolean compression;
	char compress_algo[512];

	const char *fullpath;
	apr_finfo_t finfo;
	struct content_textinfo_s content;
	struct chunk_textinfo_s chunk;
	struct compression_ctx_s comp_ctx;
	struct compressed_chunk_s cp_chunk;

	/**/
	char *forced_cp;
	char *forced_cp_algo;
	char *forced_cp_bs;

	gboolean update_only;
	struct storage_policy_s *sp;
};

struct dav_stream {
	const dav_resource *r;
	apr_pool_t *p;
	int fsync_on_close;
	FILE *f;
	gboolean compression;
	void *buffer;	
	apr_size_t bufsize;
	const char *pathname;
	const char *final_pathname;
	apr_size_t blocksize;
	gulong compress_checksum;
	guint32 compressed_size; 
	char *metadata_compress;
	struct compression_ctx_s comp_ctx;

	GChecksum *gchecksum;
	MD5_CTX md5_ctx;
};

/**
 *
 *
 *
 */
dav_error * resource_init_decompression(dav_resource *resource, dav_rawx_server_conf *conf);

/**
 *
 *
 *
 */
void resource_stat_chunk(dav_resource *resource, int xattr_too);

/**
 *
 *
 *
 */
void request_load_chunk_info(request_rec *request, dav_resource *resource);

/**
 *
 *
 *
 */
void request_parse_query(request_rec *r, dav_resource *resource);

/**
 *
 *
 *
 */
void chunk_textinfo_fill_headers(request_rec *r, struct chunk_textinfo_s *cti);

/**
 *
 *
 *
 */
void content_textinfo_fill_headers(request_rec *r, struct content_textinfo_s *cti);

/**************** repository internals functions ************************/

/**
 *
 *
 *
 */
dav_error * rawx_repo_check_request(request_rec *req, const char *root_dir, const char *label,
		int use_checked_in, dav_resource_private *ctx, dav_resource **result_resource);

/**
 *
 *
 *
 */
dav_error * rawx_repo_configure_hash_dir(request_rec *req, dav_resource_private *ctx);

/**
 *
 *
 *
 */
dav_error * rawx_repo_write_last_data_crumble(dav_stream *stream);

/**
 *
 *
 *
 */
dav_error * rawx_repo_rollback_upload(dav_stream *stream);

/**
 *
 *
 *
 */
dav_error * rawx_repo_commit_upload(dav_stream *stream);

/**
 *
 *
 *
 */
dav_error * rawx_repo_ensure_directory(const dav_resource *resource);

/**
 *
 *
 *
 */
dav_error * rawx_repo_stream_create(const dav_resource *resource, dav_stream **result);

#endif /*  _RAWX_REPO_CORE_H_ */
