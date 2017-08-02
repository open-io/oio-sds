/*
OpenIO SDS rawx-apache2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#ifndef OIO_SDS__rawx_apache2__src__rawx_repo_core_h
# define OIO_SDS__rawx_apache2__src__rawx_repo_core_h 1

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_shm.h>
#include <apr_global_mutex.h>
#include <mod_dav.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>
#include <rawx-lib/src/compression.h>

#include "rawx_config.h"

/* context needed to identify a resource */
struct dav_resource_private
{
	apr_pool_t *pool;
	request_rec *request;

	struct storage_policy_s *sp;

	const char *fullpath;

	apr_finfo_t finfo;
	struct chunk_textinfo_s chunk;
	struct compression_ctx_s comp_ctx;
	struct compressed_chunk_s cp_chunk;

	gboolean update_only : 8;
	gboolean compression : 8;

	char hex_chunkid[STRLEN_CHUNKID];
	char file_extension[32];
	char compress_algo[128];
	char dirname[512];
};

struct dav_stream
{
	const dav_resource *r;
	apr_pool_t *p;
	int fsync_on_close;
	FILE *f;
	void *buffer;
	apr_size_t buffer_size;
	apr_size_t buffer_offset;
	const char *pathname;
	const char *final_pathname;

	gulong compress_checksum;
	guint32 compressed_size;
	char *metadata_compress;
	struct compression_ctx_s comp_ctx;
	gboolean compression;

	GChecksum *md5;
	apr_size_t total_size;
};

#define RESOURCE_STAT_CHUNK_READ_ATTRS 0x01
#define RESOURCE_STAT_CHUNK_PENDING    0x02

dav_error * resource_init_decompression(dav_resource *resource, dav_rawx_server_conf *conf);

void resource_stat_chunk(dav_resource *resource, int flags);

void request_load_chunk_info_from_headers(request_rec *request,
		struct chunk_textinfo_s *cti);

void request_overload_chunk_info_from_trailers(request_rec *request,
		struct chunk_textinfo_s *cti);

const char * check_chunk_info(const struct chunk_textinfo_s * const cti);

const char * check_chunk_info_with_trailers(const struct chunk_textinfo_s * const cti);

void request_parse_query(request_rec *r, dav_resource *resource);

void request_fill_headers(request_rec *r, struct chunk_textinfo_s *c1);

dav_error * rawx_repo_check_request(request_rec *req, const char *root_dir, const char *label,
		int use_checked_in, dav_resource_private *ctx, dav_resource **result_resource);

dav_error * rawx_repo_configure_hash_dir(request_rec *req, dav_resource_private *ctx);

dav_error * rawx_repo_write_last_data_crumble(dav_stream *stream);

dav_error * rawx_repo_rollback_upload(dav_stream *stream);

dav_error * rawx_repo_commit_upload(dav_stream *stream);

dav_error * rawx_repo_stream_create(const dav_resource *resource, dav_stream **result);

#endif /*OIO_SDS__rawx_apache2__src__rawx_repo_core_h*/
