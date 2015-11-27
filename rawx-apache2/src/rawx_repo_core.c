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

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rawx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */
#include <mod_dav.h>

#include <ctype.h>

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>

#include "rawx_repo_core.h"
#include "rawx_internals.h"
#include "rawx_event.h"

#define DEFAULT_BLOCK_SIZE "5242880"
#define DEFAULT_COMPRESSION_ALGO "ZLIB"

/******************** INTERNALS METHODS **************************/

static apr_status_t
apr_storage_policy_clean(void *p)
{
	struct storage_policy_s *sp = (struct storage_policy_s *) p;
	storage_policy_clean(sp);
	return APR_SUCCESS;
}

static void
__set_header(request_rec *r, const char *n, const char *v)
{
	if (!v) return;
	apr_table_setn(r->headers_out, apr_pstrcat(r->pool,
				RAWX_HEADER_PREFIX, n, NULL), apr_pstrdup(r->pool, v));
}

static dav_error *
_set_chunk_extended_attributes(dav_stream *stream)
{
	GError *ge = NULL;
	dav_error *e = NULL;

	/* Save the new Chunk's hash in the XATTR, in upppercase! */
	gchar *hex = g_ascii_strup (g_checksum_get_string(stream->md5), -1);
	stream->r->info->chunk.hash = apr_pstrdup(stream->p, hex);
	g_free (hex);

	stream->r->info->chunk.size = apr_psprintf(stream->r->pool, "%d", (int)stream->total_size);

	if(stream->compressed_size) {
		char size[32];
		apr_snprintf(size, 32, "%d", stream->compressed_size);
		if(!set_rawx_full_info_in_attr(stream->pathname, fileno(stream->f), &ge,
					&(stream->r->info->content), &(stream->r->info->chunk),
					stream->metadata_compress, size)) {
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_FORBIDDEN, 0, apr_pstrdup(stream->p, gerror_get_message(ge)));
		}
	} else { 
		if(!set_rawx_full_info_in_attr(stream->pathname, fileno(stream->f), &ge, &(stream->r->info->content),
					&(stream->r->info->chunk), NULL, NULL)) {
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_FORBIDDEN, 0, apr_pstrdup(stream->p, gerror_get_message(ge)));
		}
	}

	if(ge)
		g_clear_error(&ge);

	return e;
}

static dav_error *
_finalize_chunk_creation(dav_stream *stream)
{
	dav_error *e = NULL;
	int status = 0;

	/* ensure to flush the FILE * buffer in system fd */
	if(fflush(stream->f)) {
		DAV_ERROR_REQ(stream->r->info->request, 0, "fflush error : %s", strerror(errno));
		e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				apr_pstrcat(stream->p, "fflush error : ", strerror(errno), NULL));
	}

	if (stream->fsync_on_close & FSYNC_ON_CHUNK) {
		if (-1 == fsync(fileno(stream->f))) {
			DAV_ERROR_REQ(stream->r->info->request, 0, "fsync error : %s", strerror(errno));
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					apr_pstrcat(stream->p, "fsync error : ", strerror(errno), NULL));
		}
	}

	fclose(stream->f);

	/* Finish: move pending file to final file */
	status = rename(stream->pathname, stream->final_pathname);
	if( 0 != status ) {
		e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				MAP_IO2HTTP(status), 0,
				apr_pstrcat(stream->p, "rename(",stream->pathname, ", ",stream->final_pathname, ") failure : ", strerror(errno), NULL));
	} else if (stream->fsync_on_close & FSYNC_ON_CHUNK_DIR) {
		/* Open directory and call fsync to ensure the rename has been done */
		int dir = open(stream->r->info->dirname, 0);
		if (dir != -1) {
			status = fsync(dir);
			if (status != 0) {
				DAV_ERROR_REQ(stream->r->info->request, 0,
						"fsync error : %s", strerror(errno));
			}
			close(dir);
		} else {
			DAV_ERROR_REQ(stream->r->info->request, 0,
					"could not open directory to fsync: %s", strerror(errno));
		}
	}

	return e;
}

static dav_error *
_write_data_crumble_UNCOMP(dav_stream *stream)
{
	if ( 1 != fwrite(stream->buffer, stream->bufsize, 1, stream->f)) {
		/* ### use something besides 500? */
		return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"An error occurred while writing to a "
				"resource.");
	}

	return NULL;
}

static dav_error *
_write_data_crumble_COMP(dav_stream *stream, gulong *checksum)
{
	GByteArray *gba = g_byte_array_new();
	dav_error *e = NULL;
	int rc = -1;

	rc = stream->comp_ctx.data_compressor(stream->buffer, stream->bufsize, gba, checksum);
	if (0 == rc) {
		if (1 != fwrite(gba->data, gba->len, 1, stream->f)) {
			/* ### use something besides 500? */
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"An error occurred while writing to a "
					"resource.");
		} else {
			stream->compressed_size+=gba->len;
		}
	} else {
		/* ### use something besides 500? */
		e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"An error occurred while compressing data.");
	}		

	g_byte_array_free(gba, TRUE);	

	return e;
}

/******************** RESOURCE UTILY FUNCTIONS *******************/

dav_error *
resource_init_decompression(dav_resource *resource, dav_rawx_server_conf *conf)
{
	char *c = NULL;
	dav_error *r = NULL;
	GError *e = NULL;
	GHashTable *comp_opt = NULL;

	comp_opt = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	if(!get_compression_info_in_attr(resource_get_pathname(resource), &e, &comp_opt)){
		if(comp_opt)
			g_hash_table_destroy(comp_opt);
		if(e)	
			g_clear_error(&e);
		return server_create_and_stat_error(conf, resource->pool, HTTP_CONFLICT, 0, "Failed to get chunk compression in attr");
	}
	c = g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION);
	if (c && 0 == g_ascii_strcasecmp(c, NS_COMPRESSION_ON)) {
		resource->info->compression = TRUE; 
	} else {
		resource->info->compression = FALSE;
	}

	if(resource->info->compression){
		// init compression method according to algo choice
		char *algo = g_hash_table_lookup(comp_opt, NS_COMPRESS_ALGO_OPTION);
		memset(resource->info->compress_algo, 0, sizeof(resource->info->compress_algo));
		memcpy(resource->info->compress_algo, algo, MIN(strlen(algo), sizeof(resource->info->compress_algo)));
		init_compression_ctx(&(resource->info->comp_ctx), algo); 
		if (0 != resource->info->comp_ctx.chunk_initiator(&(resource->info->cp_chunk),
					(char*)resource->info->fullpath)) {
			r = server_create_and_stat_error(resource_get_server_config(resource), resource->pool,
					HTTP_INTERNAL_SERVER_ERROR, 0, "Failed to init chunk bucket");
		}
	}
	if(comp_opt)
		g_hash_table_destroy(comp_opt);

	if(NULL != e)
		g_clear_error(&e);

	return r;
}

/******************** REQUEST UTILITY FUNCTIONS ******************/

void
resource_stat_chunk(dav_resource *resource, int xattr_too)
{
	apr_pool_t *pool;
	dav_resource_private *ctx;
	apr_status_t status;

	ctx = resource->info;
	pool = resource->pool;

	if (resource->type != DAV_RESOURCE_TYPE_REGULAR || resource->collection) {
		DAV_ERROR_RES(resource, 0, "Cannot stat a anything else a chunk");
		return;
	}
	
	char * tmp_path = apr_pstrcat(resource->pool, resource_get_pathname(resource), ".pending", NULL);

	status = apr_stat(&(resource->info->finfo), tmp_path, APR_FINFO_NORM, resource->pool);

	if(status != APR_SUCCESS)
		status = apr_stat(&(resource->info->finfo), resource_get_pathname(resource), APR_FINFO_NORM, resource->pool);

	resource->collection = 0;
	resource->exists = (status == APR_SUCCESS);
	
	if (!resource->exists)
		DAV_DEBUG_RES(resource, 0, "Resource does not exist [%s]", resource_get_pathname(resource));
	else  {
		gboolean rc;
		GError *err = NULL;

		DAV_DEBUG_RES(resource, 0, "Resource exists [%s]", resource_get_pathname(resource));

		memset(&(ctx->content), 0, sizeof(ctx->content));
		memset(&(ctx->chunk), 0, sizeof(ctx->chunk));
		if (xattr_too) {
			rc = get_rawx_info_in_attr(resource_get_pathname(resource), &err,
					&(ctx->content), &(ctx->chunk));
			if (!rc) {
				DAV_DEBUG_RES(resource, 0, "Chunk xattr loading error [%s] : %s",
						resource_get_pathname(resource),
						apr_pstrdup(resource->pool, gerror_get_message(err)));
			}
			else {
				REPLACE_FIELD(pool, content, container_id);
				REPLACE_FIELD(pool, content, content_id);
				REPLACE_FIELD(pool, content, path);
				REPLACE_FIELD(pool, content, version);
				REPLACE_FIELD(pool, content, size);
				REPLACE_FIELD(pool, content, chunk_nb);
				REPLACE_FIELD(pool, content, storage_policy);

				REPLACE_FIELD(pool, content, rawx_list);
				REPLACE_FIELD(pool, content, spare_rawx_list);

				REPLACE_FIELD(pool, chunk, id);
				REPLACE_FIELD(pool, chunk, size);
				REPLACE_FIELD(pool, chunk, position);
				REPLACE_FIELD(pool, chunk, hash);
				REPLACE_FIELD(pool, chunk, metadata);
			}
			if (err)
				g_clear_error(&err);
		}
	}
}

static int
__load_one_header(request_rec *request, const char *name, char **dst)
{
	const char *value = apr_table_get(request->headers_in, name);
	if (!value)
		return 0;
	*dst = apr_pstrdup(request->pool, value);
	return 1;
}

static int
__load_one_header_lc(request_rec *request, const char *name, char **dst)
{
	size_t len = strlen(name);
	char *lc = alloca(len+1);
	memcpy(lc, name, len+1);
	for (char *p=lc+1; *p ;++p) *p = tolower(*p);

	const char *value = apr_table_get(request->headers_in, lc);
	if (!value)
		return 0;
	*dst = apr_pstrdup(request->pool, value);
	return 1;
}

#define LOAD_HEADER2(Where,Name) do { \
	if (!resource->info->Where) { \
		if (!__load_one_header(request, Name, &(resource->info->Where))) \
			__load_one_header_lc(request, Name, &(resource->info->Where)); \
	} \
} while (0)

static void
_up (gchar *s)
{
	if (s) {
		do { *s = g_ascii_toupper(*s); } while (*(s++));
	}
}

const char *
request_load_chunk_info(request_rec *request, dav_resource *resource)
{
	LOAD_HEADER2(content.container_id,   RAWX_HEADER_PREFIX "container-id");

	LOAD_HEADER2(content.content_id,     RAWX_HEADER_PREFIX "content-id");
	LOAD_HEADER2(content.path,           RAWX_HEADER_PREFIX "content-path");
	LOAD_HEADER2(content.version,        RAWX_HEADER_PREFIX "content-version");
	LOAD_HEADER2(content.size,           RAWX_HEADER_PREFIX "content-size");
	LOAD_HEADER2(content.chunk_nb,       RAWX_HEADER_PREFIX "content-chunksnb");
	LOAD_HEADER2(content.storage_policy, RAWX_HEADER_PREFIX "content-stgpol");

	LOAD_HEADER2(chunk.id,           RAWX_HEADER_PREFIX "chunk-id");
	LOAD_HEADER2(chunk.size,         RAWX_HEADER_PREFIX "chunk-size");
	LOAD_HEADER2(chunk.position,     RAWX_HEADER_PREFIX "chunk-pos");
	LOAD_HEADER2(chunk.hash,         RAWX_HEADER_PREFIX "chunk-hash");

	if (!resource->info->content.container_id) return "container-id";
	if (!resource->info->content.content_id) return "content-id";
	if (!resource->info->content.path) return "content-path";
	if (!resource->info->chunk.position) return "chunk-pos";
	
	_up (resource->info->content.container_id);
	_up (resource->info->content.content_id);
	_up (resource->info->chunk.hash);
	_up (resource->info->chunk.id);

	if (!oio_str_ishexa(resource->info->content.container_id, 64))
		return "container-id";
	if (!oio_str_ishexa1(resource->info->content.content_id))
		return "content-id";

	if (resource->info->chunk.id &&
		!oio_str_ishexa1(resource->info->chunk.id))
		return "chunk-id";
	if (resource->info->chunk.hash && resource->info->chunk.hash[0] &&
		!oio_str_ishexa1(resource->info->chunk.hash))
		return "chunk-hash";
	
	return NULL;
}

void
request_parse_query(request_rec *r, dav_resource *resource)
{
	/* Sanity check */
	if(!r->parsed_uri.query)
		return;
	
	char *query = NULL;
	query = apr_pstrdup(r->pool, r->parsed_uri.query);

	/* Expected cp=true&algo=XXXX&bs=XXXX */
	char *k = NULL;
	char *v = NULL;
	char *last = NULL;
	
	k = apr_strtok(query, "=&", &last);
	v = apr_strtok(NULL, "=&",&last);

	if(!k || !v)
		goto end;
		
	if(0 == apr_strnatcasecmp(k, "comp"))
		resource->info->forced_cp = apr_pstrdup(r->pool, v);
	if(0 == apr_strnatcasecmp(k, "algo"))
		resource->info->forced_cp_algo = apr_pstrdup(r->pool, v);
	if(0 == apr_strnatcasecmp(k, "bs"))
		resource->info->forced_cp_bs = apr_pstrdup(r->pool, v);

	while(1) {
		k = apr_strtok(NULL, "=&", &last);
		v = apr_strtok(NULL, "=&", &last);
		if(!k || !v)
			break;
		if(0 == apr_strnatcasecmp(k, "comp"))
			resource->info->forced_cp = apr_pstrdup(r->pool, v);
		if(0 == apr_strnatcasecmp(k, "algo"))
			resource->info->forced_cp_algo = apr_pstrdup(r->pool, v);
		if(0 == apr_strnatcasecmp(k, "bs"))
			resource->info->forced_cp_bs = apr_pstrdup(r->pool, v);
		
	}

end:
	if(!resource->info->forced_cp)
		resource->info->forced_cp = apr_pstrdup(r->pool, "false");
}

void
request_fill_headers(request_rec *r, struct content_textinfo_s *c0,
		struct chunk_textinfo_s *c1)
{
	__set_header(r, "container-id",  c0->container_id);

	__set_header(r, "content-id",           c0->content_id);
	__set_header(r, "content-path",         c0->path);
	__set_header(r, "content-size",         c0->size);
	__set_header(r, "content-version",      c0->version);
	__set_header(r, "content-chunksnb",     c0->chunk_nb);
	__set_header(r, "content-stgpol",       c0->storage_policy);
	__set_header(r, "content-version",     	c0->version);

	__set_header(r, "chunk-id",          c1->id);
	__set_header(r, "chunk-size",        c1->size);
	__set_header(r, "chunk-hash",        c1->hash);
	__set_header(r, "chunk-pos",         c1->position);
}

/*************************************************************************/

dav_error *
rawx_repo_check_request(request_rec *req, const char *root_dir, const char * label,
			int use_checked_in, dav_resource_private *ctx, dav_resource **result_resource)
{
	/* Ensure the chunkid in the URL has the approriated format and
	 * increment the request counters */
	int i;
	const char *src;
	dav_rawx_server_conf *conf = request_get_server_config(req);

	if (g_str_has_prefix(req->uri, "/rawx/chunk/set")) {
		ctx->update_only = TRUE;
	} else {
		ctx->update_only = FALSE;
	}

	src = strrchr(req->uri, '/');
	src = src ? src + 1 : req->uri;

	if (0 == apr_strnatcasecmp(src, "info")) {
		return dav_rawx_info_get_resource(req, root_dir, label, use_checked_in, result_resource);
	}

	if (0 == apr_strnatcasecmp(src, "stat")) {
		return dav_rawx_stat_get_resource(req, root_dir, label, use_checked_in, result_resource);
	}

	if (0 == apr_strnatcasecmp(src, "update")) {
		return dav_rawx_chunk_update_get_resource(req, root_dir, label, use_checked_in, result_resource);
	}

	if (g_str_has_prefix(src, "rawx/")) {
		server_inc_request_stat(conf, RAWX_STATNAME_REQ_RAW, request_get_duration(req));
		return server_create_and_stat_error(conf, req->pool,
				HTTP_BAD_REQUEST, 0, "Raw request not yet implemented");
	}

	for (i=0; *src ; src++, i++) {
		gchar c = g_ascii_toupper(*src);
		if (!g_ascii_isdigit(c) && (c < 'A' || c > 'F') && i < 64) {
			/* Only compare first 64 characters */
			return server_create_and_stat_error(conf, req->pool,
					HTTP_BAD_REQUEST, 0, "Invalid CHUNK id character");
		} else if (i < 64) {
			ctx->hex_chunkid[i] = c; // Upper case
		} else if (i >= 64 && i < (int)(63 + sizeof(ctx->file_extension))) {
			/* Consider extra characters are file extension */
			ctx->file_extension[i-64] = *src; // Original case
		}
	}
	if (i != 64 && req->method_number != M_MOVE) {
		return server_create_and_stat_error(conf, req->pool,
				HTTP_BAD_REQUEST, 0, apr_psprintf(req->pool, "Invalid CHUNK id length: %d", i));
	} else if (ctx->file_extension[0] != 0 &&
			apr_strnatcasecmp(ctx->file_extension, ".corrupted")) {
		return server_create_and_stat_error(conf, req->pool, HTTP_BAD_REQUEST,
				0, apr_psprintf(req->pool, "Invalid extension: %s",
				ctx->file_extension));
	}

	return NULL;
}

dav_error *
rawx_repo_configure_hash_dir(request_rec *req, dav_resource_private *ctx)
{
	int i_width, i_depth, i_src, i_dst;
	int dst_maxlen;
	const char *src;
	char *dst;
	dav_rawx_server_conf *conf;

	conf = request_get_server_config(req);

	src = &(ctx->hex_chunkid[0]);
	i_src = 0;

	dst = &(ctx->dirname[0]);
	dst_maxlen = sizeof(ctx->dirname);
	g_strlcpy(dst, conf->docroot, dst_maxlen-1);
	i_dst = strlen(dst);
	if (dst[i_dst-1] != '/')
		dst[i_dst++] = '/';

	/* check there remains enough space in the buffer */
	register int remaining, needed;
	remaining = dst_maxlen - i_dst;
	needed = 1 + (sizeof(ctx->hex_chunkid) + (conf->hash_width + 1) * conf->hash_depth);
	if (remaining < needed)
		return server_create_and_stat_error(request_get_server_config(req), req->pool,
				HTTP_INTERNAL_SERVER_ERROR, 0, "DocRoot too long or buffer too small");

	for (i_depth=0; i_depth < conf->hash_depth ;i_depth++) {
		for (i_width=0; i_width < conf->hash_width ;i_width++)
			dst[i_dst++] = src[i_src++];
		dst[i_dst++] = '/';
	}

	return NULL;
}

dav_error *
rawx_repo_write_last_data_crumble(dav_stream *stream)
{
	dav_error *e = NULL;
	gulong checksum = 0;
	checksum = stream->compress_checksum;

	/* If buffer contain data, compress it if needed and write it to distant file */
	if( 0 < stream->bufsize ) {	
		if(!stream->compression) {
			e = _write_data_crumble_UNCOMP(stream);
		} else {
			e = _write_data_crumble_COMP(stream, &checksum);
		}
	}
	/* write eof & checksum */
	if( !e && stream->compression ) {
		if( 0 != stream->comp_ctx.eof_writer(stream->f, checksum, &(stream->compressed_size))) {
			/* ### use something besides 500? */
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"An error occurred while writing end of file ");
		}
	}
	return e;
}

dav_error *
rawx_repo_rollback_upload(dav_stream *stream)
{
	fclose(stream->f);
	if (remove(stream->pathname) != 0) {
		/* ### use a better description? */
		return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"There was a problem removing (rolling "
				"back) the resource "
				"when it was being closed.");
	}

	if (remove(stream->final_pathname) != 0) {
		/* ### use a better description? */
		return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				"There was a problem removing (rolling "
				"back) the resource "
				"when it was being closed.");
	}

	return NULL;
}

dav_error *
rawx_repo_commit_upload(dav_stream *stream)
{
	dav_error *e = NULL;

	e = _set_chunk_extended_attributes(stream);
	if( NULL != e) {
		DAV_DEBUG_REQ(stream->r->info->request, 0, "Failed to set chunk extended attributes : %s", e->desc);
		return e;
	}

	e = _finalize_chunk_creation(stream);

	if( NULL != e ) {
		DAV_DEBUG_REQ(stream->r->info->request, 0, "Failed to finalize chunk file creation : %s", e->desc);
		return e;
	}

	request_fill_headers(stream->r->info->request,
			&(stream->r->info->content), &(stream->r->info->chunk));

	send_chunk_event("rawx.chunk.new", stream->r);

	return NULL;
}

dav_error *
rawx_repo_ensure_directory(const dav_resource *resource)
{
	dav_resource_private *ctx = resource->info;
	apr_status_t status;
	/* perform a mkdir of the directory */
	status = apr_dir_make_recursive(ctx->dirname,
		APR_FPROT_UREAD|APR_FPROT_UWRITE|APR_FPROT_UEXECUTE
		|APR_FPROT_GREAD|APR_FPROT_GEXECUTE
		|APR_FPROT_WREAD|APR_FPROT_WEXECUTE,
		resource->info->pool);
	if (status != APR_SUCCESS) {
		return server_create_and_stat_error(resource_get_server_config(resource), resource->info->pool,
			MAP_IO2HTTP(status), 0,
				apr_pstrcat(resource->info->pool, "mkdir(", ctx->dirname, ") failure : ", strerror(errno), NULL));
	}
	
	DAV_DEBUG_REQ(resource->info->request, status, "mkdir(%s) success", ctx->dirname);
	return NULL;
}

dav_error *
rawx_repo_stream_create(const dav_resource *resource, dav_stream **result)
{
	/* build the stream */
	apr_pool_t *p = resource->info->pool;
	dav_resource_private *ctx = resource->info;
	dav_rawx_server_conf *conf = resource_get_server_config(resource);
	apr_status_t rv = 0;
	char * metadata_compress = NULL;
	struct storage_policy_s *sp = NULL;
	const struct data_treatments_s *dt = NULL;

	dav_stream *ds = NULL;

	ds = apr_pcalloc(p, sizeof(*ds));

	ds->fsync_on_close = conf->fsync_on_close;
	ds->p = p;
	ds->r = resource;
	ds->final_pathname = apr_pstrcat(p, ctx->dirname, "/", ctx->hex_chunkid, NULL);
	ds->pathname = apr_pstrcat(p, ctx->dirname, "/", ctx->hex_chunkid, ".pending", NULL);

	/* Create busy chunk file */
	ds->f = fopen(ds->pathname, "w");

	if (!ds->f) {
		DAV_DEBUG_REQ(resource->info->request, 0, "open(%s) failed : %s", ds->pathname, strerror(errno));
		return server_create_and_stat_error(resource_get_server_config(resource), p,
			MAP_IO2HTTP(rv), 0, "An error occurred while opening a resource.");
	}
	else if (conf->FILE_buffer_size > 0) {
		int s = 131072;
		char *buf;
		if (conf->FILE_buffer_size < 131072 && conf->FILE_buffer_size > 8192)
			s = conf->FILE_buffer_size;
		buf = apr_pcalloc(p, s);
		if (0 != setvbuf(ds->f, buf, _IOFBF, (ssize_t)s)) {
			DAV_DEBUG_REQ(resource->info->request, 0,
					"setvbuf failed : (errno=%d) %s",
					errno, strerror(errno));
		}
	}

	/* TODO: try to create a storage_policy struct from request header */
	/* if not possible, get it from rawx_conf (default namespace conf) */
	DAV_DEBUG_REQ(resource->info->request, 0 , "stg_pol init from local sp");
	if (NULL != (sp = storage_policy_dup(conf->rawx_conf->sp)))
		apr_pool_cleanup_register(p, sp, apr_storage_policy_clean,
				apr_pool_cleanup_null);

	dt = storage_policy_get_data_treatments(sp);

	gint match = -1;

	if(ctx->forced_cp)
		match = g_ascii_strncasecmp(ctx->forced_cp, "true", 4);

	if((!dt || COMPRESSION != data_treatments_get_type(dt)) && (match != 0)){
		DAV_DEBUG_REQ(resource->info->request, 0 , "Compression Mode OFF");
		ds->blocksize = g_ascii_strtoll(DEFAULT_BLOCK_SIZE, NULL, 10); /* conf->rawx_conf->blocksize; */
		ds->buffer = apr_pcalloc(p, ds->blocksize);
		ds->bufsize = 0;	
	} else {	
		DAV_DEBUG_REQ(resource->info->request, 0 , "Compression Mode ON");
		ds->compression = TRUE;
		if(NULL != dt && COMPRESSION == data_treatments_get_type(dt)) {
			/* compression configured "normally" */
			const char *bs = NULL;
			const char *algo = NULL;
			bs = data_treatments_get_param(dt, DT_KEY_BLOCKSIZE);
			if(!bs)
				bs = DEFAULT_BLOCK_SIZE;
			algo = data_treatments_get_param(dt, DT_KEY_ALGO);
			if(!algo)
				algo = DEFAULT_COMPRESSION_ALGO;
			ds->blocksize = g_ascii_strtoll(bs, NULL, 10);

			metadata_compress = apr_pstrcat(p, NS_COMPRESSION_OPTION, "=", NS_COMPRESSION_ON, ";", 
					NS_COMPRESS_ALGO_OPTION,"=", algo, ";", 
					NS_COMPRESS_BLOCKSIZE_OPTION, "=", bs, NULL);  

			init_compression_ctx(&(ds->comp_ctx), algo); 
		} else {
			/* compression forced by request header */
			if(!ctx->forced_cp_algo || !ctx->forced_cp_bs){
				return server_create_and_stat_error(resource_get_server_config(resource), p,
						HTTP_BAD_REQUEST, 0,
						apr_pstrcat(p, "Failed to get compression info from incoming request", NULL));
			}	
			ds->blocksize = strtol(ctx->forced_cp_bs, NULL, 10);

			metadata_compress = apr_pstrcat(p, NS_COMPRESSION_OPTION, "=", NS_COMPRESSION_ON, ";", 
					NS_COMPRESS_ALGO_OPTION,"=", ctx->forced_cp_algo, ";", 
					NS_COMPRESS_BLOCKSIZE_OPTION, "=", ctx->forced_cp_bs, NULL);	

			init_compression_ctx(&(ds->comp_ctx), ctx->forced_cp_algo); 
		}

		ds->buffer = apr_pcalloc(p, ds->blocksize);
		ds->bufsize = 0;	
	
		gulong checksum = 0;

		if(!(ds->comp_ctx.checksum_initiator)(&checksum)){
			WARN("Failed to init compression checksum");
		}

		ds->metadata_compress = apr_pstrndup(p, metadata_compress, strlen(metadata_compress));

		/* writting compression header in busy file */
		guint32 bsize32 = ds->blocksize;
		if(0 != ds->comp_ctx.header_writer(ds->f, bsize32, &checksum, &(ds->compressed_size))){
			return server_create_and_stat_error(resource_get_server_config(resource), p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				apr_pstrcat(p, "Failed to write compression headers", NULL));
		}
		ds->compress_checksum = checksum;
	}

	ds->md5 = g_checksum_new (G_CHECKSUM_MD5);

	*result = ds;

	return NULL;
}
