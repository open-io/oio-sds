#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.repo"
#endif

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

#include <metautils/lib/metautils.h>
#include <rawx-lib/src/rawx.h>

#include "rawx_repo_core.h"
#include "rawx_internals.h"


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
__set_header(request_rec *r, apr_uint32_t h_scheme, const char *n, const char *v)
{
	if (r && n && v) {
		if (h_scheme & HEADER_SCHEME_V2) {
			DAV_DEBUG_REQ(r, 0, "scheme v2 setting header"); 
			apr_table_setn(r->headers_out, apr_pstrcat(r->pool, HEADER_PREFIX_GRID, n, NULL), apr_pstrdup(r->pool, v));
		} else {
			DAV_DEBUG_REQ(r, 0, "scheme v1 setting header"); 
			apr_table_setn(r->headers_out, apr_pstrdup(r->pool, n), apr_pstrdup(r->pool, v));
		}
	} else {
		DAV_DEBUG_REQ(r, 0, "pointers ko");  
	}
}

static dav_error *
_set_chunk_extended_attributes(dav_stream *stream)
{
	unsigned char md5_hash[16];
	char str_hash[33];
	GError *ge = NULL;
	dav_error *e = NULL;

	/* Save the new Chunk'hash in the XATTR, in upppercase! */
	bzero(md5_hash, sizeof(md5_hash));
	bzero(str_hash, sizeof(str_hash));
	MD5_Final(md5_hash, &(stream->md5_ctx));
	g_snprintf(str_hash, sizeof(str_hash),
			"%02X%02X%02X%02X"
			"%02X%02X%02X%02X"
			"%02X%02X%02X%02X"
			"%02X%02X%02X%02X"
			,md5_hash[0],  md5_hash[1],  md5_hash[2],  md5_hash[3]
			,md5_hash[4],  md5_hash[5],  md5_hash[6],  md5_hash[7]
			,md5_hash[8],  md5_hash[9],  md5_hash[10], md5_hash[11]
			,md5_hash[12], md5_hash[13], md5_hash[14], md5_hash[15]);
	stream->r->info->chunk.hash = apr_pstrdup(stream->p, str_hash);

	if(stream->compressed_size) {
		char size[32];
		bzero(size, sizeof(size));
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
		bzero(resource->info->compress_algo, sizeof(resource->info->compress_algo));
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

		bzero(&(ctx->content), sizeof(ctx->content));
		bzero(&(ctx->chunk), sizeof(ctx->chunk));
		if (xattr_too) {
			rc = get_rawx_info_in_attr(resource_get_pathname(resource), &err,
					&(ctx->content), &(ctx->chunk));
			if (!rc) {
				DAV_DEBUG_RES(resource, 0, "Chunk xattr loading error [%s] : %s",
						resource_get_pathname(resource),
						apr_pstrdup(resource->pool, gerror_get_message(err)));
			}
			else {
				REPLACE_FIELD(pool, content, path);
				REPLACE_FIELD(pool, content, size);
				REPLACE_FIELD(pool, content, chunk_nb);
				REPLACE_FIELD(pool, content, metadata);
				REPLACE_FIELD(pool, content, system_metadata);
				REPLACE_FIELD(pool, content, container_id);
				REPLACE_FIELD(pool, chunk, id);
				REPLACE_FIELD(pool, chunk, path);
				REPLACE_FIELD(pool, chunk, size);
				REPLACE_FIELD(pool, chunk, hash);
				REPLACE_FIELD(pool, chunk, position);
				REPLACE_FIELD(pool, chunk, metadata);
				REPLACE_FIELD(pool, chunk, container_id);
			}
			if (err)
				g_clear_error(&err);
		}
	}
}

static void
__load_one_header(request_rec *request, apr_uint32_t headers, const char *name, char **dst)
{
	const char *value;

	*dst = NULL;

	if (headers & HEADER_SCHEME_V2) {
		char new_name[strlen(name) + sizeof(HEADER_PREFIX_GRID)];
		g_snprintf(new_name, sizeof(new_name), HEADER_PREFIX_GRID"%s", name);
		if (NULL != (value = apr_table_get(request->headers_in, new_name))) {
			*dst = apr_pstrdup(request->pool, value);
			DAV_XDEBUG_REQ(request, 0, "Header found [%s]:[%s]", new_name, *dst);
		}
	}

	if (!(*dst) && (headers & HEADER_SCHEME_V1)) {
		if (NULL != (value = apr_table_get(request->headers_in, name))) {
			*dst = apr_pstrdup(request->pool, value);
			DAV_XDEBUG_REQ(request, 0, "Header found [%s]:[%s]", name, *dst);
		}
	}

}

#define LOAD_HEADER(Set,Where,Name) __load_one_header(request, conf->headers_scheme, Name, &(resource->info-> Set . Where))

void
request_load_chunk_info(request_rec *request, dav_resource *resource)
{
	dav_rawx_server_conf *conf;

	conf = request_get_server_config(request);

	/* These headers are used by the Integrity loop */
	LOAD_HEADER(content, path,            "content_path");
	LOAD_HEADER(content, size,            "content_size");
	LOAD_HEADER(content, chunk_nb,        "content_chunksnb");
	LOAD_HEADER(content, metadata,        "content_metadata");
	LOAD_HEADER(content, system_metadata, "content_metadata-sys");
	LOAD_HEADER(content, container_id,    "content_containerid");

	LOAD_HEADER(chunk, id,           "chunk_id");
	LOAD_HEADER(chunk, path,         "chunk_path");
	LOAD_HEADER(chunk, size,         "chunk_size");
	LOAD_HEADER(chunk, hash,         "chunk_hash");
	LOAD_HEADER(chunk, position,     "chunk_position");
	LOAD_HEADER(chunk, metadata,     "chunk_metadata");
	LOAD_HEADER(chunk, container_id, "chunk_containerid");

	if (conf->headers_scheme & HEADER_SCHEME_V1) {
		/* There are the headers used by the common client.
		 * This is an ugly clue of history and entropy */
		LOAD_HEADER(chunk, id,           "chunkid");
		LOAD_HEADER(chunk, path,         "contentpath");
		LOAD_HEADER(chunk, size,         "chunksize");
		LOAD_HEADER(chunk, hash,         "chunkhash");
		LOAD_HEADER(chunk, position,     "chunkpos");
		LOAD_HEADER(chunk, metadata,     "chunkmetadata");
		LOAD_HEADER(chunk, container_id, "containerid");

		LOAD_HEADER(content, path,            "contentpath");
		LOAD_HEADER(content, size,            "contentsize");
		LOAD_HEADER(content, chunk_nb,        "chunknb");
		LOAD_HEADER(content, metadata,        "contentmetadata");
		LOAD_HEADER(content, system_metadata, "contentmetadata-sys");
		LOAD_HEADER(content, container_id,    "containerid");
	}
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
content_textinfo_fill_headers(request_rec *r, struct content_textinfo_s *cti)
{
	DAV_DEBUG_REQ(r, 0, "Filling headers with content textinfo");
	dav_rawx_server_conf *conf;
	if (!cti)
		return;
	conf = request_get_server_config(r);
	__set_header(r, conf->headers_scheme, "content_path",         cti->path);
	__set_header(r, conf->headers_scheme, "content_size",         cti->size);
	__set_header(r, conf->headers_scheme, "content_chunksnb",     cti->chunk_nb);
	__set_header(r, conf->headers_scheme, "content_metadata",     cti->metadata);
	__set_header(r, conf->headers_scheme, "content_metadata-sys", cti->system_metadata);
	__set_header(r, conf->headers_scheme, "content_containerid",  cti->container_id);
}

void
chunk_textinfo_fill_headers(request_rec *r, struct chunk_textinfo_s *cti)
{
	dav_rawx_server_conf *conf;
	if (!cti)
		return;
	conf = request_get_server_config(r);
	__set_header(r, conf->headers_scheme, "chunk_id",          cti->id);
	__set_header(r, conf->headers_scheme, "chunk_path",        cti->path);
	__set_header(r, conf->headers_scheme, "chunk_size",        cti->size);
	__set_header(r, conf->headers_scheme, "chunk_hash",        cti->hash);
	__set_header(r, conf->headers_scheme, "chunk_position",    cti->position);
	__set_header(r, conf->headers_scheme, "chunk_metadata",    cti->metadata);
	__set_header(r, conf->headers_scheme, "chunk_containerid", cti->container_id);
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
	if(g_str_has_prefix(req->uri, "/rawx/chunk/set")) {
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
		server_inc_request_stat(request_get_server_config(req), RAWX_STATNAME_REQ_RAW, request_get_duration(req));
		return server_create_and_stat_error(request_get_server_config(req), req->pool,
				HTTP_BAD_REQUEST, 0, "Raw request not yet implemented");
	}

	for (i=0; *src ; src++, i++) {
		char c = *src;
		c = g_ascii_toupper(*src);
		if (!g_ascii_isdigit(c) && (c < 'A' || c > 'F'))
			return server_create_and_stat_error(request_get_server_config(req), req->pool,
					HTTP_BAD_REQUEST, 0, "Invalid CHUNK id character");
		ctx->hex_chunkid[i] = c;
	}
	if (i != 64) {
		return server_create_and_stat_error(request_get_server_config(req), req->pool,
				HTTP_BAD_REQUEST, 0, apr_psprintf(req->pool, "Invalid CHUNK id length: %d", i));
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

	/* Now populate the reply headers with the chunk's attributes */
	content_textinfo_fill_headers(stream->r->info->request, &(stream->r->info->content));
	chunk_textinfo_fill_headers(stream->r->info->request, &(stream->r->info->chunk));

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

static char *
__extract_stgpol(apr_pool_t *p, const char *str)
{
	char *tmp = NULL;
	char *end = NULL;
	if (str)
		tmp = g_strrstr(str, "storage-policy");
	if(!tmp)
		return NULL;
	tmp = strchr(tmp, '=');
	tmp = apr_pstrdup(p, tmp + 1);
	end = strchr(tmp, ';');
	if(NULL != end)
		memset(end, '\0', 1); 
	return tmp;
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
	char *str = __extract_stgpol(p, resource->info->content.system_metadata);
	if(NULL != str) {
		DAV_DEBUG_REQ(resource->info->request, 0 , "stg_pol init from req header %s", str);
		sp = storage_policy_init(conf->rawx_conf->ni, str);
	} else {
		DAV_DEBUG_REQ(resource->info->request, 0 , "stg_pol init from local sp");
		sp = storage_policy_dup(conf->rawx_conf->sp);
	}
	apr_pool_cleanup_register(p, sp, apr_storage_policy_clean, apr_pool_cleanup_null);

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
						400, 0,
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
				500, 0,
				apr_pstrcat(p, "Failed to write compression headers", NULL));
		}
		ds->compress_checksum = checksum;
	}

	MD5_Init(&(ds->md5_ctx));

	*result = ds;

	return NULL;
}
