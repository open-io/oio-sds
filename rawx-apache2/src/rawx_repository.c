#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#ifdef APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include <unistd.h>
#include <sys/stat.h>

#include <openssl/md5.h>

#include <apr.h>
#include <apr_file_io.h>
#include <apr_strings.h>
#include <apr_buckets.h>

#include <httpd.h>
#include <http_log.h>
#include <http_config.h>
#include <http_protocol.h>      /* for ap_set_* (in dav_rawx_set_headers) */
#include <http_request.h>       /* for ap_update_mtime() */
#include <mod_dav.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include <glib.h>

#include "mod_dav_rawx.h"
#include "rawx_bucket.h"
#include "rawx_repo_core.h"
#include "rawx_internals.h"
#include "rawx_config.h"

struct apr_bucket_type_t chunk_bucket_type = {
	"CHUNK-input",
	5,
	APR_BUCKET_DATA,
	chunk_bucket_destroy,
	chunk_bucket_read,
	apr_bucket_setaside_noop,
	chunk_bucket_split,
	chunk_bucket_copy
};

/* pull this in from the other source file */
/*extern const dav_hooks_locks dav_hooks_locks_fs; */

/* HERE */
/* forward-declare the hook structures */
static const dav_hooks_repository dav_hooks_repository_rawx;

static const dav_hooks_liveprop dav_hooks_liveprop_rawx;

/*
 ** The namespace URIs that we use. This list and the enumeration must
 ** stay in sync.
 */
static const char * const dav_rawx_namespace_uris[] =
{
	"DAV:",
	"http://apache.org/dav/props/",
	NULL        /* sentinel */
};

enum {
	DAV_FS_URI_DAV,            /* the DAV: namespace URI */
	DAV_FS_URI_MYPROPS         /* the namespace URI for our custom props */
};


static const dav_liveprop_spec dav_rawx_props[] =
{
	/* standard DAV properties */
	{
		DAV_FS_URI_DAV,
		"creationdate",
		DAV_PROPID_creationdate,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getcontentlength",
		DAV_PROPID_getcontentlength,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getetag",
		DAV_PROPID_getetag,
		0
	},
	{
		DAV_FS_URI_DAV,
		"getlastmodified",
		DAV_PROPID_getlastmodified,
		0
	},

	/* our custom properties */
	{
		DAV_FS_URI_MYPROPS,
		"executable",
		DAV_PROPID_FS_executable,
		0       /* handled special in dav_rawx_is_writable */
	},

	{ 0, 0, 0, 0 }        /* sentinel */
};

static const dav_liveprop_group dav_rawx_liveprop_group =
{
	dav_rawx_props,
	dav_rawx_namespace_uris,
	&dav_hooks_liveprop_rawx
};

/* --------------------------------------------------------------------
 **
 ** REPOSITORY HOOK FUNCTIONS
 */

static dav_error *
dav_rawx_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	dav_resource_private ctx;
	dav_resource *resource;
	dav_rawx_server_conf *conf;
	dav_error *e = NULL;

	*result_resource = NULL;

	(void) use_checked_in;/* No way, we do not support versioning */
	conf = request_get_server_config(r);
	

	/* Check if client allowed to work with us */
	if(conf->enabled_acl) {
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
		if(!authorized_personal_only(r->connection->client_ip, conf->rawx_conf->acl))
#else
		if(!authorized_personal_only(r->connection->remote_ip, conf->rawx_conf->acl))
#endif
		{
			return server_create_and_stat_error(conf, r->pool, HTTP_UNAUTHORIZED, 0, "Permission Denied (APO)");
		}
	}

	/* Create private resource context descriptor */
	memset(&ctx, 0x00, sizeof(ctx));
	ctx.pool = r->pool;
	ctx.request = r;

	e = rawx_repo_check_request(r, root_dir, label, use_checked_in, &ctx, result_resource);
	/* Return in case we have an error or if result_resource != null because it was an info request */
	if(NULL != e || NULL != *result_resource) {
		return e;
	}

	DAV_DEBUG_REQ(r, 0, "The chunk ID seems OK");

	/* Build the hashed path */
	if (conf->hash_width <= 0 || conf->hash_depth <= 0) {
		apr_snprintf(ctx.dirname, sizeof(ctx.dirname),
			"%.*s", (int)sizeof(conf->docroot), conf->docroot);
	} else {
		e = rawx_repo_configure_hash_dir(r, &ctx);
		if( NULL != e) {
			return e;
		}
	}
	DAV_DEBUG_REQ(r, 0, "Hashed directory : %.*s", (int)sizeof(ctx.dirname), ctx.dirname);

	/* All the checks on the URL have been passed, now build a resource */

	resource = apr_pcalloc(r->pool, sizeof(*resource));
	resource->type = DAV_RESOURCE_TYPE_REGULAR;
	resource->info = apr_pcalloc(r->pool, sizeof(ctx));;
	memcpy(resource->info, &ctx, sizeof(ctx));
	resource->hooks = &dav_hooks_repository_rawx;
	resource->pool = r->pool;
	bzero(&(resource->info->comp_ctx), sizeof(struct compression_ctx_s));

	resource->info->fullpath = apr_pstrcat(resource->pool,
		resource->info->dirname, "/", resource->info->hex_chunkid,
		NULL);
	
	/* init compression context structure if we are in get method (for decompression) */
	
	if(r->method_number == M_GET && !ctx.update_only) {
		resource_init_decompression(resource, conf);
	}

	/* Check the chunk's existence */
	resource_stat_chunk(resource, r->method_number == M_GET || r->method_number == M_OPTIONS);

	if (r->method_number == M_PUT || r->method_number == M_POST || (r->method_number == M_GET && ctx.update_only)) {
		request_load_chunk_info(r, resource);
	}

	if (r->method_number == M_POST || r->method_number == M_PUT) {
		if(resource->exists)
			return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_CONFLICT, 0, "Resource busy or already exists");
		request_parse_query(r, resource);
	}
	
	*result_resource = resource;
	return NULL;
}

static dav_error *
dav_rawx_get_parent_resource(const dav_resource *resource, dav_resource **result_parent)
{
	apr_pool_t *pool;
	dav_resource *parent;

	(void) resource;
	(void) result_parent;
	pool = resource->pool;

	DAV_XDEBUG_RES(resource, 0, "%s(%s)", __FUNCTION__, resource_get_pathname(resource));
	
	/* Build a fake root */
	parent = apr_pcalloc(resource->pool, sizeof(*resource));
	parent->exists = 1;
	parent->collection = 1;
	parent->uri = "/";
	parent->type = DAV_RESOURCE_TYPE_WORKING;
	parent->info = NULL;
	parent->hooks = &dav_hooks_repository_rawx;
	parent->pool = pool;

	*result_parent = parent;
	return NULL;
}

static int
dav_rawx_is_same_resource(const dav_resource *res1, const dav_resource *res2)
{
	dav_resource_private *ctx1 = res1->info;
	dav_resource_private *ctx2 = res2->info;

	DAV_XDEBUG_RES(res1, 0, "%s(%s,%s)", __FUNCTION__,
		resource_get_pathname(res1), resource_get_pathname(res2));

	return (res1->type == res2->type)
		&& (0 == apr_strnatcasecmp(ctx1->hex_chunkid, ctx2->hex_chunkid))
		&& (0 == apr_strnatcasecmp(ctx1->dirname, ctx2->dirname));
}

static int
dav_rawx_is_parent_resource(const dav_resource *res1, const dav_resource *res2)
{
	(void) res1;
	(void) res2;

	DAV_XDEBUG_RES(res1, 0, "%s(%s,%s)", __FUNCTION__,
		resource_get_pathname(res1), resource_get_pathname(res2));

	return 0;
}

static dav_error *
dav_rawx_open_stream(const dav_resource *resource, dav_stream_mode mode, dav_stream **stream)
{
	/* FIRST STEP OF PUT REQUEST */
	dav_stream *ds = NULL;
	dav_error *e = NULL;

	(void) mode;
	
	DAV_DEBUG_REQ(resource->info->request, 0, "%s(%s/%s)", __FUNCTION__, resource->info->dirname, resource->info->hex_chunkid);

	e = rawx_repo_ensure_directory(resource);
	if( NULL != e ) {
		DAV_DEBUG_REQ(resource->info->request, 0, "Chunk directory creation failure");
		return e;
	}
	
	e = rawx_repo_stream_create(resource, &ds);
	if( NULL != e ) {
		DAV_DEBUG_REQ(resource->info->request, 0, "Dav stream initialization failure");
		return e;
	}

	*stream = ds;

	DAV_DEBUG_REQ(resource->info->request, 0, "About to write in [%s]", ds->pathname);

	return NULL;
}

static dav_error *
dav_rawx_close_stream(dav_stream *stream, int commit)
{
	/* LAST STEP OF PUT REQUEST */

	dav_error *e = NULL;

	DAV_DEBUG_REQ(stream->r->info->request, 0, "Closing (%s) the stream to [%s]",
		(commit ? "commit" : "rollback"), stream->pathname);
	
	if (!commit) {
		e = rawx_repo_rollback_upload(stream);
	} else {
		e = rawx_repo_write_last_data_crumble(stream);
		if( NULL != e ) {
			DAV_DEBUG_REQ(stream->r->info->request, 0, "Cannot commit, an error occured while writing end of data");
			/* Must we did it ? */
			dav_error *e_tmp = NULL;
			e_tmp = rawx_repo_rollback_upload(stream);
			if( NULL != e_tmp) {
				DAV_ERROR_REQ(stream->r->info->request, 0, "Error while rolling back upload : %s", e_tmp->desc);
			}
		} else {
			e = rawx_repo_commit_upload(stream);
		}
	}

	/* stats update */
	server_inc_request_stat(resource_get_server_config(stream->r), RAWX_STATNAME_REQ_CHUNKPUT, request_get_duration(stream->r->info->request));
	return e;
}

static dav_error *
dav_rawx_write_stream(dav_stream *stream, const void *buf, apr_size_t bufsize)
{
	gsize nb_write;
	
	DAV_XDEBUG_POOL(stream->p, 0, "%s(%s)", __FUNCTION__, stream->pathname);

	guint written = 0;
	guint tmp = 0;
	GByteArray* gba = NULL;

	gulong checksum = 0;
	checksum = stream->compress_checksum;

	while(written < bufsize){
		memcpy(stream->buffer + stream->bufsize, buf + written, MIN(bufsize - written, stream->blocksize - stream->bufsize));
		tmp = MIN(bufsize - written, stream->blocksize - stream->bufsize);
		written += tmp;
		stream->bufsize += tmp;

		/* If buffer full, compress if needed and write to distant file */
		if(stream->blocksize - stream->bufsize <=0){	
			nb_write = 0;
			if(!stream->compression) {
				nb_write = fwrite(stream->buffer, stream->bufsize, 1, stream->f);
				if (nb_write != 1) {
					/* ### use something besides 500? */
					return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
							HTTP_INTERNAL_SERVER_ERROR, 0,
							"An error occurred while writing to a "
							"resource.");
				}
			} else {
				gba = g_byte_array_new();
				if(stream->comp_ctx.data_compressor(stream->buffer, stream->bufsize, gba, 
							&checksum)!=0) { 
					if (gba)
						g_byte_array_free(gba, TRUE);	
					/* ### use something besides 500? */
					return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
							HTTP_INTERNAL_SERVER_ERROR, 0,
							"An error occurred while compressing data.");
				}		
				nb_write = fwrite(gba->data, gba->len, 1, stream->f);
				if (nb_write != 1) {
					if (gba)
						g_byte_array_free(gba, TRUE);	
					/* ### use something besides 500? */
					return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
							HTTP_INTERNAL_SERVER_ERROR, 0,
							"An error occurred while writing to a "
							"resource.");
				}
				stream->compressed_size += gba->len;
				if (gba)
					g_byte_array_free(gba, TRUE);	
			}

			stream->buffer = apr_pcalloc(stream->p, stream->blocksize);
			stream->bufsize = 0;
		}
	}
	
	stream->compress_checksum = checksum;
	
	/* update the hash and the stats */
	MD5_Update(&(stream->md5_ctx), buf, bufsize);
	server_add_stat(resource_get_server_config(stream->r), RAWX_STATNAME_REP_BWRITTEN, bufsize, 0);
	return NULL;
}

static dav_error *
dav_rawx_seek_stream(dav_stream *stream, apr_off_t abs_pos)
{
	DAV_XDEBUG_POOL(stream->p, 0, "%s(%s)", __FUNCTION__, stream->pathname);
	TRACE("Seek stream: START please contact CDR if you get this TRACE");

	if (fseek(stream->f, abs_pos, SEEK_SET) != 0) {
		/* ### should check whether apr_file_seek set abs_pos was set to the
		 * correct position? */
		/* ### use something besides 500? */
		return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
			HTTP_INTERNAL_SERVER_ERROR, 0,
				"Could not seek to specified position in the "
				"resource.");
	}
	return NULL;
}

static dav_error *
dav_rawx_set_headers(request_rec *r, const dav_resource *resource)
{
	if (!resource->exists)
		return NULL;

	DAV_DEBUG_REQ(r, 0, "%s(%s)", __FUNCTION__, resource_get_pathname(resource));

	/* make sure the proper mtime is in the request record */
	ap_update_mtime(r, resource->info->finfo.mtime);
	ap_set_last_modified(r);
	ap_set_etag(r);

	/* we accept byte-ranges */
	apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "Accept-Ranges"), apr_pstrdup(r->pool, "bytes"));

	/* set up the Content-Length header */
	ap_set_content_length(r, resource->info->finfo.size);

	chunk_textinfo_fill_headers(r, &(resource->info->chunk));
	content_textinfo_fill_headers(r, &(resource->info->content));

	/* compute metadata_compress if compressed content */
	if(resource->info->compression) {
		char *buf = apr_pstrcat(r->pool, "compression=on;compression_algorithm=", resource->info->compress_algo, 
				";compression_blocksize=", apr_psprintf(r->pool, "%d", resource->info->cp_chunk.block_size), ";", NULL);
		apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "metadatacompress"), buf);
	}

	return NULL;
}

static dav_error *
dav_rawx_deliver(const dav_resource *resource, ap_filter_t *output)
{
	dav_rawx_server_conf *conf;
	apr_pool_t *pool;
	apr_bucket_brigade *bb = NULL;
	apr_status_t status;
	apr_bucket *bkt = NULL;
	dav_resource_private *ctx;
	dav_error *e = NULL;

	apr_finfo_t info;

	DAV_XDEBUG_RES(resource, 0, "%s(%s)", __FUNCTION__, resource_get_pathname(resource));

	pool = resource->pool;
	conf = resource_get_server_config(resource);

	/* Check resource type */
	if (DAV_RESOURCE_TYPE_REGULAR != resource->type) {
		e = server_create_and_stat_error(conf, pool, HTTP_CONFLICT, 0, "Cannot GET this type of resource.");
		goto end_deliver;
	}

	if (resource->collection) {
		e = server_create_and_stat_error(conf, pool, HTTP_CONFLICT, 0, "No GET on collections");
		goto end_deliver;
	}

	/* Check if it is not a busy file */
	char *pending_file = apr_pstrcat(pool, resource_get_pathname(resource), ".pending", NULL);
	status = apr_stat(&info, pending_file, APR_FINFO_ATIME, pool);
	if (APR_SUCCESS == status){
		e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN, 0, "File in pending mode.");
		goto end_deliver;
	}

	ctx = resource->info;

	if(ctx->update_only) {
		GError *error_local = NULL;
		/* UPDATE chunk attributes and go on */
		const char *path = resource_get_pathname(resource);
		FILE *f = NULL;
		f = fopen(path, "r");
		/* Try to open the file but forbids a creation */
		if(!set_rawx_full_info_in_attr(path, fileno(f), &error_local,&(ctx->content),
					&(ctx->chunk), NULL, NULL)) {
			fclose(f);
			e = server_create_and_stat_error(conf, pool,
					HTTP_FORBIDDEN, 0, apr_pstrdup(pool, gerror_get_message(error_local)));
			g_clear_error(&error_local);
			goto end_deliver;
		}
		fclose(f);
	} else {
		bb = apr_brigade_create(pool, output->c->bucket_alloc);


		if(!ctx->compression){
			apr_file_t *fd = NULL;

			/* Try to open the file but forbids a creation */
			status = apr_file_open(&fd, resource_get_pathname(resource), APR_READ|APR_BINARY, 0, pool);
			if (APR_SUCCESS != status) {
				e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN, 0, "File permissions deny server access.");
				goto end_deliver;
			}

			/* FIXME this does not handle large files. but this is test code anyway */
			bkt = apr_bucket_file_create(fd, 0,
					(apr_size_t)resource->info->finfo.size,
					pool, output->c->bucket_alloc);
		}
		else {
			DAV_DEBUG_RES(resource, 0, "Building a compressed resource bucket");
			gint i64;

			i64 = g_ascii_strtoll(ctx->cp_chunk.uncompressed_size, NULL, 10);

			/* creation of compression specific bucket */
			bkt = apr_pcalloc(pool, sizeof(struct apr_bucket));
			bkt->type = &chunk_bucket_type;
			bkt->length = i64; 
			bkt->start = 0;
			bkt->data = ctx; 
			bkt->free = chunk_bucket_free_noop;
			bkt->list = output->c->bucket_alloc;
		}

		APR_BRIGADE_INSERT_TAIL(bb, bkt);

		/* as soon as the chunk has been sent, end of stream!*/
		bkt = apr_bucket_eos_create(output->c->bucket_alloc);
		APR_BRIGADE_INSERT_TAIL(bb, bkt);

		if ((status = ap_pass_brigade(output, bb)) != APR_SUCCESS){
			e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN, 0, "Could not write contents to filter.");
			/* close file */
			if(ctx->cp_chunk.fd) {
				fclose(ctx->cp_chunk.fd);
			}
			goto end_deliver;
		}
		if (ctx->cp_chunk.buf){
			g_free(ctx->cp_chunk.buf);
			ctx->cp_chunk.buf = NULL;
		}
		if(ctx->cp_chunk.uncompressed_size){
			g_free(ctx->cp_chunk.uncompressed_size);
			ctx->cp_chunk.uncompressed_size = NULL;
		}

		/* close file */
		if(ctx->cp_chunk.fd) {
			fclose(ctx->cp_chunk.fd);
		}

		server_inc_stat(conf, RAWX_STATNAME_REP_2XX, 0);
		server_add_stat(conf, RAWX_STATNAME_REP_BWRITTEN, resource->info->finfo.size, 0);
	}

end_deliver:

	/* Now we pass here even if an error occured, for process request duration */
	server_inc_request_stat(resource_get_server_config(resource), RAWX_STATNAME_REQ_CHUNKGET,
			request_get_duration(resource->info->request));
	
	return e;
}

static dav_error *
dav_rawx_remove_resource(dav_resource *resource, dav_response **response)
{
	char buff[128];
	char attr_path[2048];
	apr_pool_t *pool;
	apr_status_t status;
	dav_error *e = NULL;

	DAV_XDEBUG_RES(resource, 0, "%s(%s)", __FUNCTION__, resource_get_pathname(resource));
	pool = resource->pool;
	*response = NULL;

	if (DAV_RESOURCE_TYPE_REGULAR != resource->type)  {
		e = server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_CONFLICT, 0, "Cannot DELETE this type of resource.");
		goto end_remove;
	}
	if (resource->collection) {
		e = server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_CONFLICT, 0, "No DELETE on collections");
		goto end_remove;
	}

	status = apr_file_remove(resource_get_pathname(resource), pool);
	if (APR_SUCCESS != status) {
		e = server_create_and_stat_error(resource_get_server_config(resource), pool,
			HTTP_FORBIDDEN, 0, apr_pstrcat(pool,
					"Failed to DELETE this chunk : ",
					apr_strerror(status, buff, sizeof(buff)),
					NULL));
		goto end_remove;
	}

	resource->exists = 0;
	resource->collection = 0;

	memset(attr_path, 0x00, sizeof(attr_path));
	apr_snprintf(attr_path, sizeof(attr_path), "%s.attr", resource_get_pathname(resource));
	status = apr_file_remove(attr_path, pool);
	if (status != APR_SUCCESS && !APR_STATUS_IS_ENOENT(status)) {
		e = server_create_and_stat_error(resource_get_server_config(resource), pool, 
			HTTP_INTERNAL_SERVER_ERROR, 0, apr_pstrcat(pool,
					"Failed to DELETE this chunk's  properties : ",
					apr_strerror(status, buff, sizeof(buff)),
					NULL));
		goto end_remove;
	}

	server_inc_stat(resource_get_server_config(resource), RAWX_STATNAME_REP_2XX, 0);

end_remove:

	/* Now we pass here even if an error occured, for process request duration */
	server_inc_request_stat(resource_get_server_config(resource), RAWX_STATNAME_REQ_CHUNKDEL,
				request_get_duration(resource->info->request));

	return e;
}

/* XXX JFS : etags are strings that uniquely identify a content.
 * A chunk is unique in a namespace, thus the e-tag must contain 
 * both fields. */
static const char *
dav_rawx_getetag(const dav_resource *resource)
{
	const char *etag;
	dav_rawx_server_conf *conf;
	dav_resource_private *ctx;
	
	ctx = resource->info;
	conf = resource_get_server_config(resource);

	if (!resource->exists) {
		DAV_DEBUG_RES(resource, 0, "%s(%s) : resource not found",
			__FUNCTION__, resource_get_pathname(resource));
		return NULL;
	}

	etag = apr_psprintf(resource->pool, "chunk-%s-%s", conf->ns_name,
		ctx->hex_chunkid);
	DAV_DEBUG_RES(resource, 0, "%s(%s) : ETag=[%s]", __FUNCTION__,
		resource_get_pathname(resource), etag);
	return etag;
}

/* XXX JFS : rawx walks are dummy*/
static dav_error *
dav_rawx_walk(const dav_walk_params *params, int depth, dav_response **response)
{
	dav_walk_resource wres;
	dav_error *err;

	(void) depth;
	err = NULL;
	memset(&wres, 0x00, sizeof(wres));
	wres.walk_ctx = params->walk_ctx;
	wres.pool = params->pool;
	wres.resource = params->root;

	DAV_XDEBUG_RES(params->root, 0, "sanity checks for %s(%s)", __FUNCTION__, resource_get_pathname(wres.resource));
	
	if (wres.resource->type != DAV_RESOURCE_TYPE_REGULAR)
		return server_create_and_stat_error(resource_get_server_config(params->root), params->root->pool,
			HTTP_CONFLICT, 0, "Only regular resources can be deleted with RAWX");
	if (wres.resource->collection)
		return server_create_and_stat_error(resource_get_server_config(params->root), params->root->pool,
			HTTP_CONFLICT, 0, "Collection resources canot be deleted with RAWX");
	if (!wres.resource->exists)
		return server_create_and_stat_error(resource_get_server_config(params->root), params->root->pool,
			HTTP_NOT_FOUND, 0, "Resource not found (no chunk)");
		
	DAV_DEBUG_RES(params->root, 0, "ready for %s(%s)", __FUNCTION__, resource_get_pathname(wres.resource));
    	err = (*params->func)(&wres, DAV_CALLTYPE_MEMBER);
	*response = wres.response;
	return err;
}

static const dav_hooks_repository dav_hooks_repository_rawx =
{
	1,
	dav_rawx_get_resource,
	dav_rawx_get_parent_resource,
	dav_rawx_is_same_resource,
	dav_rawx_is_parent_resource,
	dav_rawx_open_stream,
	dav_rawx_close_stream,
	dav_rawx_write_stream,
	dav_rawx_seek_stream,
	dav_rawx_set_headers,
	dav_rawx_deliver,
	NULL /* no collection creation */,
	NULL /* no copy of resources allowed */,
	NULL /* cannot move resources */,
	dav_rawx_remove_resource /*only for regular resources*/,
	dav_rawx_walk /* no walk across the chunks */,
	dav_rawx_getetag,
	NULL, /* no module context */
#if MODULE_MAGIC_COOKIE == 0x41503234UL /* "AP24" */
	NULL,
	NULL,
#endif
};

static dav_prop_insert
dav_rawx_insert_prop(const dav_resource *resource, int propid, dav_prop_insert what, apr_text_header *phdr)
{
	const char *value;
	const char *s;
	apr_pool_t *p = resource->info->pool;
	const dav_liveprop_spec *info;
	int global_ns;

	/* an HTTP-date can be 29 chars plus a null term */
	/* a 64-bit size can be 20 chars plus a null term */
	char buf[DAV_TIMEBUF_SIZE];

	/*
	 ** None of FS provider properties are defined if the resource does not
	 ** exist. Just bail for this case.
	 **
	 ** Even though we state that the FS properties are not defined, the
	 ** client cannot store dead values -- we deny that thru the is_writable
	 ** hook function.
	 */
	if (!resource->exists)
		return DAV_PROP_INSERT_NOTDEF;

	switch (propid) {
		case DAV_PROPID_creationdate:
			/*
			 ** Closest thing to a creation date. since we don't actually
			 ** perform the operations that would modify ctime (after we
			 ** create the file), then we should be pretty safe here.
			 */
			dav_format_time(DAV_STYLE_ISO8601,
					resource->info->finfo.ctime,
					buf);
			value = buf;
			break;

		case DAV_PROPID_getcontentlength:
			/* our property, but not defined on collection resources */
			if (resource->collection)
				return DAV_PROP_INSERT_NOTDEF;

			(void) sprintf(buf, "%" APR_OFF_T_FMT, resource->info->finfo.size);
			value = buf;
			break;

		case DAV_PROPID_getetag:
			value = dav_rawx_getetag(resource);
			break;

		case DAV_PROPID_getlastmodified:
			dav_format_time(DAV_STYLE_RFC822,
					resource->info->finfo.mtime,
					buf);
			value = buf;
			break;

		case DAV_PROPID_FS_executable:
			/* our property, but not defined on collection resources */
			if (resource->collection)
				return DAV_PROP_INSERT_NOTDEF;

			/* our property, but not defined on this platform */
			if (!(resource->info->finfo.valid & APR_FINFO_UPROT))
				return DAV_PROP_INSERT_NOTDEF;

			/* the files are "ours" so we only need to check owner exec privs */
			if (resource->info->finfo.protection & APR_UEXECUTE)
				value = "T";
			else
				value = "F";
			break;

		default:
			/* ### what the heck was this property? */
			return DAV_PROP_INSERT_NOTDEF;
	}

	/* assert: value != NULL */

	/* get the information and global NS index for the property */
	global_ns = dav_get_liveprop_info(propid, &dav_rawx_liveprop_group, &info);

	/* assert: info != NULL && info->name != NULL */

	/* DBG3("FS: inserting lp%d:%s  (local %d)", ns, scan->name, scan->ns); */

	if (what == DAV_PROP_INSERT_VALUE) {
		s = apr_psprintf(p, "<lp%d:%s>%s</lp%d:%s>" DEBUG_CR,
				global_ns, info->name, value, global_ns, info->name);
	}
	else if (what == DAV_PROP_INSERT_NAME) {
		s = apr_psprintf(p, "<lp%d:%s/>" DEBUG_CR, global_ns, info->name);
	}
	else {
		/* assert: what == DAV_PROP_INSERT_SUPPORTED */
		s = apr_psprintf(p,
				"<D:supported-live-property D:name=\"%s\" "
				"D:namespace=\"%s\"/>" DEBUG_CR,
				info->name, dav_rawx_namespace_uris[info->ns]);
	}
	apr_text_append(p, phdr, s);

	/* we inserted what was asked for */
	return what;
}

static int
dav_rawx_is_writable(const dav_resource *resource, int propid)
{
	const dav_liveprop_spec *info;

#ifdef DAV_FS_HAS_EXECUTABLE
	/* if we have the executable property, and this isn't a collection,
	   then the property is writable. */
	if (propid == DAV_PROPID_FS_executable && !resource->collection)
		return 1;
#endif

	(void) dav_get_liveprop_info(propid, &dav_rawx_liveprop_group, &info);
	return info->is_writable;
}

static dav_error *
dav_rawx_patch_validate(const dav_resource *resource, const apr_xml_elem *elem, int operation,
		void **context, int *defer_to_dead)
{
	const apr_text *cdata;
	const apr_text *f_cdata;
	char value;
	dav_elem_private *priv = elem->priv;

	if (priv->propid != DAV_PROPID_FS_executable) {
		*defer_to_dead = 1;
		return NULL;
	}

	if (operation == DAV_PROP_OP_DELETE) {
		return __dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
				"The 'executable' property cannot be removed.");
	}

	cdata = elem->first_cdata.first;

	/* ### hmm. this isn't actually looking at all the possible text items */
	f_cdata = elem->first_child == NULL
		? NULL
		: elem->first_child->following_cdata.first;

	/* DBG3("name=%s  cdata=%s  f_cdata=%s",elem->name,cdata ? cdata->text : "[null]",f_cdata ? f_cdata->text : "[null]"); */

	if (cdata == NULL) {
		if (f_cdata == NULL) {
			return __dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
					"The 'executable' property expects a single "
					"character, valued 'T' or 'F'. There was no "
					"value submitted.");
		}
		cdata = f_cdata;
	}
	else if (f_cdata != NULL)
		goto too_long;

	if (cdata->next != NULL || strlen(cdata->text) != 1)
		goto too_long;

	value = cdata->text[0];
	if (value != 'T' && value != 'F') {
		return __dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
				"The 'executable' property expects a single "
				"character, valued 'T' or 'F'. The value "
				"submitted is invalid.");
	}

	*context = (void *)((long)(value == 'T'));

	return NULL;

too_long:
	return __dav_new_error(resource->info->pool, HTTP_CONFLICT, 0,
			"The 'executable' property expects a single "
			"character, valued 'T' or 'F'. The value submitted "
			"has too many characters.");

}

static dav_error *
dav_rawx_patch_exec(const dav_resource *resource, const apr_xml_elem *elem, int operation,
		void *context, dav_liveprop_rollback **rollback_ctx)
{
	(void) resource;
	(void) elem;
	(void) operation;
	(void) context;
	(void) rollback_ctx;
	/* XXX JFS : TODO dump the xattr handle in the file */
	return __dav_new_error(resource->info->pool, HTTP_INTERNAL_SERVER_ERROR, 0, "PROPPATCH not yet implemented");
}

static void
dav_rawx_patch_commit(const dav_resource *resource, int operation, void *context, dav_liveprop_rollback *rollback_ctx)
{
	(void) resource;
	(void) operation;
	(void) context;
	(void) rollback_ctx;
	/* attributes already changed */
}

static dav_error *
dav_rawx_patch_rollback(const dav_resource *resource, int operation, void *context, dav_liveprop_rollback *rollback_ctx)
{
	(void) resource;
	(void) operation;
	(void) context;
	(void) rollback_ctx;
	/* Nothing to do */
	return NULL;
}


static const dav_hooks_liveprop dav_hooks_liveprop_rawx =
{
	dav_rawx_insert_prop,
	dav_rawx_is_writable,
	dav_rawx_namespace_uris,
	dav_rawx_patch_validate,
	dav_rawx_patch_exec,
	dav_rawx_patch_commit,
	dav_rawx_patch_rollback,
	NULL /* no module context */
};

static const dav_provider dav_rawx_provider =
{
	&dav_hooks_repository_rawx,
	&dav_hooks_db_dbm,
	NULL,               /* no lock management */
	NULL,               /* vsn */
	NULL,               /* binding */
	NULL,               /* search */
	NULL                /* ctx */
};

void
dav_rawx_gather_propsets(apr_array_header_t *uris)
{
#ifdef DAV_FS_HAS_EXECUTABLE
	*(const char **)apr_array_push(uris) =
		"<http://apache.org/dav/propset/fs/1>";
#endif
}

int
dav_rawx_find_liveprop(const dav_resource *resource, const char *ns_uri, const char *name, const dav_hooks_liveprop **hooks)
{
	/* don't try to find any liveprops if this isn't "our" resource */
	if (resource->hooks != &dav_hooks_repository_rawx)
		return 0;
	return dav_do_find_liveprop(ns_uri, name, &dav_rawx_liveprop_group, hooks);
}

void
dav_rawx_insert_all_liveprops(request_rec *r, const dav_resource *resource, dav_prop_insert what, apr_text_header *phdr)
{
	(void) r;

	/* don't insert any liveprops if this isn't "our" resource */
	if (resource->hooks != &dav_hooks_repository_rawx)
		return;

	if (!resource->exists) {
		/* a lock-null resource */
		/*
		 ** ### technically, we should insert empty properties. dunno offhand
		 ** ### what part of the spec said this, but it was essentially thus:
		 ** ### "the properties should be defined, but may have no value".
		 */
		return;
	}

	(void) dav_rawx_insert_prop(resource, DAV_PROPID_creationdate, what, phdr);
	(void) dav_rawx_insert_prop(resource, DAV_PROPID_getcontentlength, what, phdr);
	(void) dav_rawx_insert_prop(resource, DAV_PROPID_getlastmodified, what, phdr);
	(void) dav_rawx_insert_prop(resource, DAV_PROPID_getetag, what, phdr);

#ifdef DAV_FS_HAS_EXECUTABLE
	/* Only insert this property if it is defined for this platform. */
	(void) dav_rawx_insert_prop(resource, DAV_PROPID_FS_executable, what, phdr);
#endif

	/* ### we know the others aren't defined as liveprops */
}

void
dav_rawx_register(apr_pool_t *p)
{
	dav_register_liveprop_group(p, &dav_rawx_liveprop_group);
	dav_register_provider(p, "rawx", &dav_rawx_provider);
}
