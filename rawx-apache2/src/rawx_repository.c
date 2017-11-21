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

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#ifdef APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include <unistd.h>

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

/*
RAWX{{
GET /{CHUNKID}
~~~~~~~~~~~~~~

Download a chunk from the target RAWX service.
The chunk ID is given as a token of the URL.
No particular header is expected in the request.
The attributes of the chunk will be returned as headers of the reply.

.. list-table:: URL tokens
   :header-rows: 1
   :widths: 10 20

   * - Token
     - Description
   * - CHUNKID
     - a string of 64 hexadecimal characters


.. list-table:: Request Headers
   :header-rows: 1
   :widths: 10 20

   * - Header
     - Description
   * - Range
     - Both *chunked* and *inline* are managed


.. list-table:: Reply Headers
   :header-rows: 1
   :widths: 10 20

   * - Header
     - Description
   * - X-oio-chunk-meta-container-id
     - String of 64 hexadecimal characters
   * - X-oio-chunk-meta-content-path
     - A string
   * - X-oio-chunk-meta-content-id
     - String of hexadecimal characters, usually of 32 characters. The only constraint
       is that the number must be even, to be convertible to a binary form.
   * - X-oio-chunk-meta-content-version
     - A strictly positive integer, less than (2^63). That integer SHOULD match the
       number of bytes of the targeted chunk.
   * - X-oio-chunk-meta-content-storage-policy
     - A string, no check will be performed, at the RAWX level the string might even
       represent a non-existing storage policy
   * - X-oio-chunk-meta-content-chunk-method
     - A string. At the RAWX level no check will be performed and that string
       might even be an invalid chunk-method description.
   * - X-oio-chunk-meta-metachunk-size
     - A null or positive number
   * - X-oio-chunk-meta-metachunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-id
     - A string of 64 hexadecimal characters that must math the CHUNKID present in
       the URL
   * - X-oio-chunk-meta-chunk-size
     - A null or positive integer
   * - X-oio-chunk-meta-chunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-pos
     - Either a positive integer (including 0) or a compound of 2 positive integers
       gathered with a dot.
   * - X-oio-chunk-meta-oio-version
     - A string describing the versin of the headers.
   * - X-oio-chunk-meta-full-path
     - A string representing a complete OpenIO URL


Example
-------

.. code-block:: http

   GET /CE456217C7DBAC618A7F0EBFBCDB6C8F184ED8ADCBC6F0B6F493A51EE095D86A HTTP/1.1
   Host: 127.0.0.1:6009
   User-Agent: curl/7.55.1


.. code-block:: http

   HTTP/1.1 200 OK
   Date: Tue, 21 Nov 2017 16:19:57 GMT
   Server: Apache
   Last-Modified: Tue, 21 Nov 2017 16:18:29 GMT
   ETag: "55e808daf7710"
   Accept-Ranges: bytes
   Content-Length: 100
   X-oio-chunk-meta-container-id: 9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F
   X-oio-chunk-meta-content-path: magic
   X-oio-chunk-meta-content-id: 5835AF8D805E0500AAB7F6808F50900A
   X-oio-chunk-meta-content-version: 1511281109448048
   X-oio-chunk-meta-content-storage-policy: EC
   X-oio-chunk-meta-content-chunk-method: ec/algo=liberasurecode_rs_vand,k=6,m=3
   X-oio-chunk-meta-metachunk-size: 111
   X-oio-chunk-meta-metachunk-hash: 272913026300E7AE9B5E2D51F138E674
   X-oio-chunk-meta-chunk-id: CE456217C7DBAC618A7F0EBFBCDB6C8F184ED8ADCBC6F0B6F493A51EE095D86A
   X-oio-chunk-meta-chunk-size: 100
   X-oio-chunk-meta-chunk-hash: 527EC56D67EF8DA68E3FB93158552272
   X-oio-chunk-meta-chunk-pos: 0.3
   X-oio-chunk-meta-oio-version: 4.0
   X-oio-chunk-meta-full-path: ACCT/JFS/magic/1511281109448048

   ...


PUT /{CHUNKID}
~~~~~~~~~~~~~~

Upload a chunk on the target RAWX service.

.. list-table:: URL tokens
   :header-rows: 1
   :widths: 10 20

   * - Token
     - Description
   * - CHUNKID
     - a string of 64 hexadecimal characters


.. list-table:: HTTP Headers
   :header-rows: 1
   :widths: 10 20

   * - Header
     - Description
   * - Transfer-Encoding
     - Both *chunked* and *inline* are managed


.. list-table:: RAWX Headers
   :header-rows: 1
   :widths: 10 20

   * - Header
     - Description
   * - X-oio-chunk-meta-container-id
     - String of 64 hexadecimal characters
   * - X-oio-chunk-meta-content-path
     - A string
   * - X-oio-chunk-meta-content-id
     - String of hexadecimal characters, usually of 32 characters. The only constraint
       is that the number must be even, to be convertible to a binary form.
   * - X-oio-chunk-meta-content-version
     - A strictly positive integer, less than (2^63). That integer SHOULD match the
       number of bytes of the targeted chunk.
   * - X-oio-chunk-meta-content-storage-policy
     - A string, no check will be performed, at the RAWX level the string might even
       represent a non-existing storage policy
   * - X-oio-chunk-meta-content-chunk-method
     - A string. At the RAWX level no check will be performed and that string
       might even be an invalid chunk-method description.
   * - X-oio-chunk-meta-metachunk-size
     - A null or positive number
   * - X-oio-chunk-meta-metachunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-id
     - A string of 64 hexadecimal characters that must math the CHUNKID present in
       the URL
   * - X-oio-chunk-meta-chunk-size
     - A null or positive integer
   * - X-oio-chunk-meta-chunk-hash
     - A string of 32 hexadecimal characters
   * - X-oio-chunk-meta-chunk-pos
     - Either a positive integer (including 0) or a compound of 2 positive integers
       gathered with a dot.
   * - X-oio-chunk-meta-oio-version
     - A string describing the versin of the headers.
   * - X-oio-chunk-meta-full-path
     - A string representing a complete OpenIO URL


Example
-------

.. code-block:: http

   PUT /0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF HTTP/1.1
   Content-Length: 12345
   X-oio-chunk-meta-container-id: 9006CE70B59E5777D6BB410C57944812EB05FCDB5BA85D520A14B3051D1D094F
   X-oio-chunk-meta-content-path: magic
   X-oio-chunk-meta-content-id: 5835AF8D805E0500AAB7F6808F50900A
   X-oio-chunk-meta-content-version: 1511281109448048
   X-oio-chunk-meta-content-storage-policy: EC
   X-oio-chunk-meta-content-chunk-method: ec/algo=liberasurecode_rs_vand,k=6,m=3
   X-oio-chunk-meta-metachunk-size: 111
   X-oio-chunk-meta-metachunk-hash: 272913026300E7AE9B5E2D51F138E674
   X-oio-chunk-meta-chunk-id: CE456217C7DBAC618A7F0EBFBCDB6C8F184ED8ADCBC6F0B6F493A51EE095D86A
   X-oio-chunk-meta-chunk-size: 100
   X-oio-chunk-meta-chunk-hash: 527EC56D67EF8DA68E3FB93158552272
   X-oio-chunk-meta-chunk-pos: 0.3
   X-oio-chunk-meta-oio-version: 4.0
   X-oio-chunk-meta-full-path: ACCT/JFS/magic/1511281109448048

   -snip-


.. code-block:: http

   HTTP/1.1 200 OK
   Content-Length: 0



DELETE /{CHUNKID}
~~~~~~~~~~~~~~~~~

Delete a chunk stored on the target RAWX service.

.. list-table:: URL tokens
   :header-rows: 1
   :widths: 10 20

   * - Token
     - Description
   * - CHUNKID
     - a string of 64 hexadecimal characters


Example
-------

.. code-block:: http

   DELETE /0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF HTTP/1.1
   Content-Length: 0


.. code-block:: http

   HTTP/1.1 204 No content
   Content-Length: 0


}}RAWX
 */
static dav_error *
dav_rawx_get_resource(request_rec *r, const char *root_dir, const char *label,
	int use_checked_in, dav_resource **result_resource)
{
	(void) use_checked_in;
	*result_resource = NULL;

	dav_rawx_server_conf *conf = request_get_server_config(r);

	/* Create private resource context descriptor */
	dav_resource_private ctx = {0};
	ctx.pool = r->pool;
	ctx.request = r;

	dav_error *e = rawx_repo_check_request(r, root_dir, label, use_checked_in,
			&ctx, result_resource);
	/* Return in case we have an error or
	 * if result_resource != null because it was an info request */
	if (e || *result_resource) {
		return e;
	}

	/* Build the hashed path */
	if (conf->hash_width <= 0 || conf->hash_depth <= 0) {
		apr_snprintf(ctx.dirname, sizeof(ctx.dirname),
			"%.*s", (int)sizeof(conf->docroot), conf->docroot);
	} else {
		e = rawx_repo_configure_hash_dir(r, &ctx);
		if ( NULL != e) {
			return e;
		}
	}
	DAV_DEBUG_REQ(r, 0, "Hashed directory: %.*s", (int)sizeof(ctx.dirname), ctx.dirname);

	/* All the checks on the URL have passed, now build a resource */
	dav_resource *resource = apr_pcalloc(r->pool, sizeof(*resource));
	resource->type = DAV_RESOURCE_TYPE_REGULAR;
	resource->info = apr_pcalloc(r->pool, sizeof(ctx));;
	memcpy(resource->info, &ctx, sizeof(ctx));
	resource->hooks = &dav_hooks_repository_rawx;
	resource->pool = r->pool;
	memset(&(resource->info->comp_ctx), 0, sizeof(struct compression_ctx_s));

	resource->info->fullpath = apr_pstrcat(resource->pool,
		resource->info->dirname, resource->info->hex_chunkid,
		resource->info->file_extension,
		NULL);

	/* init compression context structure if we are in get method */
	if (r->method_number == M_GET && !ctx.update_only) {
		resource_init_decompression(resource, conf);
	}

	/* Check the chunk's existence */
	int flags = (r->method_number == M_GET ||
			r->method_number == M_OPTIONS ||
			r->method_number == M_DELETE)?
				 RESOURCE_STAT_CHUNK_READ_ATTRS : 0;
	if (r->method_number == M_PUT || r->method_number == M_POST)
		flags |= RESOURCE_STAT_CHUNK_PENDING;

	resource_stat_chunk(resource, flags);

	if (r->method_number == M_COPY) {
		request_load_chunk_info_from_headers(r, &(resource->info->chunk));
	}

	if (r->method_number == M_PUT || r->method_number == M_POST ||
			r->method_number == M_MOVE ||
			(r->method_number == M_GET && ctx.update_only)) {
		request_load_chunk_info_from_headers(r, &(resource->info->chunk));
		const char *missing = check_chunk_info(&resource->info->chunk);
		if (missing != NULL) {
			return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_BAD_REQUEST, 0, apr_pstrcat(r->pool, "missing or invalid header ", missing, NULL));
		}
	}

	if (r->method_number == M_POST || r->method_number == M_PUT) {
		if (resource->info->chunk.chunk_id) {
			if (0 != apr_strnatcasecmp(resource->info->chunk.chunk_id, resource->info->hex_chunkid))
				return server_create_and_stat_error(request_get_server_config(r), r->pool,
						HTTP_BAD_REQUEST, 0, "chunk-id mismatch");
		}
		if (resource->exists)
			return server_create_and_stat_error(request_get_server_config(r), r->pool,
				HTTP_CONFLICT, 0, "Resource busy or already exists");
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
		&& (0 == apr_strnatcasecmp(ctx1->dirname, ctx2->dirname))
		&& (0 == apr_strnatcasecmp(ctx1->file_extension, ctx2->file_extension));
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
	(void) mode;
	DAV_DEBUG_REQ(resource->info->request, 0, "%s(%s/%s)", __FUNCTION__, resource->info->dirname, resource->info->hex_chunkid);

	dav_stream *ds = NULL;
	dav_error *e = rawx_repo_stream_create(resource, &ds);
	if ( NULL != e ) {
		DAV_DEBUG_REQ(resource->info->request, 0, "Dav stream initialization failure");
		return e;
	}

	*stream = ds;

	DAV_DEBUG_REQ(resource->info->request, 0, "About to write in [%s]", ds->pathname);

	return NULL;
}

static void
_rollback_and_log(dav_stream *stream)
{
	dav_error *e = rawx_repo_rollback_upload(stream);
	if (!e)
		return;
	DAV_ERROR_REQ(stream->r->info->request, 0,
			"Error while rolling back upload: %s", e->desc);
}

static dav_error *
dav_rawx_close_stream(dav_stream *stream, int commit)
{
	/* LAST STEP OF PUT REQUEST */

	dav_error *e = NULL;

	DAV_DEBUG_REQ(stream->r->info->request, 0,
			"Closing (%s) the stream to [%s]",
			(commit ? "commit" : "rollback"), stream->pathname);

	if (!commit) {
		e = rawx_repo_rollback_upload(stream);
	} else {
		e = rawx_repo_write_last_data_crumble(stream);
		if (e) {
			DAV_DEBUG_REQ(stream->r->info->request, 0,
					"Cannot commit, an error occured while writing end of data");
			_rollback_and_log(stream);
		} else {
			e = rawx_repo_commit_upload(stream);
			if (e)
				_rollback_and_log(stream);
		}
	}

	/* stats update */
	if (stream->total_size > 0) {
		server_add_stat(resource_get_server_config(stream->r),
				RAWX_STATNAME_REP_BWRITTEN,
				stream->total_size, 0);
	}
	server_inc_request_stat(resource_get_server_config(stream->r),
			RAWX_STATNAME_REQ_CHUNKPUT,
			request_get_duration(stream->r->info->request));

	if (stream->md5) {
		g_checksum_free(stream->md5);
		stream->md5 = NULL;
	}
	return e;
}

static dav_error *
dav_rawx_write_stream(dav_stream *stream, const void *buf, apr_size_t bufsize)
{
	DAV_XDEBUG_POOL(stream->p, 0, "%s(%s)", __FUNCTION__, stream->pathname);

	apr_size_t copied = 0;
	gulong checksum = stream->compress_checksum;

	while (copied < bufsize) {
		apr_size_t to_copy = MIN(bufsize - copied,
				stream->buffer_size - stream->buffer_offset);
		memcpy(stream->buffer + stream->buffer_offset, buf + copied, to_copy);
		copied += to_copy;
		stream->buffer_offset += to_copy;

		/* If buffer full, compress if needed and write to distant file */
		if (stream->buffer_size - stream->buffer_offset <= 0){
			size_t written = 0;
			if (!stream->compression) {
				written = fwrite(stream->buffer, stream->buffer_offset, 1,
						stream->f);
				if (written != 1) {
					/* ### use something besides 500? */
					return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
							HTTP_INTERNAL_SERVER_ERROR, 0,
							"An error occurred while writing to a "
							"resource.");
				}
			} else {
				GByteArray *gba = g_byte_array_new();
				if (stream->comp_ctx.data_compressor(stream->buffer, stream->buffer_offset, gba,
							&checksum)!=0) {
					if (gba)
						g_byte_array_free(gba, TRUE);
					/* ### use something besides 500? */
					return server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
							HTTP_INTERNAL_SERVER_ERROR, 0,
							"An error occurred while compressing data.");
				}
				written = fwrite(gba->data, gba->len, 1, stream->f);
				if (written != 1) {
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

			memset(stream->buffer, 0, stream->buffer_size);
			stream->buffer_offset = 0;
		}
	}

	stream->compress_checksum = checksum;

	/* update the hash and the stats */
	if (stream->md5)
		g_checksum_update(stream->md5, buf, bufsize);

	/* update total_size */
	stream->total_size += bufsize;
	return NULL;
}

static dav_error *
dav_rawx_seek_stream(dav_stream *stream, apr_off_t abs_pos)
{
	DAV_XDEBUG_POOL(stream->p, 0, "%s(%s)", __FUNCTION__, stream->pathname);

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
	apr_table_setn(r->headers_out, apr_pstrdup(r->pool, "Accept-Ranges"),
			apr_pstrdup(r->pool, "bytes"));

	/* set up the Content-Length header */
	ap_set_content_length(r, resource->info->finfo.size);

	request_fill_headers(r, &(resource->info->chunk));

	/* compute metadata_compress if compressed content */
	if (resource->info->compression) {
		apr_table_setn(r->headers_out,
				apr_pstrdup(r->pool, "compression"),
				apr_pstrdup(r->pool, "on"));
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

	ctx = resource->info;

	if (ctx->update_only) {
		/* Check if it is not a busy file. We accept reads during
		 * compression but not attr updates. */
		char *pending_file = apr_pstrcat(pool,
				resource_get_pathname(resource), ".pending", NULL);
		status = apr_stat(&info, pending_file, APR_FINFO_ATIME, pool);
		if (status == APR_SUCCESS || status == APR_INCOMPLETE) {
			e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN,
					0, "File in pending mode.");
			goto end_deliver;
		}

		GError *error_local = NULL;
		/* UPDATE chunk attributes and go on */
		const char *path = resource_get_pathname(resource);
		FILE *f = NULL;
		f = fopen(path, "r");
		/* Try to open the file but forbids a creation */
		if (!set_rawx_info_to_fd(fileno(f), &error_local, &(ctx->chunk))) {
			fclose(f);
			e = server_create_and_stat_error(conf, pool,
					HTTP_FORBIDDEN, 0, apr_pstrdup(pool, gerror_get_message(error_local)));
			g_clear_error(&error_local);
			goto end_deliver;
		}
		fclose(f);
	} else {
		bb = apr_brigade_create(pool, output->c->bucket_alloc);

		if (!ctx->compression){
			apr_file_t *fd = NULL;

			/* Try to open the file but forbids a creation */
			status = apr_file_open(&fd, resource_get_pathname(resource),
					APR_FOPEN_READ|
					APR_FOPEN_BINARY|
					APR_FOPEN_BUFFERED|
					APR_FOPEN_SENDFILE_ENABLED,
					0, pool);
			if (status != APR_SUCCESS) {
				e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN,
						0, "File permissions deny server access.");
				goto end_deliver;
			}

			apr_brigade_insert_file(bb, fd, 0,
					(apr_size_t)resource->info->finfo.size, pool);
		}
		else {
			DAV_DEBUG_RES(resource, 0, "Building a compressed resource bucket");
			gint i64;

			i64 = g_ascii_strtoll(ctx->cp_chunk.uncompressed_size, NULL, 10);

			/* creation of compression specific bucket */
			apr_bucket *bkt = apr_pcalloc(pool, sizeof(struct apr_bucket));
			bkt->type = &chunk_bucket_type;
			bkt->length = i64;
			bkt->start = 0;
			bkt->data = ctx;
			bkt->free = chunk_bucket_free_noop;
			bkt->list = output->c->bucket_alloc;

			APR_BRIGADE_INSERT_TAIL(bb, bkt);
		}

		/* as soon as the chunk has been sent, end of stream!*/
		APR_BRIGADE_INSERT_TAIL(bb,
				apr_bucket_eos_create(output->c->bucket_alloc));

		if ((status = ap_pass_brigade(output, bb)) != APR_SUCCESS){
			e = server_create_and_stat_error(conf, pool, HTTP_FORBIDDEN, 0,
					"Failed to send data to the client (timed out?)");
			/* close file */
			if (ctx->cp_chunk.fd) {
				fclose(ctx->cp_chunk.fd);
			}
			goto end_deliver;
		}
		if (ctx->cp_chunk.buf){
			g_free(ctx->cp_chunk.buf);
			ctx->cp_chunk.buf = NULL;
		}
		if (ctx->cp_chunk.uncompressed_size){
			g_free(ctx->cp_chunk.uncompressed_size);
			ctx->cp_chunk.uncompressed_size = NULL;
		}

		/* close file */
		if (ctx->cp_chunk.fd) {
			fclose(ctx->cp_chunk.fd);
		}

		server_inc_stat(conf, RAWX_STATNAME_REP_2XX, 0);
		server_add_stat(conf, RAWX_STATNAME_REP_BWRITTEN, resource->info->finfo.size, 0);
	}

end_deliver:

	if (bb) {
		apr_brigade_destroy(bb);
		bb = NULL;
	}

	/* Now we pass here even if an error occured, for process request duration */
	server_inc_request_stat(resource_get_server_config(resource), RAWX_STATNAME_REQ_CHUNKGET,
			request_get_duration(resource->info->request));

	return e;
}

static dav_error *
dav_rawx_copy_resource(const dav_resource *src, dav_resource *dst, int depth,
		dav_response **response)
{
	(void) depth;
	char buff[128];
	apr_pool_t *pool;
	pool = dst->pool;
	apr_status_t status;
	dav_error *e = NULL;
	dav_rawx_server_conf * srv_conf = resource_get_server_config(src);

	*response = NULL;

	if (DAV_RESOURCE_TYPE_REGULAR != src->type) {
		e = server_create_and_stat_error(srv_conf, pool, HTTP_CONFLICT,
				0, "Cannot COPY this type of resource");
		goto end_copy;
	}
	if (src->collection) {
		e = server_create_and_stat_error(srv_conf, pool, HTTP_CONFLICT,
				0, "No COPY on collections");
		goto end_copy;
	}
	if (!apr_strnatcasecmp(src->info->hex_chunkid, dst->info->hex_chunkid)) {
		e = server_create_and_stat_error(srv_conf, pool, HTTP_FORBIDDEN, 0,
				"Source and destination should not have the same id");
		goto end_copy;
	}

	if (!src->info->chunk.oio_full_path) {
		e = server_create_and_stat_error(srv_conf, pool,
					HTTP_FORBIDDEN, 0,
					apr_pstrdup(pool, "Missing fullpath"));
		goto end_copy;
	}

	DAV_DEBUG_RES(src, 0, "Copying %s to %s", resource_get_pathname(src),
			resource_get_pathname(dst));
	status = apr_file_link(resource_get_pathname(src),
			resource_get_pathname(dst));

	if (status != APR_SUCCESS) {
		e = server_create_and_stat_error(srv_conf,
				pool, HTTP_INTERNAL_SERVER_ERROR, status,
				apr_pstrcat(pool, "Failed to COPY this chunk: ",
					apr_strerror(status, buff, sizeof(buff)), NULL));
		goto end_copy;
	}

	GError *local_error = NULL;
	if (!set_rawx_info_to_file(resource_get_pathname(dst), &local_error,
				&(src->info->chunk))) {
		e = server_create_and_stat_error(srv_conf, pool,
				HTTP_FORBIDDEN, 0,
				apr_pstrdup(pool, gerror_get_message(local_error)));
		goto end_copy;
	}

	server_inc_stat(srv_conf, RAWX_STATNAME_REP_2XX, 0);

end_copy:
	server_inc_request_stat(srv_conf, RAWX_STATNAME_REQ_OTHER,
			request_get_duration(src->info->request));

	return e;
}

static dav_error *
dav_rawx_move_resource(dav_resource *src_res, dav_resource *dst_res,
		dav_response **response)
{
	char buff[128];
	apr_pool_t *pool;
	pool = dst_res->pool;
	apr_status_t status;
	dav_error *e = NULL;
	dav_rawx_server_conf *srv_conf = resource_get_server_config(src_res);

	*response = NULL;

	if (DAV_RESOURCE_TYPE_REGULAR != src_res->type)  {
		e = server_create_and_stat_error(srv_conf, pool,
			HTTP_CONFLICT, 0, "Cannot MOVE this type of resource.");
		goto end_move;
	}
	if (src_res->collection) {
		e = server_create_and_stat_error(srv_conf, pool,
			HTTP_CONFLICT, 0, "No MOVE on collections");
		goto end_move;
	}
	if (apr_strnatcasecmp(src_res->info->hex_chunkid,
			dst_res->info->hex_chunkid)) {
		e = server_create_and_stat_error(srv_conf, pool,
				HTTP_FORBIDDEN, 0,
				"Source and destination chunk ids are not the same");
		goto end_move;
	}

	DAV_DEBUG_RES(src_res, 0, "Moving %s to %s",
			resource_get_pathname(src_res), resource_get_pathname(dst_res));
	status = apr_file_rename(resource_get_pathname(src_res),
			resource_get_pathname(dst_res), pool);

	if (status != APR_SUCCESS) {
		e = server_create_and_stat_error(srv_conf,
				pool, HTTP_INTERNAL_SERVER_ERROR, status,
				apr_pstrcat(pool, "Failed to MOVE this chunk: ",
					apr_strerror(status, buff, sizeof(buff)), NULL));
		goto end_move;
	}

	server_inc_stat(srv_conf, RAWX_STATNAME_REP_2XX, 0);

end_move:
	server_inc_request_stat(srv_conf, RAWX_STATNAME_REQ_OTHER,
			request_get_duration(src_res->info->request));

	return e;
}

static dav_error *
dav_rawx_remove_resource(dav_resource *resource, dav_response **response)
{
	char buff[128];
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

	send_chunk_event("storage.chunk.deleted", resource);

	resource->exists = 0;
	resource->collection = 0;

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

/* JFS : walks are not managed by this rawx */
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
	dav_rawx_copy_resource,
	dav_rawx_move_resource /* only for regular resources */,
	dav_rawx_remove_resource /* only for regular resources */,
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
	return __dav_new_error(resource->info->pool, HTTP_NOT_IMPLEMENTED,
			0, "PROPPATCH not yet implemented");
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
