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
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>

#include "rawx_repo_core.h"
#include "rawx_internals.h"
#include "rawx_event.h"

#define DEFAULT_BLOCK_SIZE 1048576
#define DEFAULT_COMPRESSION_ALGO "ZLIB"

/******************** INTERNALS METHODS **************************/

static void
__set_header(request_rec *r, const char *n, const char *v)
{
	if (!v) return;
	apr_table_setn(r->headers_out, apr_pstrcat(r->pool,
				RAWX_HEADER_PREFIX, n, NULL),
				apr_pstrdup(r->pool, v));
}

static dav_error *
_set_chunk_extended_attributes(dav_stream *stream, struct chunk_textinfo_s *cti)
{
	GError *ge = NULL;
	dav_error *e = NULL;

	if (!set_rawx_info_to_fd(fileno(stream->f), &ge, cti))
		e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
				HTTP_FORBIDDEN, 0, apr_pstrdup(stream->p, gerror_get_message(ge)));
	if (ge)
		g_clear_error (&ge);
	return e;
}

static dav_error *
_finalize_chunk_creation(dav_stream *stream)
{
	dav_error *e = NULL;
	int status = 0;

	/* ensure to flush the FILE * buffer in system fd */
	if (fflush(stream->f)) {
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
	if (fwrite(stream->buffer, stream->buffer_offset, 1, stream->f) != 1) {
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

	rc = stream->comp_ctx.data_compressor(stream->buffer,
			stream->buffer_offset, gba, checksum);
	if (0 == rc) {
		if (1 != fwrite(gba->data, gba->len, 1, stream->f)) {
			/* ### use something besides 500? */
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"An error occurred while writing to a "
					"resource.");
		} else {
			stream->compressed_size += gba->len;
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

	GHashTable *comp_opt =
			g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	if (!get_compression_info_in_attr(
			resource_get_pathname(resource), &e, comp_opt)) {
		if (comp_opt)
			g_hash_table_destroy(comp_opt);
		if (e)
			g_clear_error(&e);
		return server_create_and_stat_error(conf, resource->pool,
				HTTP_CONFLICT, 0, "Failed to get chunk compression from attr");
	}
	c = g_hash_table_lookup(comp_opt, NS_COMPRESSION_OPTION);
	if (c && !g_ascii_strcasecmp(c, NS_COMPRESSION_ON)) {
		resource->info->compression = TRUE;
	} else {
		resource->info->compression = FALSE;
	}

	if (resource->info->compression) {
		// init compression method according to algo choice
		char *algo = g_hash_table_lookup(comp_opt, NS_COMPRESS_ALGO_OPTION);
		memset(resource->info->compress_algo, 0,
				sizeof(resource->info->compress_algo));
		memcpy(resource->info->compress_algo, algo, MIN(strlen(algo),
					sizeof(resource->info->compress_algo)));
		init_compression_ctx(&(resource->info->comp_ctx), algo);
		if (resource->info->comp_ctx.chunk_initiator(
				&(resource->info->cp_chunk), resource->info->fullpath)) {
			r = server_create_and_stat_error(
					resource_get_server_config(resource), resource->pool,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"Failed to init chunk bucket");
		}
	}
	if (comp_opt)
		g_hash_table_destroy(comp_opt);

	if (e)
		g_clear_error(&e);

	return r;
}

/******************** REQUEST UTILITY FUNCTIONS ******************/

static int
_load_field(apr_pool_t *pool, apr_table_t *table, const char *name, char **dst)
{
	const char *value = apr_table_get(table, name);
	if (!value)
		return 0;
	gchar *decoded = g_uri_unescape_string (value, NULL);
	*dst = apr_pstrdup (pool, decoded);
	g_free (decoded);
	return 1;
}

#define REPLACE_FIELD(S) str_replace_by_pooled_str(pool, &(cti->S))

#define LAZY_LOAD_FIELD(Where,Name) do { \
	if (!cti->Where) \
		_load_field(pool, src, RAWX_HEADER_PREFIX Name, &(cti->Where)); \
} while (0)

#define OVERLOAD_FIELD(Where,Name) do { \
	_load_field(pool, src, RAWX_HEADER_PREFIX Name, &(cti->Where)); \
} while (0)

static gboolean _null_or_hexa1 (const char *s) { return !s || oio_str_ishexa1(s); }

static void
chunk_info_fields__glib2apr (apr_pool_t *pool, struct chunk_textinfo_s *cti)
{
	REPLACE_FIELD(container_id);

	REPLACE_FIELD(content_id);
	REPLACE_FIELD(content_path);
	REPLACE_FIELD(content_version);
	REPLACE_FIELD(content_size);
	REPLACE_FIELD(content_chunk_nb);

	REPLACE_FIELD(content_storage_policy);
	REPLACE_FIELD(content_chunk_method);
	REPLACE_FIELD(content_mime_type);

	REPLACE_FIELD(metachunk_size);
	REPLACE_FIELD(metachunk_hash);

	REPLACE_FIELD(chunk_id);
	REPLACE_FIELD(chunk_size);
	REPLACE_FIELD(chunk_position);
	REPLACE_FIELD(chunk_hash);
}

void
request_overload_chunk_info_from_trailers(request_rec *request,
		struct chunk_textinfo_s *cti)
{
	apr_table_t *src = request->trailers_in;
	apr_pool_t *pool = request->pool;

	OVERLOAD_FIELD(metachunk_hash, "metachunk-hash");
	OVERLOAD_FIELD(metachunk_size, "metachunk-size");
	OVERLOAD_FIELD(chunk_size,     "chunk-size");
	OVERLOAD_FIELD(chunk_hash,     "chunk-hash");
}

void
request_load_chunk_info_from_headers(request_rec *request,
		struct chunk_textinfo_s *cti)
{
	apr_table_t *src = request->headers_in;
	apr_pool_t *pool = request->pool;

	LAZY_LOAD_FIELD(container_id,           "container-id");
	LAZY_LOAD_FIELD(content_id,             "content-id");
	LAZY_LOAD_FIELD(content_path,           "content-path");
	LAZY_LOAD_FIELD(content_version,        "content-version");
	LAZY_LOAD_FIELD(content_size,           "content-size");
	LAZY_LOAD_FIELD(content_chunk_nb,       "content-chunksnb");
	LAZY_LOAD_FIELD(content_storage_policy, "content-storage-policy");
	LAZY_LOAD_FIELD(content_mime_type,      "content-mime-type");
	LAZY_LOAD_FIELD(content_chunk_method,   "content-chunk-method");
	LAZY_LOAD_FIELD(metachunk_hash,         "metachunk-hash");
	LAZY_LOAD_FIELD(metachunk_size,         "metachunk-size");
	LAZY_LOAD_FIELD(chunk_id,               "chunk-id");
	LAZY_LOAD_FIELD(chunk_size,             "chunk-size");
	LAZY_LOAD_FIELD(chunk_position,         "chunk-pos");
	LAZY_LOAD_FIELD(chunk_hash,             "chunk-hash");
}

const char *
check_chunk_info(const struct chunk_textinfo_s * const cti)
{
	if (!cti->container_id) return "container-id";
	if (!cti->content_id) return "content-id";
	if (!cti->content_storage_policy) return "storage-policy";
	if (!cti->content_chunk_method) return "chunk-method";
	//if (!cti->content_mime_type) return "mime-type";
	if (!cti->content_path) return "content-path";
	if (!cti->content_version) return "version";
	if (!cti->chunk_position) return "chunk-pos";

	oio_str_upper (cti->container_id);
	oio_str_upper (cti->content_id);
	oio_str_upper (cti->chunk_hash);
	oio_str_upper (cti->chunk_id);

	if (!oio_str_ishexa(cti->container_id, 64)) return "container-id";
	if (!_null_or_hexa1(cti->content_id)) return "content-id";
	if (!_null_or_hexa1(cti->chunk_id)) return "chunk-id";
	if (!_null_or_hexa1(cti->chunk_hash)) return "chunk-hash";

	return NULL;
}

const char *
check_chunk_info_with_trailers(const struct chunk_textinfo_s * const cti)
{
	const char *msg = check_chunk_info (cti);
	if (NULL != msg) return msg;

	if (cti->metachunk_size && !oio_str_is_number(cti->metachunk_size, NULL))
		return "metachunk-size";

	oio_str_upper (cti->metachunk_hash);

	if (!_null_or_hexa1(cti->metachunk_hash))
		return "metachunk-hash";

	if (cti->chunk_size && !oio_str_is_number(cti->chunk_size, NULL))
		return "chunk-size";

	if (g_str_has_prefix(cti->content_chunk_method, "ec/")
			&& !cti->metachunk_size)
		return "metachunk-size";

	if (g_str_has_prefix(cti->content_chunk_method, "ec/")
			&& !cti->metachunk_hash)
		return "metachunk-hash";

	return NULL;
}

void
resource_stat_chunk(dav_resource *resource, int flags)
{
	dav_resource_private *ctx;
	apr_status_t status = APR_ENOENT;

	ctx = resource->info;

	if (resource->type != DAV_RESOURCE_TYPE_REGULAR || resource->collection) {
		DAV_ERROR_RES(resource, 0, "Cannot stat a anything else a chunk");
		return;
	}

	if (flags & RESOURCE_STAT_CHUNK_PENDING) {
		char *tmp_path = apr_pstrcat(resource->pool,
				resource_get_pathname(resource), ".pending", NULL);
		status = apr_stat(&(resource->info->finfo), tmp_path,
				APR_FINFO_NORM, resource->pool);
	}

	if (status != APR_SUCCESS)
		status = apr_stat(&(resource->info->finfo),
				resource_get_pathname(resource),
				APR_FINFO_NORM, resource->pool);

	resource->collection = 0;
	resource->exists = (status == APR_SUCCESS);

	if (!resource->exists)
		DAV_DEBUG_RES(resource, 0, "Resource does not exist [%s]", resource_get_pathname(resource));
	else  {
		gboolean rc;
		GError *err = NULL;

		DAV_DEBUG_RES(resource, 0, "Resource exists [%s]", resource_get_pathname(resource));

		memset(&(ctx->chunk), 0, sizeof(ctx->chunk));
		if (flags & RESOURCE_STAT_CHUNK_READ_ATTRS) {
			rc = get_rawx_info_from_file(resource_get_pathname(resource), &err, &(ctx->chunk));
			if (!rc) {
				DAV_DEBUG_RES(resource, 0, "Chunk xattr loading error [%s] : %s",
						resource_get_pathname(resource),
						apr_pstrdup(resource->pool, gerror_get_message(err)));
			}
			else {
				chunk_info_fields__glib2apr (resource->pool, &resource->info->chunk);
			}
			if (err)
				g_clear_error(&err);
		}
	}
}

void
request_parse_query(request_rec *r, dav_resource *resource)
{
	if (!r->parsed_uri.query)
		return;

	char *query = NULL;
	query = apr_pstrdup(r->pool, r->parsed_uri.query);

	/* Expected comp=true&algo=XXXX&bs=XXXX */
	char *k = NULL;
	char *v = NULL;
	char *last = NULL;

	k = apr_strtok(query, "=&", &last);
	v = apr_strtok(NULL, "=&", &last);

	if (!k || !v)
		goto end;

	do {
		if (!apr_strnatcasecmp(k, "comp"))
			resource->info->forced_cp = apr_pstrdup(r->pool, v);
		if (!apr_strnatcasecmp(k, "algo"))
			resource->info->forced_cp_algo = apr_pstrdup(r->pool, v);
		if (!apr_strnatcasecmp(k, "bs"))
			resource->info->forced_cp_bs = apr_pstrdup(r->pool, v);
	} while ((k = apr_strtok(NULL, "=&", &last)) &&
			(v = apr_strtok(NULL, "=&", &last)));

end:
	DAV_DEBUG_REQ(r, 0, "forced_cp=%s, forced_cp_algo=%s, forced_cp_bs=%s",
			resource->info->forced_cp, resource->info->forced_cp_algo,
			resource->info->forced_cp_bs);
	if (!resource->info->forced_cp)
		resource->info->forced_cp = apr_pstrdup(r->pool, "false");
}

void
request_fill_headers(request_rec *r, struct chunk_textinfo_s *c)
{
	__set_header(r, "container-id",  c->container_id);

	if (c->content_path) {
		gchar *decoded = g_uri_escape_string (c->content_path, NULL, FALSE);
		__set_header(r, "content-path", decoded);
		g_free (decoded);
	}

	__set_header(r, "content-id",       c->content_id);
	__set_header(r, "content-size",     c->content_size);
	__set_header(r, "content-version",  c->content_version);
	__set_header(r, "content-chunksnb", c->content_chunk_nb);

	__set_header(r, "content-storage-policy", c->content_storage_policy);
	__set_header(r, "content-chunk-method",   c->content_chunk_method);
	__set_header(r, "content-mime-type",      c->content_mime_type);

	__set_header(r, "metachunk-size", c->metachunk_size);
	__set_header(r, "metachunk-hash", c->metachunk_hash);

	__set_header(r, "chunk-id",   c->chunk_id);
	__set_header(r, "chunk-size", c->chunk_size);
	__set_header(r, "chunk-hash", c->chunk_hash);
	__set_header(r, "chunk-pos",  c->chunk_position);
}

/*************************************************************************/

dav_error *
rawx_repo_check_request(request_rec *req, const char *root_dir, const char * label,
			int use_checked_in, dav_resource_private *ctx, dav_resource **result_resource)
{
	dav_rawx_server_conf *conf = request_get_server_config(req);

	ctx->update_only = g_str_has_prefix(req->uri, "/rawx/chunk/set");

	char *src = strrchr(req->uri, '/');
	src = src ? src + 1 : req->uri;

	if (!strcmp(src, "info"))
		return dav_rawx_info_get_resource(req, root_dir, label, use_checked_in, result_resource);

	if (!strcmp(src, "stat"))
		return dav_rawx_stat_get_resource(req, root_dir, label, use_checked_in, result_resource);

	if (!strcmp(src, "update"))
		return dav_rawx_chunk_update_get_resource(req, root_dir, label, use_checked_in, result_resource);

	if (g_str_has_prefix(src, "rawx/"))
		return server_create_and_stat_error(conf, req->pool,
				HTTP_BAD_REQUEST, 0, "Raw request not yet implemented");

	if (!oio_str_ishexa (src, 64))
		return server_create_and_stat_error(conf, req->pool,
				HTTP_BAD_REQUEST, 0, "Invalid CHUNK id character");

	ctx->file_extension[0] = 0;
	g_strlcpy(ctx->hex_chunkid, src, sizeof(ctx->hex_chunkid));
	oio_str_upper (ctx->hex_chunkid);

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

	/* If buffer contain data, compress it if needed and write it to file */
	if (stream->buffer_offset > 0) {
		if (!stream->compression) {
			e = _write_data_crumble_UNCOMP(stream);
		} else {
			e = _write_data_crumble_COMP(stream, &checksum);
		}
	}
	/* write eof & checksum */
	if (!e && stream->compression) {
		if (stream->comp_ctx.eof_writer(stream->f, checksum, &(stream->compressed_size))) {
			/* ### use something besides 500? */
			e = server_create_and_stat_error(resource_get_server_config(stream->r), stream->p,
					HTTP_INTERNAL_SERVER_ERROR, 0,
					"An error occurred while writing end of file ");
		}
	}
	return e;
}

static int
_unlink_and_log(dav_stream *stream, const char *path)
{
	if (unlink(path) == 0 || errno == ENOENT || errno == ENOTDIR)
		return 0;
	DAV_ERROR_REQ(stream->r->info->request, 0, "ORPHAN %s", path);
	return 1;
}

dav_error *
rawx_repo_rollback_upload(dav_stream *stream)
{
	if (stream->f)
		fclose(stream->f);

	const int rc_final = _unlink_and_log(stream, stream->final_pathname);
	const int rc_temp = _unlink_and_log(stream, stream->pathname);
	if (!rc_temp && !rc_final)
		return NULL;

	return server_create_and_stat_error(
			resource_get_server_config(stream->r), stream->p,
			HTTP_INTERNAL_SERVER_ERROR, 0, "Rollback error");
}

#define DUP(F) do { \
	if (stream->r->info->chunk . F) \
		fake. F = apr_pstrdup(stream->r->pool, stream->r->info->chunk. F); \
} while (0)

dav_error *
rawx_repo_commit_upload(dav_stream *stream)
{
	dav_error *e = NULL;
	struct chunk_textinfo_s fake = {0};

	DUP(container_id);
	DUP(content_id);
	DUP(content_path);
	DUP(content_version);
	DUP(content_size);
	DUP(content_chunk_nb);
	DUP(content_storage_policy);
	DUP(content_chunk_method);
	DUP(content_mime_type);
	DUP(metachunk_size);
	DUP(metachunk_hash);
	DUP(chunk_id);
	DUP(chunk_size);
	DUP(chunk_hash);
	DUP(chunk_position);
	DUP(compression_metadata);
	DUP(compression_size);

	/* Load the metadata located in the Trailers of the request */
	request_overload_chunk_info_from_trailers (stream->r->info->request, &fake);

	/* Sanitize the chunk hash */
	if (stream->md5) {
		const char *hex = g_checksum_get_string(stream->md5);
		if (!fake.chunk_hash) {
			/* No checksum provided, let's save the checksum computed */
			fake.chunk_hash = apr_pstrdup(stream->p, hex);
			oio_str_upper(fake.chunk_hash);
			DAV_DEBUG_REQ(stream->r->info->request, 0, "MD5 computed for %s",
					stream->final_pathname);
		} else {
			/* A checksum has been provided, let's check it matches the checksum
			 * computed over the input */
			if (0 != strcasecmp(fake.chunk_hash, hex)) {
				return server_create_and_stat_error(resource_get_server_config(stream->r),
						stream->p, HTTP_UNPROCESSABLE_ENTITY, 0, apr_pstrcat(stream->p,
							"MD5 mismatch hdr=", fake.chunk_hash, " body=", hex, NULL));
			} else {
				DAV_DEBUG_REQ(stream->r->info->request, 0, "MD5 match for %s",
						stream->final_pathname);
			}
		}
	} else {
		DAV_DEBUG_REQ(stream->r->info->request, 0, "No MD5 computed for %s",
				stream->final_pathname);
	}

	/* Ensure a (meta)chunk size */
	if (!fake.chunk_size) {
		fake.chunk_size = apr_psprintf(stream->r->pool, "%d", (int)stream->total_size);
	}

	if (stream->compressed_size) {
		char size[32];
		apr_snprintf(size, 32, "%d", stream->compressed_size);
		oio_str_replace(&(fake.compression_metadata), stream->metadata_compress);
		oio_str_replace(&(fake.compression_size), size);
	}

	const char *msg = check_chunk_info_with_trailers (&fake);
	if (msg != NULL) {
		e = server_create_and_stat_error(resource_get_server_config(stream->r),
				stream->p, HTTP_FORBIDDEN, 0,
				apr_pstrcat(stream->p, "Error with xattr/header ", msg, NULL));
		return e;
	}

	/* ok, save now */
	e = _set_chunk_extended_attributes(stream, &fake);
	if (e) {
		DAV_ERROR_REQ(stream->r->info->request, 0,
				"Failed to set chunk extended attributes: %s", e->desc);
		return e;
	}

	e = _finalize_chunk_creation(stream);
	if (e) {
		DAV_ERROR_REQ(stream->r->info->request, 0,
				"Failed to finalize chunk file creation: %s", e->desc);
		return e;
	}

	request_fill_headers(stream->r->info->request, &fake);

	send_chunk_event("storage.chunk.new", stream->r);

	return NULL;
}

static dav_error *
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
	int retryable = 1;

	int should_compress = 0;

	dav_stream *ds = apr_pcalloc(p, sizeof(*ds));
	ds->fsync_on_close = conf->fsync_on_close;
	ds->p = p;
	ds->r = resource;
	ds->final_pathname = apr_pstrcat(p, ctx->dirname, "/", ctx->hex_chunkid, NULL);
	ds->pathname = apr_pstrcat(p, ctx->dirname, "/", ctx->hex_chunkid, ".pending", NULL);

	/* Create busy chunk file */
	int fd;
retry:
	fd = open(ds->pathname, O_CREAT|O_EXCL|O_WRONLY, 0600);
	if (fd < 0) {
		if (errno == ENOENT && retryable) {
			retryable = 0;
			dav_error *e = rawx_repo_ensure_directory (resource);
			if (!e)
				goto retry;
			return e;
		}
		DAV_DEBUG_REQ(resource->info->request, 0, "open(%s) failed : %s",
				ds->pathname, strerror(errno));
		return server_create_and_stat_error(resource_get_server_config(resource), p,
				MAP_IO2HTTP(rv), 0, "Chunk creation error");
	}

	/* Check the final chunks hasn't been created meanwhile */
	if (0 == access(ds->final_pathname, F_OK)) {
		(void) unlink(ds->pathname);
		return server_create_and_stat_error(resource_get_server_config(resource), p,
				HTTP_FORBIDDEN, 0, "Chunk already present.");
	}

	/* Wrap it under a FILE */
	if (!(ds->f = fdopen(fd, "w"))) {
		DAV_DEBUG_REQ(resource->info->request, 0, "fdopen(%s) failed : %s",
				ds->pathname, strerror(errno));
		(void) unlink(ds->pathname);
		return server_create_and_stat_error(resource_get_server_config(resource), p,
				HTTP_INTERNAL_SERVER_ERROR, 0, "FILE allocation error");
	}

	/* Preallocate disk space for the chunk */
	apr_int64_t chunk_size = 0;
	if (ctx->chunk.chunk_size != NULL && conf->fallocate &&
			(chunk_size = apr_strtoi64(ctx->chunk.chunk_size, NULL, 10)) > 0 &&
			(rv = posix_fallocate(fileno(ds->f), 0, (off_t)chunk_size)) != 0) {
		DAV_DEBUG_REQ(resource->info->request, 0, "posix_fallocate(%s) failed : %s",
				ds->pathname, strerror(errno));
		dav_error *err = server_create_and_stat_error(conf, p,
				MAP_IO2HTTP(rv), 0, "Space allocation error");
		fclose(ds->f);
		unlink(ds->pathname);
		return err;
	}

	if (conf->compression_algo && *conf->compression_algo) {
		should_compress = TRUE;
		ctx->forced_cp_algo = apr_pstrdup(p, conf->compression_algo);
	} else if (ctx->forced_cp) {
		should_compress = !g_ascii_strncasecmp(ctx->forced_cp, "true", 4);
	}

	if (!should_compress ||
			!namespace_in_compression_mode(conf->rawx_conf->ni)) {
		ds->buffer_size = DEFAULT_BLOCK_SIZE;
		ds->buffer = apr_pcalloc(p, ds->buffer_size);
		ds->buffer_offset = 0;
	} else {
		ds->compression = TRUE;
		if (ctx->forced_cp_bs)
			ds->buffer_size = strtol(ctx->forced_cp_bs, NULL, 10);
		else
			ds->buffer_size = DEFAULT_BLOCK_SIZE;

		if (!ctx->forced_cp_algo)
			ctx->forced_cp_algo = DEFAULT_COMPRESSION_ALGO;

		metadata_compress = apr_pstrcat(p,
				NS_COMPRESSION_OPTION, "=", NS_COMPRESSION_ON, ";",
				NS_COMPRESS_ALGO_OPTION,"=", ctx->forced_cp_algo, ";",
				NS_COMPRESS_BLOCKSIZE_OPTION, "=", ctx->forced_cp_bs, NULL);

		DAV_DEBUG_REQ(resource->info->request, 0 , "%s", metadata_compress);
		init_compression_ctx(&(ds->comp_ctx), ctx->forced_cp_algo);

		ds->buffer = apr_pcalloc(p, ds->buffer_size);
		ds->buffer_offset = 0;

		gulong checksum = 0;

		if(!(ds->comp_ctx.checksum_initiator)(&checksum)){
			WARN("Failed to init compression checksum");
		}

		ds->metadata_compress = apr_pstrndup(p, metadata_compress, strlen(metadata_compress));

		/* writting compression header in busy file */
		guint32 bsize32 = ds->buffer_size;
		if(0 != ds->comp_ctx.header_writer(ds->f, bsize32, &checksum, &(ds->compressed_size))){
			return server_create_and_stat_error(resource_get_server_config(resource), p,
				HTTP_INTERNAL_SERVER_ERROR, 0,
				apr_pstrcat(p, "Failed to write compression headers", NULL));
		}
		ds->compress_checksum = checksum;
	}

	ds->md5 = NULL;
	if (conf->checksum_mode == CHECKSUM_ALWAYS) {
		ds->md5 = g_checksum_new (G_CHECKSUM_MD5);
	} else if (conf->checksum_mode == CHECKSUM_SMART) {
	   if (!oio_str_prefixed(ctx->chunk.content_chunk_method, STGPOL_DSPREFIX_EC, "/"))
		   ds->md5 = g_checksum_new (G_CHECKSUM_MD5);
	}

	*result = ds;

	return NULL;
}
