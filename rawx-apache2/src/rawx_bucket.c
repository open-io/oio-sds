
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

// TODO FIXME replace with APR equivalent
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

#include <rawx-lib/src/rawx.h>

#include <glib.h>

#include "rawx_bucket.h"
#include "rawx_repo_core.h"
#include "rawx_internals.h"
#include "rawx_config.h"

void
chunk_bucket_destroy(void *d)
{
	(void) d;
	/*no-op*/
}

void
chunk_bucket_free_noop(void *d)
{
	(void) d;
	/*no-op*/
}

apr_status_t
chunk_bucket_read(apr_bucket *b, const char **str, apr_size_t *len, apr_read_type_e block)
{
	apr_size_t written=0, length=0;
	apr_size_t offset = 0;
	apr_int64_t total64, remaining64, done64;
	apr_int64_t bl64, w64;
	ssize_t w;
	dav_resource_private *ctx;
	apr_status_t rc;
	rc = APR_SUCCESS;

	(void) block;

	*str = NULL;  /* in case we die prematurely */
	*len = 0;

	/*dummy bucket*/
	if (b->length == (apr_size_t)(-1) || b->start == (apr_off_t)(-1))
		return APR_SUCCESS;
	
	ctx = b->data;
	offset = b->start - ctx->cp_chunk.read;
	DAV_DEBUG_REQ(ctx->request, 0, "Reading data for this bucket start at current position + %"APR_SIZE_T_FMT, offset);
	DAV_DEBUG_REQ(ctx->request, 0, "Bucket length %"APR_SIZE_T_FMT, b->length);
	total64 = g_ascii_strtoll(ctx->cp_chunk.uncompressed_size, NULL, 10);
	done64 = b->start;
	bl64 = b->length;
	remaining64 = MIN(total64 - done64, bl64);

	DAV_DEBUG_REQ(ctx->request, 0, "Data already returned=%"APR_INT64_T_FMT", remaining=%"APR_INT64_T_FMT, done64, remaining64);

	if (remaining64 <= 0){
		DAV_DEBUG_REQ(ctx->request, 0, "No remaining data, end of resource delivering.");
		apr_bucket_heap_make(b, NULL, *len, apr_bucket_free);
		return APR_SUCCESS;
	}
	else { /* determine the size of THIS bucket */
		if (remaining64 > APR_BUCKET_BUFF_SIZE)
			length = APR_BUCKET_BUFF_SIZE;
		else
			length = remaining64;
	}

	*len = length;

	guint8 *buf = apr_bucket_alloc(length, b->list);
	for (written=0; written < length ;) {
		GError *gerror;
	
		DAV_DEBUG_REQ(ctx->request, 0, "Trying to read at most %"APR_SSIZE_T_FMT" bytes (%"APR_SSIZE_T_FMT" received)",
				length - written, written);
		
		gerror = NULL;
		w = ctx->comp_ctx.data_uncompressor(&ctx->cp_chunk, offset, buf+written, length-written, &gerror);
		offset = 0;
		DAV_DEBUG_REQ(ctx->request, 0 , "%"APR_SSIZE_T_FMT" bytes read from local resource", w);
		if (w < 0) {
			DAV_ERROR_REQ(ctx->request, 0, "Read from chunk failed : %s", gerror_get_message(gerror));
			if (gerror)
				g_error_free(gerror);
			apr_bucket_free(buf);
			return APR_INCOMPLETE;
		}
		if (gerror)
			g_error_free(gerror);
		if (w == 0) {
			DAV_DEBUG_REQ(ctx->request, 0, "No bytes read from local resource whereas we"
						" must read again, this should never happened");
			apr_bucket_free(buf);
			return APR_INCOMPLETE;
		}
		written += w;
	}
	*len = written;

	DAV_DEBUG_REQ(ctx->request, 0, "Bucket done (%"APR_SSIZE_T_FMT" bytes, rc=%d)", written, rc);

	w64 = written;

	DAV_DEBUG_REQ(ctx->request, 0, "Status info : %"APR_INT64_T_FMT" written , %"APR_INT64_T_FMT" length total", w64, bl64);

	apr_bucket_heap_make(b, (char*)buf, *len, apr_bucket_free);

	if(w64 < bl64) {
		apr_bucket *bkt;
		DAV_DEBUG_REQ(ctx->request, 0, "Creating bucket info: bkt->length = %"APR_INT64_T_FMT", bkt->start ="
					" %"APR_INT64_T_FMT", bkt->data = %p, bkt->list = %p\n", remaining64, done64 + w64,
					&(ctx->cp_chunk), b->list);
		bkt = apr_bucket_alloc(sizeof(*bkt), b->list);
		bkt->type = &chunk_bucket_type;
		bkt->length = remaining64 - w64;
		bkt->start = done64 + w64;
		bkt->data = ctx;
		bkt->free = chunk_bucket_free_noop;
		bkt->list = b->list;
		APR_BUCKET_INSERT_AFTER(b, bkt);
		DAV_DEBUG_REQ(ctx->request, 0, "Starting a new RAWX bucket (length=%"APR_SIZE_T_FMT" start=%"APR_INT64_T_FMT")", bkt->length, bkt->start);
	}

	*str = (char*)buf;
	return rc;
}

apr_status_t
chunk_bucket_split(apr_bucket *e, apr_size_t point)
{
	dav_resource_private *ctx = e->data;
	DAV_DEBUG_REQ(ctx->request, 0, "Calling bucket split, want to split bucket(start=%"APR_OFF_T_FMT",length=%"APR_SIZE_T_FMT") at %"APR_SIZE_T_FMT, e->start, e->length, point);
	apr_bucket *splitted = NULL;
	apr_bucket_copy(e, &splitted);
	splitted->start = e->start + point;
	splitted->length = e->length - point;
	e->length = point;
	APR_BUCKET_INSERT_AFTER(e, splitted);
	DAV_DEBUG_REQ(ctx->request, 0, "Split result : b1(start=%"APR_OFF_T_FMT",length=%"APR_SIZE_T_FMT"), b2(start=%"APR_OFF_T_FMT",length=%"APR_SIZE_T_FMT")", e->start, e->length, splitted->start, splitted->length);
	return APR_SUCCESS;
}

apr_status_t
chunk_bucket_copy(apr_bucket *e, apr_bucket **c)
{
	dav_resource_private *ctx = e->data;
	DAV_DEBUG_REQ(ctx->request, 0, "Calling bucket copy");

	apr_bucket *result = NULL;
	result = apr_palloc(ctx->pool, sizeof(struct apr_bucket));
	result->type = e->type;
	result->length = e->length;
	result->start = e->start;
	result->data = ctx;
	result->free = chunk_bucket_free_noop;
	result->list = e->list;

	*c = result;

	return APR_SUCCESS;

}
