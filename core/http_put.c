/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <core/http_put.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <glib/gstdio.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <erasurecode.h>

#include <core/client_variables.h>
#include <core/oioext.h>
#include <core/oiolog.h>

#include "internals.h"
#include "http_internals.h"

#define EC_SEGMENT_SIZE 1048576

enum http_single_put_e
{
	HTTP_SINGLE_BEGIN = 0,
	HTTP_SINGLE_REQUEST,
	HTTP_SINGLE_PAUSED,
	HTTP_SINGLE_REPLY,
	HTTP_SINGLE_FINISHED
};

enum http_whole_put_state_e
{
	HTTP_WHOLE_BEGIN = 0,
	HTTP_WHOLE_READY,
	HTTP_WHOLE_PAUSED,
	HTTP_WHOLE_FINISHED
};

struct http_put_dest_s
{
	struct http_put_s *http_put;	/* backpointer */
	gchar *url;
	CURL *handle;

	/* Headers to send in the put request */
	GSList *headers;
	struct curl_slist *curl_headers;

	/* Headers from the response */
	GHashTable *response_headers;

	/* user data corresponding to this destination */
	gpointer user_data;

	GBytes *buffer;

	/* HTTP error code (valid if success == 1) */
	gint64 bytes_sent;
	guint http_code;
	enum http_single_put_e state;

	// In EC, we have to send the meta-chunk hash as trailing headers
	GChecksum *checksum_metachunk;
	GChecksum *checksum_chunk;
};

struct http_put_s
{
	GSList *dests; /* <struct http_put_dest_s*> */

	CURLM *mhandle;

	long timeout_cnx;  // milliseconds
	long timeout_op;  // milliseconds

	/* how many bytes are announced to the server
	 *   <0 : streaming with transfer-encoding=chunked
	 *   0 : empty content
	 *   >0 : content-length known and announced */
	gint64 content_length;

	/* how many bytes are expected
	 *   <0 : streaming with transfer-encoding=chunked
	 *   0 : empty content
	 *   >0 : content-length known and announced */
	gint64 soft_length;

	/* How many bytes might still be enqueued. <remaining_length> starts at
	 * <soft_length> and decreases for each buffer enqueued. */
	gint64 remaining_length;

	GQueue *buffer_tail; /* <GBytes*> */

	enum http_whole_put_state_e state;

	// We need this at the end of the stream.
	GChecksum *checksum_metachunk;

	// EC parameters.
	int ec_k, ec_m, ec_handle;
};

#ifdef HAVE_EXTRA_DEBUG
static const char *
_single_put_state_to_string (enum http_single_put_e s)
{
	switch (s) {
		ON_ENUM(HTTP_SINGLE_,BEGIN);
		ON_ENUM(HTTP_SINGLE_,REQUEST);
		ON_ENUM(HTTP_SINGLE_,PAUSED);
		ON_ENUM(HTTP_SINGLE_,REPLY);
		ON_ENUM(HTTP_SINGLE_,FINISHED);
	}
	g_assert_not_reached ();
	return "?";
}
#endif

static void __attribute__ ((constructor))
init_curl(void)
{
	/* With NSS, all internal data are not correctly freed at
	 * the end of the program... and we don't use ssl so we don't need it.
	 */
	curl_global_init(CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL);
}

static void __attribute__ ((destructor))
destroy_curl(void)
{
	curl_global_cleanup();
}

/* -------------------------------------------------------------------------- */

struct http_put_s *
http_put_create(gint64 content_length, gint64 soft_length)
{
	/* sanity checks */
	if (soft_length < 0 && content_length >= 0)
		soft_length = content_length;
	if (soft_length >= 0 && content_length >= 0) {
		if (soft_length != content_length)
			return NULL;
	}

	struct http_put_s *p = g_try_malloc0(sizeof(struct http_put_s));
	p->dests = NULL;
	p->mhandle = curl_multi_init();
	p->buffer_tail = g_queue_new();
	p->timeout_cnx = oio_client_rawx_timeout_cnx * 1000L;  // seconds to ms
	p->timeout_op = oio_client_rawx_timeout_req * 1000L;  // seconds to ms
	p->content_length = content_length;
	p->remaining_length = p->soft_length = soft_length;
	p->state = HTTP_WHOLE_BEGIN;
	return p;
}


/**
 * There's a problem with libec_get_fragment_size where it returns a 80-bytes
 * short length. So this is a hack around that problem.
 * @param ec_handle The liberasurecode handle that was created for the request.
 * @return The final fragment size that'll be pushed to RAWX.
 */
int
http_put_ec_get_fragment_size(int ec_handle)
{
	char **data_frags, **parity_frags;
	uint64_t frag_length;
	char dummy_data[EC_SEGMENT_SIZE] = { 0 };
	liberasurecode_encode(ec_handle, dummy_data, EC_SEGMENT_SIZE, &data_frags,
			&parity_frags, &frag_length);
	liberasurecode_encode_cleanup(ec_handle, data_frags, parity_frags);
	return frag_length;
}


/**
 * Wrapper around http_put_create that adjusts the soft_length and fills
 * the EC parameters.
 * @param content_length Designed for cases where the content length is already
 * 			known. Not used in practice.
 * @param soft_length The maximum allowed size for a chunk
 * @param handle The liberasurecode handle used for this request
 * @param k The K parameter for the EC
 * @param m The M parameter for the EC
 * @param chk The metachunk checksum handle, needed at the end of the request.
 */
struct http_put_s *
http_put_create_with_ec(gint64 content_length, gint64 soft_length, int handle,
		int k, int m, GChecksum * chk)
{
	int frag_length = http_put_ec_get_fragment_size(handle);
	int segments_needed = round((double) soft_length / (double) frag_length);
	soft_length = segments_needed * EC_SEGMENT_SIZE;
	struct http_put_s *put = http_put_create(content_length, soft_length);
	put->ec_handle = handle;
	put->ec_m = m;
	put->ec_k = k;
	put->checksum_metachunk = chk;
	return put;
}

/**
 * Returns whether more than EC_SEGMENT_SIZE bytes are available in the queue,
 * or that the termination buffer is present in the queue.
 * @param buffer_queue The buffer queue to be analyzed.
 * @return TRUE if enough data is available, FALSE otherwise.
 */
static int
http_put_ec_enough_data_available(GQueue * buffer_queue)
{
	int queue_len = g_queue_get_length(buffer_queue);
	unsigned int buffer_len = 0;
	gsize i_buf_len = 0;
	for (int i = 0; i < queue_len; i++) {
		i_buf_len = g_bytes_get_size(g_queue_peek_nth(buffer_queue, i));
		buffer_len += i_buf_len;
		if (buffer_len >= EC_SEGMENT_SIZE || i_buf_len == 0)
			return TRUE;
	}
	return FALSE;
}

/**
 * Returns a buffer of data to be encoded.
 *
 * Generally only returns n*EC_SEGMENT_SIZE sized buffers, but if a termination
 * buffer is detected in the queue, it will return a concatenation of the whole
 * buffer queue.
 *
 * This assumes that either more than EC_SEGMENT_SIZE bytes are available in the
 * queue, or that the termination buffer is present in the queue.
 *
 * @param put The metachunk upload handle.
 * @return The bytes to be encoded.
 */
static GBytes *
http_put_ec_get_encodable_data(struct http_put_s *put)
{

	/* FIXME: Verify that we have indeed more than EC_SEGMENT_SIZE or
	 * termination buffer is present instead of assuming. */

	// Figure out whether we need to encode everything left in buffer queue.
	// If there is a termination buffer somewhere in the queue, it's bound
	// to be at the tail of the queue.
	int end_of_metachunk =
			g_bytes_get_size(g_queue_peek_tail(put->buffer_tail)) == 0;

	// Push everything into a byte array for further manipulation.
	unsigned int buf_len = 0;
	GByteArray *buf_builder = g_byte_array_new();

	GBytes *head;
	while ((head = g_queue_pop_head(put->buffer_tail))) {
		if (g_bytes_get_size(head) != 0) {
			buf_len += g_bytes_get_size(head);
			g_byte_array_append(buf_builder, g_bytes_get_data(head, 0),
					g_bytes_get_size(head));
			g_bytes_unref(head);
		} else {
			// We no longer need to pop and we have a termination buffer so
			// we re-enqueue it.
			g_queue_push_head(put->buffer_tail, head);
			break;
		}
	}

	GBytes *concat_buffer = g_byte_array_free_to_bytes(buf_builder);

	// If we have a byte array that's a multiple of EC_SEGMENT_SIZE or less than
	// EC_SEGMENT_SIZE or it's EOF
	if (buf_len % EC_SEGMENT_SIZE == 0 || end_of_metachunk) {
		return concat_buffer;
	}
	// By now we are sure we have EC_SEGMENT_SIZE and some bytes.
	// Get the n*EC_SEGMENT_SIZE slice and the rest and push them in order.
	gsize first_slice_size = EC_SEGMENT_SIZE * (buf_len / EC_SEGMENT_SIZE);

	// Fetch the encodable data we need.
	GBytes *encodable_data = g_bytes_new_from_bytes(concat_buffer, 0,
			first_slice_size);
	GBytes *leftover_data = g_bytes_new_from_bytes(concat_buffer,
			first_slice_size,
			g_bytes_get_size(concat_buffer) - first_slice_size);

	// Re-enqueue the leftovers
	g_queue_push_head(put->buffer_tail, leftover_data);

	// Unref GBytes
	g_bytes_unref(concat_buffer);

	return encodable_data;
}

/**
 * Encodes all the data given in in buf, puts concatenated fragments in the
 * fragments array.
 *
 * Assuming we have a (2*EC_SEGEMENT_SIZE) sized buf, the result of encoding
 * each EC_SEGMENT_SIZE wil be an array of K+M ordered fragments,
 * let's say frag_{segment_num}_{frag_num}.
 *
 * In this case the first element of the fragments array will have, in this
 * order, frag_1_1+frag_2_1, and so on.
 *
 * Will encode everything it received as parameter, even if
 * size(buf) % EC_SEGMENT_SIZE != 0
 *
 * @param put The metachunk upload handle
 * @param buf The buffer to encode, typically obtained through
 * 				http_put_ec_get_encodable_data
 * @param fragments Pointer to an array of GBytes that will be allocated
 * 					by this function
 */
static void
http_put_ec_encode_data(struct http_put_s *put, GBytes * buf,
		GBytes ** fragments)
{

	// We need an EC handle to exist, and we need to know the K+M value.
	EXTRA_ASSERT(put->ec_handle && put->ec_handle > 0);
	EXTRA_ASSERT(put->ec_k > 0);
	EXTRA_ASSERT(put->ec_m > 0);

	// Required for libec
	char **data_fragments;
	char **parity_fragments;
	uint64_t fragments_length;

	GByteArray *fragment_builders[put->ec_k + put->ec_m];

	// Otherwise initialize our GByteArrays
	for (int i = 0; i < put->ec_k + put->ec_m; i++)
		fragment_builders[i] = g_byte_array_new();

	// in case we don't have less than EC_SEGMENT_SIZE
	unsigned int next_segment_length, bytes_left, buf_size = 0;
	GBytes *temp_buf;
	gsize temp_size;
	buf_size = (unsigned int) g_bytes_get_size(buf);
	bytes_left = buf_size;

	do {
		next_segment_length = bytes_left >=
				EC_SEGMENT_SIZE ? EC_SEGMENT_SIZE : bytes_left;

		temp_buf = g_bytes_new_from_bytes(buf, buf_size - bytes_left,
				next_segment_length);

		liberasurecode_encode(put->ec_handle,
				g_bytes_get_data(temp_buf, &temp_size),
				next_segment_length,
				&data_fragments, &parity_fragments, &fragments_length);

		bytes_left -= next_segment_length;

		// Now to create GBytes from the fragments we received.
		// We know for sure that we will have K data fragments and
		// M parity fragments
		for (int i = 0; i < put->ec_k; i++)
			g_byte_array_append(fragment_builders[i],
					(guint8 *) data_fragments[i], fragments_length);
		for (int i = 0; i < put->ec_m; i++)
			g_byte_array_append(fragment_builders[put->ec_k + i],
					(guint8 *) parity_fragments[i], fragments_length);

		// Cleanup.
		liberasurecode_encode_cleanup(put->ec_handle, data_fragments,
				parity_fragments);
		g_bytes_unref(temp_buf);

	} while (bytes_left > 0);

	// Build the GBytes that we're going to return
	for (int i = 0; i < put->ec_k + put->ec_m; i++)
		fragments[i] = g_byte_array_free_to_bytes(fragment_builders[i]);

	return;
}

/**
 * Generates the trailing headers for the chunk represented by dest.
 * At the time of writing, the trailing headers metachunk-hash and
 * metachunk-size are obligatory for chunks using EC.
 * @param put The metachunk upload handle
 * @param dest The chunk upload handle
 * @return A The trailing headers containing the size/hash of the metachunk
 * 			and the chunk hash.
// */
static int
http_put_ec_gen_checksums(struct curl_slist **trailers_list,
		struct http_put_dest_s *dest)
{

	struct http_put_s *put = dest->http_put;

	*trailers_list = curl_slist_append(*trailers_list,
			g_strdup_printf("X-oio-chunk-meta-metachunk-size: %ld",
					put->soft_length)
			);

	*trailers_list = curl_slist_append(*trailers_list,
			g_strdup_printf("X-oio-chunk-meta-metachunk-hash: %s",
					g_checksum_get_string(dest->checksum_metachunk)
			)
			);

	*trailers_list = curl_slist_append(*trailers_list,
			g_strdup_printf("X-oio-chunk-meta-chunk-hash: %s",
					g_checksum_get_string(dest->checksum_chunk)
			)
			);
	return CURL_TRAILERFUNC_OK;
}

struct http_put_dest_s *
http_put_add_dest(struct http_put_s *p, const char *url, gpointer u)
{
	EXTRA_ASSERT(p != NULL);
	EXTRA_ASSERT(p->state == HTTP_WHOLE_BEGIN);
	EXTRA_ASSERT(url != NULL);
	EXTRA_ASSERT(u != NULL);

	struct http_put_dest_s *dest = g_try_malloc0(sizeof(struct http_put_dest_s));
	dest->http_put = p;
	dest->url = g_strdup(url);
	dest->handle = NULL;
	dest->user_data = u;
	dest->headers = NULL;
	dest->curl_headers = NULL;
	dest->response_headers = g_hash_table_new_full (g_str_hash, g_str_equal,
			g_free, g_free);
	dest->bytes_sent = 0;
	dest->http_code = 0;
	dest->state = HTTP_SINGLE_BEGIN;

	// Proper cleanup is done in http_put_dest_destroy for the next
	// two attributes.
	dest->checksum_metachunk = p->checksum_metachunk;
	dest->checksum_chunk = g_checksum_new(G_CHECKSUM_MD5);
	p->dests = g_slist_append(p->dests, dest);

	return dest;
}

void
http_put_dest_add_header(struct http_put_dest_s *dest,
		const char *key, const char *val_fmt, ...)
{
	gchar *val = NULL;

	EXTRA_ASSERT(dest != NULL);
	EXTRA_ASSERT(key != NULL);
	EXTRA_ASSERT(val_fmt != NULL);

	va_list ap;
	va_start(ap, val_fmt);
	g_vasprintf(&val, val_fmt, ap);
	va_end(ap);

	gchar *header = g_strdup_printf("%s: %s", key, val);
	g_free(val);

	dest->headers = g_slist_prepend(dest->headers, header);
	dest->curl_headers = curl_slist_append(dest->curl_headers, header);
}

static void
http_put_dest_destroy(gpointer destination)
{
	struct http_put_dest_s *dest = destination;

	EXTRA_ASSERT(dest != NULL);

	if (dest->url)
		g_free(dest->url);
	if (dest->handle) {
		CURLMcode rc;
		rc = curl_multi_remove_handle(dest->http_put->mhandle, dest->handle);
		EXTRA_ASSERT(rc == CURLM_OK);
		(void)rc;
		curl_easy_cleanup(dest->handle);
	}
	if (dest->headers)
		g_slist_free_full(dest->headers, g_free);
	if (dest->curl_headers)
		curl_slist_free_all(dest->curl_headers);
	if (dest->response_headers)
		g_hash_table_destroy(dest->response_headers);

	if (dest->buffer) {
		g_bytes_unref(dest->buffer);
		dest->buffer = NULL;
	}

	// No need to free checksum_metachunk else we'll have a double free
	// It's freed in _sds_upload_reset right before this is called.
	if (dest->checksum_metachunk)
		dest->checksum_metachunk = NULL;

	if (dest->checksum_chunk) {
		g_checksum_free(dest->checksum_chunk);
		dest->checksum_chunk = NULL;
	}


	g_free(dest);
}

void
http_put_destroy(struct http_put_s *p)
{
	if (!p)
		return;
	if (p->dests)
		g_slist_free_full(p->dests, http_put_dest_destroy);
	if (p->mhandle)
		curl_multi_cleanup(p->mhandle);
	if (p->buffer_tail) {
		g_queue_free_full(p->buffer_tail, (GDestroyNotify)g_bytes_unref);
		p->buffer_tail = NULL;
	}
	g_free(p);
}

gint64
http_put_expected_bytes (struct http_put_s *p)
{
	EXTRA_ASSERT(p != NULL);
	if (http_put_done (p))
		return 0;
	return p->remaining_length;
}

void
http_put_feed (struct http_put_s *p, GBytes *b)
{
	EXTRA_ASSERT (p != NULL);
	EXTRA_ASSERT (b != NULL);
	gssize len = g_bytes_get_size (b);
	GRID_TRACE("%s (%p) <- %"G_GSIZE_FORMAT, __FUNCTION__, p, len);
	EXTRA_ASSERT (len <= 0 || p->remaining_length < 0 || len <= p->remaining_length);

	g_queue_push_tail (p->buffer_tail, b);

	if (!len) { /* marker for end of stream */
		p->remaining_length = 0;
	} else {
		p->remaining_length -= len;
	}
}

gboolean
http_put_done (struct http_put_s *p)
{
	EXTRA_ASSERT (p != NULL);
	return p->state == HTTP_WHOLE_FINISHED;
}

guint
http_put_get_failure_number(struct http_put_s *p)
{
	EXTRA_ASSERT(p != NULL);
	guint ret = 0;
	for (GSList *l = p->dests ; NULL != l ; l = l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state == HTTP_SINGLE_FINISHED && d->http_code / 100 != 2)
			ret++;
	}
	return ret;
}

const char *
http_put_get_header(struct http_put_s *p, gpointer k, const char *h)
{
	EXTRA_ASSERT(p != NULL);
	EXTRA_ASSERT(k != NULL);
	EXTRA_ASSERT(h != NULL);
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *dest = l->data;
		if (dest && dest->user_data == k)
			return g_hash_table_lookup(dest->response_headers, h);
	}
	return NULL;
}

guint
http_put_get_http_code(struct http_put_s *p, gpointer k)
{
	EXTRA_ASSERT(p != NULL);
	EXTRA_ASSERT(k != NULL);
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *dest = l->data;
		if (dest && dest->user_data == k)
			return dest->http_code;
	}
	return 0;
}

void
http_put_get_md5(struct http_put_s *p, guint8 *buffer, gsize size)
{
	EXTRA_ASSERT (p != NULL);
	EXTRA_ASSERT (buffer != NULL);
	memset (buffer, 0, size);
	/* TODO FIXME */
	(void)p;
}

/* -------------------------------------------------------------------------- */

static size_t
_done_reading (struct http_put_dest_s *dest, const char *why UNUSED)
{
	if (dest->buffer) {
		g_bytes_unref (dest->buffer);
		dest->buffer = NULL;
	}
	dest->state = HTTP_SINGLE_REPLY;
	GRID_TRACE("Request body completed: %s", why);
	return 0;
}

static size_t
cb_read(char *data, size_t s, size_t n, struct http_put_dest_s *dest)
{
	EXTRA_ASSERT (dest->state == HTTP_SINGLE_BEGIN || dest->state == HTTP_SINGLE_REQUEST);
	dest->state = HTTP_SINGLE_REQUEST;

	if (dest->http_put->content_length == 0)
		return _done_reading (dest, "empty body");
	if (dest->http_put->content_length > 0) {
		if (dest->bytes_sent >= dest->http_put->content_length)
			return _done_reading (dest, "body done");
	}
	if (!dest->buffer) {
		dest->state = HTTP_SINGLE_PAUSED;
		return CURL_READFUNC_PAUSE;
	}

	gsize bs = 0;
	gconstpointer b = g_bytes_get_data (dest->buffer, &bs);

	if (!b || !bs)
		return _done_reading (dest, "EOF marker");

	size_t remaining = dest->http_put->content_length - dest->bytes_sent;
	size_t max = s * n;
	size_t real = MIN(max, bs);
	real = MIN(real, remaining);

	memcpy (data, b, real);

	if (real == bs) {
		g_bytes_unref (dest->buffer);
		dest->buffer = NULL;
	} else {
		GBytes *tmp = dest->buffer;
		dest->buffer = g_bytes_new_from_bytes (tmp, real, bs - real);
		g_bytes_unref (tmp);
	}

	dest->bytes_sent += real;
	if (dest->http_put->content_length > 0) {
		if (dest->bytes_sent >= dest->http_put->content_length)
			dest->state = HTTP_SINGLE_REPLY;
	}

	GRID_TRACE2("read: %"G_GSIZE_FORMAT" avail, %"G_GSIZE_FORMAT" max,"
			" %"G_GSIZE_FORMAT" remaining, %"G_GSIZE_FORMAT" sent "
			"-> %"G_GINT64_FORMAT" total",
			bs, max, remaining, real, dest->bytes_sent);

	return real;
}

static size_t
cb_write(char *data UNUSED, size_t size, size_t nmemb, gpointer u UNUSED)
{
	return size * nmemb;
}

static size_t
cb_header(char *ptr, size_t size, size_t nmemb, void *raw_dest)
{
	EXTRA_ASSERT(ptr != NULL);
	EXTRA_ASSERT(raw_dest != NULL);

	struct http_put_dest_s *dest = raw_dest;
	int len = size * nmemb;
	gchar *header = ptr; /* /!\ not nul-terminated */
	gchar *tmp = g_strstr_len(header, len, ":");
	if (!tmp)
		return len;

	gchar *key = g_strndup(header, tmp - header);
	tmp ++; /* skip ':' */
	gchar *value = g_strndup(tmp, (header + len) - tmp);
	g_strstrip(value);
	g_hash_table_insert(dest->response_headers, key, value);
	return len;
}

static void
_start_upload(struct http_put_s *p)
{
	for (GSList *l = p->dests ; NULL != l ; l = l->next) {
		struct http_put_dest_s *dest = l->data;

		EXTRA_ASSERT (dest->state == HTTP_SINGLE_BEGIN);
		EXTRA_ASSERT (dest->http_code == 0);
		EXTRA_ASSERT (dest->bytes_sent == 0);
		EXTRA_ASSERT (dest->handle == NULL);

		dest->handle = _curl_get_handle_blob();
		EXTRA_ASSERT(dest->handle != NULL);

		curl_easy_setopt(dest->handle, CURLOPT_CONNECTTIMEOUT_MS, p->timeout_cnx);
		curl_easy_setopt(dest->handle, CURLOPT_TIMEOUT_MS, p->timeout_op);

		curl_easy_setopt(dest->handle, CURLOPT_PRIVATE, dest);
		curl_easy_setopt(dest->handle, CURLOPT_URL, dest->url);
		curl_easy_setopt(dest->handle, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(dest->handle, CURLOPT_PUT, 1L);
		if (p->content_length >= 0)
			curl_easy_setopt(dest->handle, CURLOPT_INFILESIZE_LARGE, p->content_length);
		else
			http_put_dest_add_header(dest, "Transfer-Encoding", "chunked");
		http_put_dest_add_header(dest, "Expect", " ");

		if (p->ec_handle > 0) {
			http_put_dest_add_header(dest, "Trailer",
					"X-oio-chunk-meta-metachunk-size, "
					"X-oio-chunk-meta-metachunk-hash, "
					"X-oio-chunk-meta-chunk-hash");
			// Enable if using custom curl
			curl_easy_setopt(dest->handle, CURLOPT_TRAILERDATA,
					dest);
			curl_easy_setopt(dest->handle, CURLOPT_TRAILERFUNCTION,
					http_put_ec_gen_checksums);
		}

		curl_easy_setopt(dest->handle, CURLOPT_READFUNCTION,
				(curl_read_callback)cb_read);
		curl_easy_setopt(dest->handle, CURLOPT_READDATA, dest);
		curl_easy_setopt(dest->handle, CURLOPT_WRITEFUNCTION,
				(curl_write_callback)cb_write);
		curl_easy_setopt(dest->handle, CURLOPT_HTTPHEADER, dest->curl_headers);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERFUNCTION, cb_header);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERDATA, dest);

		CURLMcode rc = curl_multi_add_handle(p->mhandle, dest->handle);
		EXTRA_ASSERT(rc == CURLM_OK);
		(void)rc;
	}
}

static void
_manage_curl_events (struct http_put_s *p)
{
	int msgs_left = 0;
	CURLMsg *msg;

	while ((msg = curl_multi_info_read(p->mhandle, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE) {
			GRID_TRACE("Unexpected CURL event");
		} else {
			CURL *easy = msg->easy_handle;
			CURLcode curl_ret = msg->data.result;
			struct http_put_dest_s *dest = NULL;

			curl_easy_getinfo(easy, CURLINFO_PRIVATE, (char**)&dest);
			EXTRA_ASSERT (easy == dest->handle);
			EXTRA_ASSERT (dest->state != HTTP_SINGLE_FINISHED);
			dest->state = HTTP_SINGLE_FINISHED;

			long http_ret;
			curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_ret);

			if (curl_ret == CURLE_OK)
				dest->http_code = http_ret;

			if (http_ret / 100 == 2) {
				GRID_TRACE("DONE [%s] code=%ld strerror=%s",
						dest->url, http_ret, curl_easy_strerror(curl_ret));
			} else {
				GRID_INFO("ERROR [%s] code=%ld strerror=%s",
						dest->url, http_ret, curl_easy_strerror(curl_ret));
			}

			CURLMcode rc = curl_multi_remove_handle(p->mhandle, dest->handle);
			EXTRA_ASSERT(rc == CURLM_OK);
			(void)rc;
			curl_easy_cleanup(dest->handle);
			dest->handle = NULL;
			g_bytes_unref(dest->buffer);
			dest->buffer = NULL;
		}
	}
}

static guint
_count_up_dests (struct http_put_s *p)
{
	guint count = 0;
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state < HTTP_SINGLE_FINISHED)
			count ++;
	}
	return count;
}

static GError *
http_put_step_classic (struct http_put_s *p)
{
	int rc;
	guint count_up = 0, count_waiting_for_data = 0;

	EXTRA_ASSERT (p != NULL);

	if (!p->dests) {
		GRID_TRACE("%s Empty upload detected", __FUNCTION__);
		p->state = HTTP_WHOLE_FINISHED;
		return NULL;
	}
	if (p->state == HTTP_WHOLE_FINISHED) {
		GRID_TRACE("%s BUG: Stepping on a finished upload", __FUNCTION__);
		return NULL;
	}

	register guint count_dests = g_slist_length(p->dests);
	GRID_TRACE("%s STEP on %u destinations", __FUNCTION__, count_dests);

	/* consume the CURL notifications for terminated actions */
	_manage_curl_events(p);

	/* Ensure the data-pipe doesn't become empty and maybe call for more */
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		count_up ++;
		if (!d->buffer && d->state < HTTP_SINGLE_FINISHED)
			count_waiting_for_data ++;
	}
	EXTRA_ASSERT(count_waiting_for_data <= count_up);
	if (count_waiting_for_data == count_up) {
		GBytes *buf = g_queue_pop_head (p->buffer_tail);
		if (buf) {
			for (GSList *l=p->dests; l ;l=l->next) {
				struct http_put_dest_s *d = l->data;
				if (d->buffer) {
					g_bytes_unref(d->buffer);
					d->buffer = NULL;
				}
				d->buffer = g_bytes_ref (buf);
			}
			g_bytes_unref (buf);
		}
	}

	if (p->state == HTTP_WHOLE_BEGIN) {
		GRID_DEBUG("%s Starting %u uploads", __FUNCTION__, count_dests);
		_start_upload(p);
		p->state = HTTP_WHOLE_READY;
	}

	/* pause CURL actions that have no data to manage immediately,
	 * and ensure the action with data ready are registered. */
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *d = l->data;
		GRID_TRACE("%s %d/%s buf=%p url=%s", __FUNCTION__,
				d->state, _single_put_state_to_string(d->state),
				d->buffer, d->url);
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		if (d->buffer) {
			if (d->state == HTTP_SINGLE_PAUSED) {
				curl_easy_pause (d->handle, CURLPAUSE_CONT);
				d->state = d->bytes_sent ? HTTP_SINGLE_REQUEST : HTTP_SINGLE_BEGIN;
			}
		}
	}

	count_up = _count_up_dests (p);
	p->state = count_up ? HTTP_WHOLE_READY : HTTP_WHOLE_PAUSED;

	GRID_TRACE("%s Uploads: %u total, %u up (%u wanted to data)",
			__FUNCTION__, count_dests, count_up, count_waiting_for_data);

	if (count_up) {
		int maxfd = -1;
		long timeout = 0;
		struct timeval tv = {1,0};
		fd_set fdread = {}, fdwrite = {}, fdexcep = {};

		curl_multi_timeout (p->mhandle, &timeout);

		/* timeout not set, libcurl recommend to wait for a few seconds */
		if (timeout < 0)
			timeout = 1000;

		/* No need to wait if actions are ready */
		if (timeout > 0) {
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout * 1000) % 1000000;
			curl_multi_fdset(p->mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

retry:
			rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &tv);
			if (rc < 0) {
				if (errno == EINTR) goto retry;
				return SYSERR("select() error: (%d) %s", errno, strerror(errno));
			}
		}
	}

	/* Do the I/O things now */
	curl_multi_perform(p->mhandle, &rc);

	if (!(count_up = _count_up_dests (p))) {
		GRID_TRACE("%s uploads finishing", __FUNCTION__);
		_manage_curl_events(p);
		p->state = HTTP_WHOLE_FINISHED;
	}

	return NULL;
}

/**
 * Mirrors the http_put_classic code, but instead of pushing the the
 * same buffer to all destinations, encodes data
 * and pushes the right fragments to the right chunks.
 *
 * @param p The metachunk upload handle
 * @return NULL if no error occured, a GError otherwise.
 */
static GError *
http_put_step_ec(struct http_put_s *p)
{

	int rc;
	guint count_up = 0, count_waiting_for_data = 0;
	EXTRA_ASSERT(p != NULL);

	if (!p->dests) {
		GRID_TRACE("%s Empty upload detected", __FUNCTION__);
		p->state = HTTP_WHOLE_FINISHED;
		return NULL;
	}
	if (p->state == HTTP_WHOLE_FINISHED) {
		GRID_TRACE("%s BUG: Stepping on a finished upload", __FUNCTION__);
		return NULL;
	}

	register guint count_dests = g_slist_length(p->dests);
	GRID_TRACE("%s STEP on %u destinations", __FUNCTION__, count_dests);

	/* consume the CURL notifications for terminated actions */
	_manage_curl_events(p);

	/* Ensure the data-pipe doesn't become empty and maybe call for more */
	for (GSList * l = p->dests; l; l = l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		count_up++;
		if (!d->buffer && d->state < HTTP_SINGLE_FINISHED)
			count_waiting_for_data++;
	}

	EXTRA_ASSERT(count_waiting_for_data <= count_up);

	// We needed to change from count_up to count_dest because we have to push
	// a new buffer to all K+M dests.
	// We could encode parts and do some magic but that is risky and unwarranted
	if (count_waiting_for_data == count_dests) {

		// Whether we reached a termination buffer at the top of the queue
		int end_of_metachunk =
				g_bytes_get_size(g_queue_peek_head(p->buffer_tail)) == 0;

		// If we have enough data available, get the data, encode it and assign
		// it to destinations.
		if (http_put_ec_enough_data_available(p->buffer_tail) ||
				end_of_metachunk) {

			// Where the magic happens.
			GBytes *fragments[p->ec_k + p->ec_m];
			GBytes *buf = NULL;
			// If we have an empty buffer at the top, push it to the cb_read
			// callbacks.
			if (end_of_metachunk) {
				buf = g_queue_pop_head(p->buffer_tail);
				for (int i = 0; i < (p->ec_m + p->ec_k); i++)
					fragments[i] = g_bytes_ref(buf);
			} else {
				// We have potentially more than EC_SEGMENT_SIZE (or EOF),
				// encode and push.
				buf = http_put_ec_get_encodable_data(p);
				http_put_ec_encode_data(p, buf, &fragments[0]);
			}

			g_bytes_unref(buf);

			// Finally, push everything.
			int fragment_index = 0;
			for (GSList * l = p->dests; l; l = l->next) {
				struct http_put_dest_s *d = l->data;
				// FIXME: Redundant verification ?
				if (d->buffer) {
					g_bytes_unref(d->buffer);
					d->buffer = NULL;
				} else {
					d->buffer = fragments[fragment_index];
					gsize data_len;
					const guchar *data =
							g_bytes_get_data(fragments[fragment_index],
							&data_len);
					if (data_len != 0)
						g_checksum_update(d->checksum_chunk, data, data_len);
				}
				fragment_index += 1;
			}
		}

	}

	if (p->state == HTTP_WHOLE_BEGIN) {
		GRID_DEBUG("%s Starting %u uploads", __FUNCTION__, count_dests);
		_start_upload(p);
		p->state = HTTP_WHOLE_READY;
	}

	/* pause CURL actions that have no data to manage immediately,
	 * and ensure the action with data ready are registered. */
	for (GSList * l = p->dests; l; l = l->next) {
		struct http_put_dest_s *d = l->data;
		GRID_TRACE("%s %d/%s buf=%p url=%s", __FUNCTION__,
				d->state, _single_put_state_to_string(d->state),
				d->buffer, d->url);
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		if (d->buffer) {
			if (d->state == HTTP_SINGLE_PAUSED) {
				curl_easy_pause(d->handle, CURLPAUSE_CONT);
				d->state =
						d->bytes_sent ? HTTP_SINGLE_REQUEST : HTTP_SINGLE_BEGIN;
			}
		}
	}

	count_up = _count_up_dests(p);
	p->state = count_up ? HTTP_WHOLE_READY : HTTP_WHOLE_PAUSED;

	GRID_TRACE("%s Uploads: %u total, %u up (%u wanted to data)",
			__FUNCTION__, count_dests, count_up, count_waiting_for_data);

	if (count_up) {
		int maxfd = -1;
		long timeout = 0;
		struct timeval tv = { 1, 0 };
		fd_set fdread = { }, fdwrite = {
		}, fdexcep = {
		};

		curl_multi_timeout(p->mhandle, &timeout);

		/* timeout not set, libcurl recommend to wait for a few seconds */
		if (timeout < 0)
			timeout = 1000;

		/* No need to wait if actions are ready */
		if (timeout > 0) {
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout * 1000) % 1000000;
			curl_multi_fdset(p->mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

retry:
			rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &tv);
			if (rc < 0) {
				if (errno == EINTR)
					goto retry;
				return SYSERR("select() error: (%d) %s", errno,
						strerror(errno));
			}
		}
	}

	/* Do the I/O things now */
	curl_multi_perform(p->mhandle, &rc);

	if (!(count_up = _count_up_dests(p))) {
		GRID_TRACE("%s uploads finishing", __FUNCTION__);
		_manage_curl_events(p);
		p->state = HTTP_WHOLE_FINISHED;
	}

	return NULL;
}

GError *
http_put_step(struct http_put_s * p)
{
	if (p->ec_handle > 0)
		return http_put_step_ec(p);
	return http_put_step_classic(p);
}

/* -------------------------------------------------------------------------- */

static const char *
_trace_tag (const curl_infotype t)
{
	switch (t) {
		case CURLINFO_TEXT:
			return "CURL:";
		case CURLINFO_HEADER_IN:
			return "CURL<";
		case CURLINFO_HEADER_OUT:
			return "CURL>";
		default:
			return NULL;
	}
}

static int
_trace(CURL *h UNUSED, curl_infotype t, char *data UNUSED, size_t size UNUSED,
		void *u UNUSED)
{
	GString *tmp = g_string_new("");
	for (; size>0 ;++data,--size) {
		if (g_ascii_isprint(*data) && !g_ascii_isspace(*data)) {
			g_string_append_c (tmp, *data);
		} else {
			g_string_append_c (tmp, ' ');
		}
	}

	const char *tag = _trace_tag(t);
	if (tag) {
		GRID_TRACE2("%s %.*s", tag, (int)tmp->len, tmp->str);
	}
	g_string_free (tmp, TRUE);
	return 0;
}

static int
_curl_set_sockopt_common (void *u UNUSED, curl_socket_t fd, curlsocktype event)
{
	if (event == CURLSOCKTYPE_IPCXN) {
		int opt = 1;
		setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(opt));
#ifdef SO_REUSEPORT
		opt = 1;
		setsockopt (fd, SOL_SOCKET, SO_REUSEPORT, (void*)&opt, sizeof(opt));
#endif
	}
	return CURL_SOCKOPT_OK;
}

static int
_curl_set_sockopt_blob (void *u, curl_socket_t fd, curlsocktype event)
{
	_curl_set_sockopt_common (u, fd, event);
	if (event == CURLSOCKTYPE_IPCXN) {
		struct linger ls = {.l_onoff=1, .l_linger=1};
		setsockopt (fd, SOL_SOCKET, SO_LINGER, (void*)&ls, sizeof(ls));
	}
	return CURL_SOCKOPT_OK;
}

/* Overrides the default setsockopt() for proxy connections.
 * SO_LINGER is now set. */
static int
_curl_set_sockopt_proxy (void *u, curl_socket_t fd, curlsocktype event)
{
	_curl_set_sockopt_common (u, fd, event);
	if (event == CURLSOCKTYPE_IPCXN) {
		int opt = 1;
		setsockopt (fd, IPPROTO_TCP, TCP_NODELAY, (void*)&opt, sizeof(opt));
		struct linger ls = {.l_onoff=1, .l_linger=0};
		setsockopt (fd, SOL_SOCKET, SO_LINGER, (void*)&ls, sizeof(ls));
	}
	return CURL_SOCKOPT_OK;
}

CURL *
_curl_get_handle_blob (void)
{
	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_FORBID_REUSE, 1L);
	curl_easy_setopt (h, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt (h, CURLOPT_FRESH_CONNECT, 1L);
	curl_easy_setopt (h, CURLOPT_USERAGENT, oio_core_http_user_agent);
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_PROXY, "");
	curl_easy_setopt (h, CURLOPT_SOCKOPTDATA, NULL);
	curl_easy_setopt (h, CURLOPT_SOCKOPTFUNCTION, _curl_set_sockopt_blob);
	if (oio_socket_rawx_buflen > 0) {
		unsigned long opt = oio_socket_rawx_buflen;
		curl_easy_setopt (h, CURLOPT_BUFFERSIZE, opt);
	}
	if (GRID_TRACE2_ENABLED()) {
		curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
		curl_easy_setopt (h, CURLOPT_VERBOSE, 1L);
	}
	return h;
}

CURL *
_curl_get_handle_proxy (void)
{
	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_USERAGENT, oio_core_http_user_agent);
	curl_easy_setopt (h, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt (h, CURLOPT_TCP_NODELAY, 1L);
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_PROXY, "");
	curl_easy_setopt (h, CURLOPT_FORBID_REUSE, 0L);
	curl_easy_setopt (h, CURLOPT_FRESH_CONNECT, 0L);
	curl_easy_setopt (h, CURLOPT_SOCKOPTDATA, NULL);
	curl_easy_setopt (h, CURLOPT_SOCKOPTFUNCTION, _curl_set_sockopt_proxy);
	if (oio_socket_proxy_buflen > 0) {
		unsigned long opt = oio_socket_proxy_buflen;
		curl_easy_setopt (h, CURLOPT_BUFFERSIZE, opt);
	}
	if (GRID_TRACE2_ENABLED()) {
		curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
		curl_easy_setopt (h, CURLOPT_VERBOSE, 1L);
	}
	return h;
}

