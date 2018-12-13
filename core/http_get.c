/*
OpenIO SDS core library
Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS

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

#include <core/http_get.h>

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <math.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <glib/gstdio.h>
#include <curl/curl.h>
#include <curl/multi.h>
#include <erasurecode.h>

#include <core/client_variables.h>
#include <core/oioext.h>
#include <core/oiolog.h>
#include <core/http_put.h>		// Needed for http_put_get_fragment_length

#include "internals.h"
#include "http_internals.h"

//FIXME: Three definitions of segment size ....
#define EC_SEGMENT_SIZE 1048576


/**
 * Trying to mirror the http_put API. Some code leech is necessary.
 * Code Leech Simulator 2018
 */

/**
 * Chunk download status.
 */
enum http_get_req_status
{
	HTTP_GET_REQ_INITIALIZED = 0,
	HTTP_GET_REQ_FINISHED
};

/**
 * Metachunk download status
 */
enum http_get_status
{
	HTTP_GET_INITIALIZED = 0,
	HTTP_GET_TRANSFER_DONE,
	HTTP_GET_FINISHED
};

struct http_get_range
{
	gint64 offset;
	gint64 length;
};

struct http_get_s
{

	// A list of http_get_req_s each representing a chunk
	GSList *chunks;

	// cURL-multi handle
	CURLM *mhandle;

	// Timeouts in milliseconds
	long timeout_cnx;
	long timeout_op;

	// Received parts of the meta-chunk.
	// In the case of EC, each reconstructed segment is pushed here.
	GQueue *buffer_queue;

	// Current meta-chunk size
	gint64 metachunk_size;

	// Current chunk size
	gint64 chunk_size;

	// The range of user data to be fetched from this meta-chunk.
	struct http_get_range *mc_range;

	// The range of rawx data to be fetched in each chunk.
	struct http_get_range c_range;

	// The final range to be pulled from the decoded data
	struct http_get_range f_range;

	// Current meta-chunk download status.
	enum http_get_status status;

	// EC parameters.
	int ec_k, ec_m, ec_handle;

};

struct http_get_req_s
{

	// Back pointer to the meta-chunk download handle.
	struct http_get_s *mc_download_handle;

	// RAWX chunk URI
	gchar *url;

	// cURL handle
	CURL *handle;

	// Needed for EC. Buffer each chunk separately, then aggregate
	// after decoding.
	GQueue *buffer_tail;

	// Response headers, needed ?
	GHashTable *response_headers;

	// HTTP stuff
	enum http_get_req_status req_status;

	// Required to cleanup headers later.
	struct oio_headers_s headers;
};

struct http_get_range *
http_get_range_convert(const struct oio_sds_dl_range_s *rng)
{
	struct http_get_range *new_rng = g_malloc0(sizeof(struct http_get_range));
	new_rng->offset = rng->offset;
	new_rng->length = rng->size;
	return new_rng;
}

/**
 * There's a problem with libec_get_fragment_size where it returns a 80-bytes
 * short length. So this is a hack around that problem.
 * @param ec_handle The liberasurecode handle that was created for the request.
 * @return The fragment size after encoding.
 */
int
http_get_ec_get_fragment_size(int ec_handle, int data_len)
{
	// We'll never try to encode a 0 sized buffer.
	g_assert(data_len > 0);
	// We need a valid handle.
	g_assert(ec_handle > 0);
	char **data_frags = NULL;
	char **parity_frags = NULL;
	uint64_t frag_length = 0;
	char *dummy_data = g_malloc0(data_len);
	int res = liberasurecode_encode(ec_handle, dummy_data, data_len,
			&data_frags, &parity_frags, &frag_length);
	// FIXME: Handle errors at this stage.
	g_assert(res == 0);
	g_free(dummy_data);
	liberasurecode_encode_cleanup(ec_handle, data_frags, parity_frags);
	return frag_length;
}

/**
 * A wrapper around http_get_ec_get_fragment size that extracts
 * the necessary data from the mc handler.
 * @param mc The meta-chunk handler
 * @return The usual fragment size after encoding.
 */
static int
http_get_ec_get_fragment_size_for_mc(struct http_get_s *mc)
{
	// We need a valid handle.
	EXTRA_ASSERT(mc->ec_handle > 0);
	int data_len =
			mc->metachunk_size > EC_SEGMENT_SIZE ?
			EC_SEGMENT_SIZE : mc->metachunk_size;
	return http_get_ec_get_fragment_size(mc->ec_handle, data_len);
}

/**
 * cURL WRITEFUNCTION callback, called every time new data is received.
 * All we do is push the buffer into the chunk handle buffer tail.
 */
static size_t
http_get_write_callback(char *data, size_t num, size_t length,
		struct http_get_req_s *chunk)
{
	g_queue_push_tail(chunk->buffer_tail, g_bytes_new(data, length * num));
	return num * length;
}

/**
 * Dummy cURL READFUNCTION callback stub.
 */
static size_t
http_get_read_callback(char *data UNUSED, size_t s UNUSED, size_t n UNUSED,
		void *chunk UNUSED)
{
	return 0;
}

/**
 * cURL HEADERFUNCTION callback stub.
 */
static size_t
http_get_header_callback(char *data, size_t s, size_t n,
		struct http_get_req_s *chunk)
{
	EXTRA_ASSERT(data != NULL);
	EXTRA_ASSERT(chunk != NULL);

	int len = s * n;
	gchar *header = data;		/* /!\ not nul-terminated */
	gchar *tmp = g_strstr_len(header, len, ":");
	if (!tmp)
		return len;

	gchar *key = g_strndup(header, tmp - header);
	tmp++;						/* skip ':' */
	gchar *value = g_strndup(tmp, (header + len) - tmp);
	g_strstrip(value);
	g_hash_table_insert(chunk->response_headers, key, value);
	return len;
}

struct http_get_s *
http_get_create_with_ec(gint64 mc_size, gint64 c_size,
		struct http_get_range *req_range, int ec_k, int ec_m, int ec_handle)
{
	// We proceed by EC_SEGMENT_SIZE, so we need to locate to which subset of
	// EC_SEGMENT_SIZE does this req_range belong.

	int adjust_for_mc_end = 0;

	int first_segment_number = (int) req_range->offset / EC_SEGMENT_SIZE;

	int last_segment_number =
			(int) (req_range->offset + req_range->length) / EC_SEGMENT_SIZE;

	if ((req_range->offset + req_range->length) % EC_SEGMENT_SIZE != 0)
		last_segment_number += 1;

	// If we're getting something near the end, and the meta-chunk size
	// can't be laid out in EC_SEGMENT_SIZE sized chunks, we need
	// to adjust for
	int val1 = (int) (req_range->offset + req_range->length);
	int val2 = (last_segment_number - first_segment_number) * EC_SEGMENT_SIZE;
	if (val1 < val2 && val1 == mc_size)
		adjust_for_mc_end = 1;

	// Cleanup is done in http_get_destroy
	struct http_get_s *mc_handle = g_try_malloc0(sizeof(struct http_get_s));
	mc_handle->status = HTTP_GET_INITIALIZED;
	mc_handle->ec_handle = ec_handle;
	mc_handle->ec_k = ec_k;
	mc_handle->ec_m = ec_m;
	mc_handle->buffer_queue = g_queue_new();
	mc_handle->chunk_size = c_size;
	mc_handle->metachunk_size = mc_size;
	mc_handle->mc_range = req_range;
	mc_handle->timeout_cnx = oio_client_rawx_timeout_cnx * 1000L;
	mc_handle->timeout_op = oio_client_rawx_timeout_req * 1000L;
	mc_handle->mhandle = curl_multi_init();
	mc_handle->chunks = g_slist_alloc();

	int normal_fragment_length =
			http_get_ec_get_fragment_size_for_mc(mc_handle);
	int final_fragment_length = normal_fragment_length;
	if (adjust_for_mc_end)
		final_fragment_length =
				http_get_ec_get_fragment_size(mc_handle->ec_handle,
				mc_size % EC_SEGMENT_SIZE);

	if (mc_size < EC_SEGMENT_SIZE)
		mc_handle->chunk_size = normal_fragment_length;

	// Now that we have the segment number, the offset for the RAWX chunks
	// is first_segment_number*fragment_size
	struct http_get_range raw_range;
	raw_range.offset = first_segment_number * normal_fragment_length;
	if (!adjust_for_mc_end)
		raw_range.length = last_segment_number * normal_fragment_length;
	else
		raw_range.length = (last_segment_number - 1) * normal_fragment_length +
				final_fragment_length;

	// While we're at it, specify the final slicing range,
	// since we'll be pulling whole segments from the chunks.
	struct http_get_range final_range;
	final_range.offset =
			req_range->offset - EC_SEGMENT_SIZE * first_segment_number;
	final_range.length = req_range->length;

	mc_handle->f_range = final_range;
	mc_handle->c_range = raw_range;

	return mc_handle;
}

void
http_get_add_chunk(struct http_get_s *mc_handle, gchar * url)
{
	// Init the chunk handle
	struct http_get_req_s *chunk = g_try_malloc0(sizeof(struct http_get_req_s));
	chunk->req_status = HTTP_GET_REQ_INITIALIZED;
	chunk->buffer_tail = g_queue_new();
	chunk->mc_download_handle = mc_handle;
	chunk->url = url;
	chunk->response_headers = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, g_free);

	// Add it to the metachunk handle
	mc_handle->chunks = g_slist_append(mc_handle->chunks, chunk);

	// Initiate cURL handle
	// TODO: Check if some curl flags need to be tweaked in download mode
	chunk->handle = _curl_get_handle_blob();

	curl_easy_setopt(chunk->handle, CURLOPT_CONNECTTIMEOUT_MS,
			mc_handle->timeout_cnx);
	curl_easy_setopt(chunk->handle, CURLOPT_TIMEOUT_MS, mc_handle->timeout_op);
	curl_easy_setopt(chunk->handle, CURLOPT_PRIVATE, chunk);
	curl_easy_setopt(chunk->handle, CURLOPT_URL, chunk->url);
	curl_easy_setopt(chunk->handle, CURLOPT_READFUNCTION,
			(curl_read_callback) http_get_read_callback);
	curl_easy_setopt(chunk->handle, CURLOPT_WRITEFUNCTION,
			(curl_write_callback) http_get_write_callback);
	curl_easy_setopt(chunk->handle, CURLOPT_WRITEDATA, chunk);
	curl_easy_setopt(chunk->handle, CURLOPT_HEADERFUNCTION,
			http_get_header_callback);
	curl_easy_setopt(chunk->handle, CURLOPT_HEADERDATA, chunk);

	// Set headers
	gchar str_range[64] = "";
	g_snprintf(str_range, sizeof(str_range),
			"bytes=%" G_GSIZE_FORMAT "-%" G_GSIZE_FORMAT,
			mc_handle->c_range.offset,
			mc_handle->c_range.offset + mc_handle->c_range.length - 1);

	oio_headers_common(&chunk->headers);
	oio_headers_add(&chunk->headers, "Range", str_range);
	curl_easy_setopt(chunk->handle, CURLOPT_HTTPHEADER, chunk->headers.headers);

	// Add to cURL multi.

	CURLMcode rc = curl_multi_add_handle(mc_handle->mhandle, chunk->handle);
	(void) rc;
	EXTRA_ASSERT(rc == CURLM_OK);

	return;
}

static void
http_get_clean_chunk(gpointer * ptr)
{
	struct http_get_req_s *chunk = (struct http_get_req_s *) ptr;

	if (ptr == NULL)
		return;

	if (chunk->response_headers)
		g_hash_table_destroy(chunk->response_headers);
	// This is normally done on in http_get_manage_curl_events, but it's here
	// in case the request doesn't end gracefully at which point the appropriate
	// cleanup isn't done.
	if (chunk->handle) {
		CURLMcode rc;
		rc = curl_multi_remove_handle(chunk->mc_download_handle->mhandle,
				chunk->handle);
		EXTRA_ASSERT(rc == CURLM_OK);
		(void) rc;
		curl_easy_cleanup(chunk->handle);
	}
	if (chunk->buffer_tail)
		g_queue_free(chunk->buffer_tail);

	// Cleanup headers.
	oio_headers_clear(&chunk->headers);

	g_free(chunk);
}

void
http_get_clean_mc_handle(struct http_get_s *mc)
{
	// First free the chunk handles and then the meta-chunk handle itself,
	// including the EC handle.
	g_slist_free_full(mc->chunks, (GDestroyNotify) http_get_clean_chunk);

	//FIXME: Handle potential destruction errors.
	if (mc->ec_handle) {
		int res = liberasurecode_instance_destroy(mc->ec_handle);
		g_assert(res == 0);
	}
	if (mc->buffer_queue)
		g_queue_free(mc->buffer_queue);
	if (mc->mc_range)
		g_free(mc->mc_range);
	if (mc->mhandle)
		curl_multi_cleanup(mc->mhandle);
	g_free(mc);
}

/**
 * Parse any possible cURL events, and handle the ones that arise, mainly
 * declaring finished transfers as finished and emitting an error
 * if one is detected.
 * @param mc The meta-chunk download handle.
 * @return NULL if no error occured, a GError otherwise.
 */
static GError *
http_get_manage_curl_events(struct http_get_s *mc)
{
	if (mc->status == HTTP_GET_FINISHED)
		return NULL;

	int msgs_left = 0;
	CURLMsg *msg = NULL;

	GError *err = NULL;

	while ((msg = curl_multi_info_read(mc->mhandle, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE)
			err = NEWERROR(CODE_NETWORK_ERROR,
					"[http_get_manage_curl_events] Unexpected cURL "
					"event ! : %d", msg->msg);
		else {
			CURL *handle = msg->easy_handle;

			struct http_get_req_s *chunk = NULL;
			curl_easy_getinfo(handle, CURLINFO_PRIVATE, &chunk);
			EXTRA_ASSERT(chunk->handle == handle);
			chunk->req_status = HTTP_GET_REQ_FINISHED;

			long http_code;
			curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);

			if (http_code != 200 && http_code != 206)
				err = NEWERROR(CODE_NETWORK_ERROR,
						"[http_get_manage_curl_events] Unexpected "
						"response code! : %d", (int) http_code);

			CURLMcode rc = curl_multi_remove_handle(mc->mhandle, handle);
			EXTRA_ASSERT(rc == CURLM_OK);
			(void) rc;

			curl_easy_cleanup(handle);
			chunk->handle = NULL;

			// Push a termination buffer
			g_queue_push_tail(chunk->buffer_tail, g_bytes_new_static("", 0));
		}
	}
	return err;
}

/**
 * Returns the number of finished chunks.
 * @param mc The metachunk download handle.
 * @return The number of finished chunks.
 */
static int
http_get_count_finished_chunks(struct http_get_s *mc)
{
	int count = 0;
	for (GSList * l = mc->chunks->next; l; l = l->next) {
		struct http_get_req_s *chunk = l->data;
		if (chunk->req_status == HTTP_GET_REQ_FINISHED)
			count++;
	}
	if (count == (int) g_slist_length(mc->chunks) - 1)
		if (mc->status == HTTP_GET_INITIALIZED)
			mc->status = HTTP_GET_TRANSFER_DONE;
	return count;
}


/**
 * Computes the total number of bytes present in a buffer queue.
 * @param buf_queue A GQueue of GByte *
 * @return The total of bytes present in the buffer queue.
 */
static int
http_get_buffer_queue_length(GQueue * buf_queue)
{
	if (buf_queue == NULL)
		return 0;
	int buf_len = 0;
	int qlen = g_queue_get_length(buf_queue);
	for (int i = 0; i < qlen; i++) {
		buf_len += g_bytes_get_size(g_queue_peek_nth(buf_queue, i));
	}
	return buf_len;
}

/**
 * Goes through the metachunk handle's chunk handles, and computes wether we
 * have at least a fragment_size worth of data in all chunks.
 *
 * @param mc The metachunk download handle.
 * @return TRUE if data is available, FALSE otherwise.
 */
static int
http_get_enough_data_available(struct http_get_s *mc)
{
	// For some reason the NULL element is counted in g_slist_length so this
	// hack is used. There has to be a better way to do things
	int transfers_finished =
			http_get_count_finished_chunks(mc) ==
			(int) g_slist_length(mc->chunks) - 1;

	int enough_data_avail = 1,
			frag_size = http_get_ec_get_fragment_size_for_mc(mc);

	// Enough data is available when:
	// - We have received at least frag_size from all chunks
	// OR
	// - All chunks have finished and we have termination buffers.

	if (transfers_finished)
		return enough_data_avail;

	for (GSList * el = mc->chunks->next; el; el = el->next) {
		struct http_get_req_s *chunk = el->data;
		int chunk_queue_length =
				http_get_buffer_queue_length(chunk->buffer_tail);
		if ((chunk_queue_length < frag_size && !transfers_finished)
				|| (transfers_finished && chunk_queue_length == 0)) {
			enough_data_avail = 0;
			break;
		}
	}
	return enough_data_avail;
}

/**
 * Concatenates the buffer queue into one GBytes instance for easier slicing.
 * @param buf_queue The buffer queue to concatenate
 * @return A GBytes pointer
 */
static GBytes *
http_get_concat_buffer(struct http_get_s *mc UNUSED,
		GQueue * buf_queue, gsize * full_buf_size)
{

	unsigned int buf_len = 0;
	GByteArray *buf_builder = g_byte_array_new();

	GBytes *head = NULL;
	gsize head_len = 0;
	while ((head = g_queue_pop_head(buf_queue))) {
		head_len = g_bytes_get_size(head);
		if (head_len != 0) {
			buf_len += head_len;
			g_byte_array_append(buf_builder,
					(const guint8 *) g_bytes_get_data(head, 0), head_len);
			g_bytes_unref(head);
		} else {
			// We no longer need to pop and we have a termination buffer
			g_bytes_unref(head);
			break;
		}
	}

	if (full_buf_size)
		*full_buf_size = buf_len;

	return g_byte_array_free_to_bytes(buf_builder);
}

/**
 * Returns a decodable amount of data from the buffer queue.
 *
 * Computes the available number of fragments and returns a GBytes array of
 * decodable fragments. If EOF is TRUE, returns everything available
 * in the buffer.
 *
 * @param mc The meta-chunk download handle.
 * @param eof If we reached the end of the meta-chunk download
 * @return
 */
static GBytes **
http_get_ec_get_decodable_data(struct http_get_s *mc, int eof,
		GBytes ** fragments)
{
	int fragment_size = http_get_ec_get_fragment_size_for_mc(mc);

	// First we need to determine the maximum size we can read,
	// i.e. the minimum readable size in all chunks.
	int min_size = INT_MAX, max_size = 0;
	for (GSList * el = mc->chunks->next; el; el = el->next) {
		struct http_get_req_s *chunk = el->data;
		int buf_len = http_get_buffer_queue_length(chunk->buffer_tail);
		int size_to_return =
				eof ? buf_len : (buf_len / fragment_size) * fragment_size;
		min_size = min_size < size_to_return ? min_size : size_to_return;
		max_size = max_size > size_to_return ? max_size : size_to_return;
	}

	// If we reached EOF, then all chunks should have the same size left in them
	// FIXME: Modify this to have it return a GError so we can handle this
//  if (eof && min_size != max_size)


	// Now to actually fetch the data
	int chunk_id = 0;
	for (GSList * el = mc->chunks->next; el; el = el->next) {
		struct http_get_req_s *chunk = el->data;
		gsize full_buf_len;
		GBytes *full_buf =
				http_get_concat_buffer(mc, chunk->buffer_tail, &full_buf_len);
		fragments[chunk_id] = g_bytes_new_from_bytes(full_buf, 0, min_size);
		if ((int) full_buf_len != min_size)
			g_queue_push_head(chunk->buffer_tail,
					g_bytes_new_from_bytes(full_buf, min_size,
							full_buf_len - min_size));
		g_bytes_unref(full_buf);
		chunk_id += 1;
	}
	return &fragments[0];
}

/**
 * Decodes the data available in the encoded_data buffer array.
 * @param mc The meta-chunk download handle.
 * @param encoded_data The encoded data buffers.
 * @return The decoded original data.
 */
static GError *
http_get_ec_decode_data(struct http_get_s *mc, GBytes ** encoded_data,
		GBytes ** result)
{
	g_assert_true(mc->ec_handle > 0);
	int std_fragment_size = http_get_ec_get_fragment_size_for_mc(mc);
	// We assume that all the buffers have the same length, as otherwise it
	// would not work.
	int bytes_left = g_bytes_get_size(encoded_data[0]);

	GByteArray *final_arr = g_byte_array_new();

	char *decoded_data = NULL;
	char *raw_fragments[mc->ec_m + mc->ec_k];
	int num_fragments = mc->ec_m + mc->ec_k;
	int next_frag_len;
	gsize decoded_data_len;

	// Convert the GBytes to normal C strings
	for (int i = 0; i < mc->ec_m + mc->ec_k; i++) {
		raw_fragments[i] = (char *) g_bytes_get_data(encoded_data[i], 0);
	}

	// Start decoding
	while (bytes_left > 0) {
		next_frag_len =
				bytes_left >=
				std_fragment_size ? std_fragment_size : bytes_left;
		int res = liberasurecode_decode(mc->ec_handle, raw_fragments,
				num_fragments, next_frag_len, 0,
				&decoded_data, &decoded_data_len);
		g_assert(res == 0);
		g_byte_array_append(final_arr, (const guint8 *) decoded_data,
				decoded_data_len);
		liberasurecode_decode_cleanup(mc->ec_handle, decoded_data);
		bytes_left -= next_frag_len;
	};

	// Free the buffers
	for (int i = 0; i < mc->ec_m + mc->ec_k; i++) {
		g_bytes_unref(encoded_data[i]);
	}

	*result = g_byte_array_free_to_bytes(final_arr);
	return NULL;
}

GError *
http_get_process_metachunk_range(struct http_get_s * mc, GBytes ** result)
{
	// FIXME: Pass the FILE descriptor and write to it as soon as possible
	int eof = 0;
	GError *err = NULL;
	while (mc->status != HTTP_GET_FINISHED) {
		// See if any of the requests finished
		err = http_get_manage_curl_events(mc);
		if (err)
			return err;

		http_get_count_finished_chunks(mc);

		// Have all the transfers ended ?
		eof = mc->status == HTTP_GET_TRANSFER_DONE;

		// If we have enough data to start decoding, do just that.
		int enough_data_avail = http_get_enough_data_available(mc);
		if (enough_data_avail) {
			GBytes *decodable_fragments[mc->ec_m + mc->ec_k];
			for (int i = 0; i < mc->ec_m + mc->ec_k; i++)
				decodable_fragments[i] = NULL;
			// Cleanup of the fragments is done inside http_get_ec_decode_data
			http_get_ec_get_decodable_data(mc, eof, &decodable_fragments[0]);
			GBytes *res = NULL;
			http_get_ec_decode_data(mc, decodable_fragments, &res);
			g_queue_push_tail(mc->buffer_queue, res);
		}
		// Have all the transfers ended ?
		eof = mc->status == HTTP_GET_TRANSFER_DONE;

		if (eof) {
			mc->status = HTTP_GET_FINISHED;
			break;
		}
		// libcURL multi select interface stuff.
		int rc;
		int maxfd = -1;
		long timeout = 0;
		struct timeval tv = { 1, 0 };
		fd_set fdread = { }, fdwrite = {
		}, fdexcep = {
		};

		curl_multi_timeout(mc->mhandle, &timeout);

		/* timeout not set, libcurl recommend to wait for a few seconds */
		if (timeout < 0)
			timeout = 1000;

		/* No need to wait if actions are ready */
		if (timeout > 0) {
			tv.tv_sec = timeout / 1000;
			tv.tv_usec = (timeout * 1000) % 1000000;
			curl_multi_fdset(mc->mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

retry:
			rc = select(maxfd + 1, &fdread, &fdwrite, &fdexcep, &tv);
			if (rc < 0) {
				if (errno == EINTR)
					goto retry;
				return SYSERR("select() error: (%d) %s", errno,
						strerror(errno));
			}
		}

		curl_multi_perform(mc->mhandle, &rc);

		err = http_get_manage_curl_events(mc);
		if (err)
			return err;
	}

	if (eof) {
		// The full meta-chunk range decoded.
		gsize len;
		GBytes *intermediate_result = http_get_concat_buffer(mc,
				mc->buffer_queue, &len);
		g_assert_true((int) len >= mc->f_range.length);
		result[0] = g_bytes_new_from_bytes(intermediate_result,
				mc->f_range.offset, mc->f_range.length);
		g_bytes_unref(intermediate_result);
		return NULL;
	}

	return err;
}
