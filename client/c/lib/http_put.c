#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "http.put"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include <glib.h>
#include <glib/gprintf.h>

#include <curl/curl.h>
#include <curl/multi.h>

#include "gs_internals.h"
#include "grid_client.h"
#include "http_put.h"


struct http_put_dest_s
{
	gboolean success;
	gchar *url;
	CURL *handle;
	size_t cursor;	/* cursor on http_put->buffer */

	/* Headers to send in the put request */
	GSList *headers;
	struct curl_slist *curl_headers;

	/* Headers from the response */
	GHashTable *response_headers;

	/* HTTP error code (valid if success == 1) */
	guint http_code;

	/* user data corresponding to this destination */
	gpointer user_data;

	struct http_put_s *http_put;	/* backpointer */
};

struct http_put_s
{
	/* list of destinations (rawx, rainx)*/
	GSList *dests;

	/* [dest->user_data, dest], ...
	 * Used to get dest quickly from dest->user_data
	 */
	GHashTable *id2dests;

	int is_running;
	CURLM *mhandle;

	long timeout_cnx;
	long timeout_op;

	/* callback to read data from client */
	http_put_input_f cb_input;
	gpointer cb_input_data;

	gchar *buffer;			/* full content */
	gsize buffer_length;	/* content size */
	gsize buffer_filled;	/* content already read from client */
};

void __attribute__ ((constructor)) init_curl(void)
{
	/* With NSS, all internal data are not correctly freed at
	 * the end of the program... and we don't use ssl so we don't need it.
	 */
	curl_global_init(CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL);
}

void __attribute__ ((destructor)) destroy_curl(void)
{
	curl_global_cleanup();
}


struct http_put_s *
http_put_create(http_put_input_f cb_input, gpointer cb_input_data, size_t data_length, long timeout_cnx, long timeout_op)
{
	struct http_put_s *p;
	p = g_malloc0(sizeof(struct http_put_s));
	p->dests = NULL;
	p->id2dests = g_hash_table_new(g_direct_hash, g_direct_equal);
	p->mhandle = curl_multi_init();
	p->cb_input = cb_input;
	p->cb_input_data = cb_input_data;
	p->buffer = g_malloc0(data_length);
	p->buffer_length = data_length;
	p->buffer_filled = 0;
	p->timeout_cnx = timeout_cnx;
	p->timeout_op = timeout_op;
	return p;
}

struct http_put_dest_s *http_put_add_dest(struct http_put_s *p, const gchar *url, gpointer user_data)
{
	struct http_put_dest_s *dest;

	g_assert(p != NULL);
	g_assert(url != NULL);
	g_assert(user_data != NULL);

	dest = g_malloc0(sizeof(struct http_put_dest_s));

	dest->url = g_strdup(url);
	dest->success = FALSE;
	dest->handle = NULL;
	dest->cursor = 0;
	dest->http_put = p;

	dest->user_data = user_data;

	dest->headers = NULL;
	dest->curl_headers = NULL;

	dest->response_headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	dest->http_code = 0;

	p->dests = g_slist_append(p->dests, dest);

	g_assert(g_hash_table_lookup(p->id2dests, user_data) == NULL);
	g_hash_table_insert(p->id2dests, user_data, dest); 

	/* Remove default header added automatically by libcurl as
	 * in integrity/http_pipe.c
	 */
	http_put_dest_add_header(dest, "Expect", " ");

	return dest;
}

void http_put_dest_add_header(struct http_put_dest_s *dest, const gchar *key, const gchar *val_fmt, ...)
{
	gchar *header;
	va_list ap;
	gchar *val;

	g_assert(dest != NULL);
	g_assert(key != NULL);
	g_assert(val_fmt != NULL);

	va_start(ap, val_fmt);
	g_vasprintf(&val, val_fmt, ap);
	va_end(ap);

	header = g_strdup_printf("%s: %s", key, val);
	g_free(val);

	dest->headers = g_slist_prepend(dest->headers, header);

	dest->curl_headers = curl_slist_append(dest->curl_headers, header);
}

static void http_put_dest_destroy(gpointer destination)
{
	struct http_put_dest_s *dest = destination;
	CURLMcode rc;

	g_assert(dest != NULL);

	if (dest->url)
		g_free(dest->url);
	if (dest->handle)
	{
		rc = curl_multi_remove_handle(dest->http_put->mhandle, dest->handle);
		g_assert(rc == CURLM_OK);
		curl_easy_cleanup(dest->handle);
	}
	if (dest->headers)
		g_slist_free_full(dest->headers, g_free);
	if (dest->curl_headers)
		curl_slist_free_all(dest->curl_headers);
	if (dest->response_headers)
		g_hash_table_destroy(dest->response_headers);
	g_free(dest);
}

void http_put_clear_dests(struct http_put_s *p)
{
	if (p->id2dests)
		g_hash_table_remove_all(p->id2dests);
	if (p->dests)
		g_slist_free_full(p->dests, http_put_dest_destroy);
	p->dests = NULL;
}

void http_put_destroy(struct http_put_s *p)
{
	g_assert(p != NULL);

	http_put_clear_dests(p);
	if (p->id2dests)
		g_hash_table_destroy(p->id2dests);
	if (p->mhandle)
		curl_multi_cleanup(p->mhandle);
	if (p->buffer)
		g_free(p->buffer);
	g_free(p);
}

/* 
 * Check number of bytes available if the main buffer for this destination.
 * If there is less data available than max, it tries to retrieve
 * data from client to fill the main buffer.
 * Finally, it returns the number of bytes available in the main buffer
 * for this destination which can be less or greater than max.
 * It returns -1 in case of error with client.
 */
static ssize_t _data_ready(size_t max, struct http_put_dest_s *dest)
{
	ssize_t res;
	size_t dest_max_read, dest_available_read;
	struct http_put_s *http_put = dest->http_put;

	//buffer_free_space = http_put->buffer_length - http_put->buffer_filled;
	dest_max_read = MIN(max, http_put->buffer_length - dest->cursor);
	dest_available_read = http_put->buffer_filled - dest->cursor;

	/*
	 *    <--------------------http_put->buffer_length----------------->
	 *    <--------http_put->buffer_filled-------->
	 *    <-dest->cursor->
	 *    #########################################000000000000000000000
	 *                    <-----------------------max----------------------...>
	 *                                             <-buffer_free_space->
	 *                    <--------------dest_max_read----------------->
	 *                    <--dest_available_read-->
	 *
	 *
	 *    <--------------------http_put->buffer_length----------------->
	 *    <--------http_put->buffer_filled-------->
	 *    <-dest->cursor->
	 *    #########################################000000000000000000000
	 *                    <-------------max---------------->
	 *                                             <-buffer_free_space->
	 *                    <--------dest_max_read----------->
	 *                    <--dest_available_read-->
	 */

	if (dest_max_read > dest_available_read)
	{
		/* we need to read data from client */
		res = dest->http_put->cb_input(http_put->cb_input_data,
				http_put->buffer + http_put->buffer_filled,
				dest_max_read - dest_available_read);
		if (res < 0 || res == 0) {
			/* if res == 0, client didn't send as many data as the content
			 * lenght so it's an error.
			 */
			return -1;
		}

		/* we read res bytes from client */
		http_put->buffer_filled += res;
	}

	return http_put->buffer_filled - dest->cursor;
}

static size_t
cb_read(void *data, size_t s, size_t n, struct http_put_dest_s *dest)
{
	ssize_t max = s * n;
	ssize_t data_ready;
	size_t data_to_read;

	data_ready = _data_ready(max, dest);
	if (data_ready < 0)
	{
		GRID_DEBUG("Failed to read bytes from client (wanted==%zd, res==%zd)",
				max, data_ready);
		return CURL_READFUNC_ABORT;
	}

	data_to_read = MIN(max, data_ready);
	memcpy(data, dest->http_put->buffer + dest->cursor, data_to_read);

	dest->cursor += data_to_read;

	TRACE("Read %zu bytes for %s (Data ready %zd)",
			data_to_read, dest->url, data_ready);

	return data_to_read;
}

static size_t
cb_write(void *data, size_t size, size_t nmemb, gpointer nothing)
{
	(void)data;
	(void)nothing;
	/* To avoid default behavior (print html to stdout),
	 * we need to implement this function which do nothing.
	 */
	return size * nmemb;
}

static size_t cb_header(void *ptr, size_t size, size_t nmemb, struct http_put_dest_s *dest)
{
	gchar *header, *key, *value, *tmp;
	int len;

	g_assert(ptr != NULL);
	g_assert(dest != NULL);

	header = ptr; /* /!\ not nul-terminated */
	len = size * nmemb;

	TRACE("header [%.*s] len %d", len, header, len);

	tmp = g_strstr_len(header, len, ":");
	if (tmp == NULL)
	{
		/* Not a key: value, skip it */
		return len;
	}

	key = g_strndup(header, tmp - header);
	tmp++; /* skip ':' */
	value = g_strndup(tmp, (header + len) - tmp);

	g_strstrip(value);

	g_hash_table_insert(dest->response_headers, key, value);

	TRACE("key [%s] value [%s]", key, value);

	return len;
}

static void start_upload(struct http_put_s *p)
{
	struct http_put_dest_s *dest;
	GRID_DEBUG("Starting UPLOAD");
	CURLMcode rc;

	for (GSList *l = p->dests ; NULL != l ; l = l->next)
	{
		dest = l->data;

		if (dest->success)
		{
			/* Don't run successfully ended requests */

			GRID_DEBUG("Ignore successful request %s", dest->url);
			continue;
		}

		dest->handle = curl_easy_init();
		g_assert(dest->handle != NULL);

#if 0
		curl_easy_setopt(dest->handle, CURLOPT_VERBOSE, 1);
#endif
		curl_easy_setopt(dest->handle, CURLOPT_CONNECTTIMEOUT, p->timeout_cnx);
		curl_easy_setopt(dest->handle, CURLOPT_TIMEOUT, p->timeout_op);

		curl_easy_setopt(dest->handle, CURLOPT_PRIVATE, dest);
		curl_easy_setopt(dest->handle, CURLOPT_USERAGENT, "http_put/1.0");
		curl_easy_setopt(dest->handle, CURLOPT_URL, dest->url);
		curl_easy_setopt(dest->handle, CURLOPT_NOPROGRESS, 1L);
		curl_easy_setopt(dest->handle, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(dest->handle, CURLOPT_PUT, 1L);
		curl_easy_setopt(dest->handle, CURLOPT_INFILESIZE, p->buffer_length);
		curl_easy_setopt(dest->handle, CURLOPT_READFUNCTION, cb_read);
		curl_easy_setopt(dest->handle, CURLOPT_READDATA, dest);
		curl_easy_setopt(dest->handle, CURLOPT_WRITEFUNCTION, cb_write);
		curl_easy_setopt(dest->handle, CURLOPT_HTTPHEADER, dest->curl_headers);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERFUNCTION, cb_header);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERDATA, dest);

		rc = curl_multi_add_handle(p->mhandle, dest->handle);
		g_assert(rc == CURLM_OK);
	}
}

static void
check_multi_info(struct http_put_s *p)
{
	int msgs_left;
	CURLMsg *msg;
	CURL *easy;
	CURLcode curl_ret;
	long http_ret;
	struct http_put_dest_s *dest;
	CURLMcode rc;

	while ((msg = curl_multi_info_read(p->mhandle, &msgs_left))) {
		if (msg->msg == CURLMSG_DONE) {
			easy = msg->easy_handle;
			curl_ret = msg->data.result;
			dest = NULL;

			curl_easy_getinfo(easy, CURLINFO_PRIVATE, &dest);
			g_assert(easy == dest->handle);

			curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_ret);

			if (curl_ret == CURLE_OK)
			{
				dest->http_code = http_ret;
				if (http_ret/100 == 2)
					dest->success = TRUE;
			}

			GRID_DEBUG("DONE! %s => HTTP ret: %ld => CURL ret: %s", dest->url, http_ret, curl_easy_strerror(curl_ret));

			rc = curl_multi_remove_handle(p->mhandle, dest->handle);
			g_assert(rc == CURLM_OK);
			curl_easy_cleanup(dest->handle);
			dest->handle = NULL;
		}
	}
}

GError *http_put_run(struct http_put_s *p)
{
	g_assert(p != NULL);

	start_upload(p);

	do {
		check_multi_info(p);

		long timeout = 0;
		curl_multi_timeout(p->mhandle, &timeout);
		if (timeout < 0)
			timeout = 1000;
		if (timeout > 1000)
			timeout = 1000;

		fd_set fdread;
		fd_set fdwrite;
		fd_set fdexcep;
		int maxfd = -1;
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdexcep);
		curl_multi_fdset(p->mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

		struct timeval tv = {timeout/1000,0};
		int rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &tv);
		if (rc < 0)
			break;
		curl_multi_perform(p->mhandle, &p->is_running);
	} while (p->is_running);

	check_multi_info(p);
	return NULL;
}

guint http_put_get_failure_number(struct http_put_s *p)
{
	struct http_put_dest_s *dest;
	guint ret = 0;

	g_assert(p != NULL);

	for (GSList *l = p->dests ; NULL != l ; l = l->next)
	{
		dest = l->data;

		if (!dest->success)
			ret++;
	}

	return ret;
}

GSList *_http_put_get_dests(struct http_put_s *p, gboolean success)
{
	struct http_put_dest_s *dest;
	GSList *list_ret = NULL;

	g_assert(p != NULL);

	for (GSList *l = p->dests ; NULL != l ; l = l->next)
	{
		dest = l->data;

		if (success == dest->success)
			list_ret = g_slist_prepend(list_ret, dest->user_data);
	}

	return list_ret;
}

GSList *http_put_get_success_dests(struct http_put_s *p)
{
	return _http_put_get_dests(p, TRUE);
}

GSList *http_put_get_failure_dests(struct http_put_s *p)
{
	return _http_put_get_dests(p, FALSE);
}

const gchar *http_put_get_header(struct http_put_s *p, gpointer user_data, const gchar *header)
{
	struct http_put_dest_s *dest;

	g_assert(p != NULL);
	g_assert(user_data != NULL);
	g_assert(header != NULL);

	dest = g_hash_table_lookup(p->id2dests, user_data);
	if (dest == NULL)
		return NULL;

	return g_hash_table_lookup(dest->response_headers, header);
}

guint http_put_get_http_code(struct http_put_s *p, gpointer user_data)
{
	struct http_put_dest_s *dest;

	g_assert(p != NULL);
	g_assert(user_data != NULL);

	dest = g_hash_table_lookup(p->id2dests, user_data);
	if (dest == NULL)
		return 0;

	return dest->http_code;
}

void http_put_get_md5(struct http_put_s *p, guint8 *buffer, gsize size)
{
	GChecksum *checksum;

	g_assert(p != NULL);
	g_assert(buffer != NULL);
	g_assert((gssize)size == g_checksum_type_get_length(G_CHECKSUM_MD5));

	checksum = g_checksum_new(G_CHECKSUM_MD5);
	g_checksum_update(checksum, (const guchar *)p->buffer, p->buffer_length);
	g_checksum_get_digest(checksum, buffer, &size);
	g_checksum_free(checksum);
}

void http_put_get_buffer(struct http_put_s *p, const gchar **buffer, gsize *size)
{
	g_assert(p->buffer_length == p->buffer_filled);

	*buffer = p->buffer;
	*size = p->buffer_length;
}
