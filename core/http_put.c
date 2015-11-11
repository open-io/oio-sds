/*
OpenIO SDS core library
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <curl/curl.h>
#include <curl/multi.h>

#include "internals.h"
#include "oioext.h"
#include "oiolog.h"
#include "http_put.h"
#include "http_internals.h"

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
};

struct http_put_s
{
	/* list of destinations (rawx, rainx)*/
	GSList *dests;

	CURLM *mhandle;

	long timeout_cnx;
	long timeout_op;

	/* how many bytes are expected
	 *   <0 : streaming with transfer-encoding=chunked
	 *   0 : empty content
	 *   >0 : content-length known and announced */
	gint64 content_length;

	/* callback to read data from client. It might be NULL, as when the
	 * client explicitely feeds the data. */
	http_put_input_f cb_input;
	gpointer cb_input_data;

	GQueue *buffer_tail;

	enum http_whole_put_state_e state;
};

void init_curl (void);
void destroy_curl (void);

void __attribute__ ((constructor))
init_curl(void)
{
	/* With NSS, all internal data are not correctly freed at
	 * the end of the program... and we don't use ssl so we don't need it.
	 */
	curl_global_init(CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL);
}

void __attribute__ ((destructor))
destroy_curl(void)
{
	curl_global_cleanup();
}

struct http_put_s *
http_put_create(http_put_input_f cb_input, gpointer cb_input_data,
		gint64 content_length)
{
	struct http_put_s *p;
	p = g_malloc0(sizeof(struct http_put_s));
	p->dests = NULL;
	p->mhandle = curl_multi_init();
	p->cb_input = cb_input;
	p->cb_input_data = cb_input_data;
	p->buffer_tail = g_queue_new();
	p->timeout_cnx = 60;
	p->timeout_op = 60;
	p->content_length = content_length;
	p->state = HTTP_WHOLE_BEGIN;
	return p;
}

struct http_put_dest_s *
http_put_add_dest(struct http_put_s *p, const char *url, gpointer user_data)
{
	struct http_put_dest_s *dest;

	g_assert(p != NULL);
	g_assert(p->state == HTTP_WHOLE_BEGIN);
	g_assert(url != NULL);
	g_assert(user_data != NULL);

	dest = g_malloc0(sizeof(struct http_put_dest_s));

	dest->http_put = p;
	dest->url = g_strdup(url);
	dest->handle = NULL;
	dest->user_data = user_data;
	dest->headers = NULL;

	dest->curl_headers = NULL;

	dest->response_headers = g_hash_table_new_full (g_str_hash, g_str_equal,
			g_free, g_free);
	dest->bytes_sent = 0;
	dest->http_code = 0;
	dest->state = HTTP_SINGLE_BEGIN;

	p->dests = g_slist_append(p->dests, dest);

	return dest;
}

void
http_put_dest_add_header(struct http_put_dest_s *dest,
		const char *key, const char *val_fmt, ...)
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

static void
http_put_dest_destroy(gpointer destination)
{
	struct http_put_dest_s *dest = destination;

	g_assert(dest != NULL);

	if (dest->url)
		g_free(dest->url);
	if (dest->handle) {
		CURLMcode rc;
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

void
http_put_destroy(struct http_put_s *p)
{
	g_assert(p != NULL);
	if (p->dests)
		g_slist_free_full(p->dests, http_put_dest_destroy);
	if (p->mhandle)
		curl_multi_cleanup(p->mhandle);
	g_free(p);
}

static size_t
_done_reading (struct http_put_dest_s *dest, const char *why)
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
cb_read(void *data, size_t s, size_t n, struct http_put_dest_s *dest)
{
	g_assert (dest->state == HTTP_SINGLE_BEGIN || dest->state == HTTP_SINGLE_REQUEST);
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
			"-> %"G_GSIZE_FORMAT" total",
			bs, max, remaining, real, dest->bytes_sent);

	return real;
}

static size_t
cb_write(void *data, size_t size, size_t nmemb, gpointer nothing)
{
	(void)data, (void)nothing;
	return size * nmemb;
}

static size_t
cb_header(void *ptr, size_t size, size_t nmemb, struct http_put_dest_s *dest)
{
	g_assert(ptr != NULL);
	g_assert(dest != NULL);

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
	//GRID_TRACE2("CURL header [%s]:[%s]", key, value);
	return len;
}

static void
_start_upload(struct http_put_s *p)
{
	for (GSList *l = p->dests ; NULL != l ; l = l->next) {
		struct http_put_dest_s *dest = l->data;

		g_assert (dest->state == HTTP_SINGLE_BEGIN);
		g_assert (dest->http_code == 0);
		g_assert (dest->bytes_sent == 0);
		g_assert (dest->handle == NULL);

		dest->handle = _curl_get_handle();
		g_assert(dest->handle != NULL);

		curl_easy_setopt(dest->handle, CURLOPT_CONNECTTIMEOUT, p->timeout_cnx);
		curl_easy_setopt(dest->handle, CURLOPT_TIMEOUT, p->timeout_op);

		curl_easy_setopt(dest->handle, CURLOPT_PRIVATE, dest);
		curl_easy_setopt(dest->handle, CURLOPT_URL, dest->url);
		curl_easy_setopt(dest->handle, CURLOPT_UPLOAD, 1L);
		curl_easy_setopt(dest->handle, CURLOPT_PUT, 1L);
		if (p->content_length >= 0)
			curl_easy_setopt(dest->handle, CURLOPT_INFILESIZE_LARGE, p->content_length);
		else
			http_put_dest_add_header(dest, "Transfer-Encoding", "chunked");
		http_put_dest_add_header(dest, "Expect", " ");

		curl_easy_setopt(dest->handle, CURLOPT_READFUNCTION, cb_read);
		curl_easy_setopt(dest->handle, CURLOPT_READDATA, dest);
		curl_easy_setopt(dest->handle, CURLOPT_WRITEFUNCTION, cb_write);
		curl_easy_setopt(dest->handle, CURLOPT_HTTPHEADER, dest->curl_headers);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERFUNCTION, cb_header);
		curl_easy_setopt(dest->handle, CURLOPT_HEADERDATA, dest);

		CURLMcode rc = curl_multi_add_handle(p->mhandle, dest->handle);
		g_assert(rc == CURLM_OK);
	}
}

static void
_manage_curl_events (struct http_put_s *p)
{
	int msgs_left = 0;
	CURLMsg *msg;

	while ((msg = curl_multi_info_read(p->mhandle, &msgs_left))) {
		if (msg->msg != CURLMSG_DONE) {
			GRID_DEBUG("Unexpected CURL event");
		} else {
			CURL *easy = msg->easy_handle;
			CURLcode curl_ret = msg->data.result;
			struct http_put_dest_s *dest = NULL;

			curl_easy_getinfo(easy, CURLINFO_PRIVATE, &dest);
			g_assert (easy == dest->handle);
			g_assert (dest->state != HTTP_SINGLE_FINISHED);
			dest->state = HTTP_SINGLE_FINISHED;

			long http_ret;
			curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_ret);

			if (curl_ret == CURLE_OK)
				dest->http_code = http_ret;

			GRID_DEBUG("DONE [%s] code=%ld strerror=%s",
					dest->url, http_ret, curl_easy_strerror(curl_ret));

			CURLMcode rc = curl_multi_remove_handle(p->mhandle, dest->handle);
			g_assert(rc == CURLM_OK);
			curl_easy_cleanup(dest->handle);
			dest->handle = NULL;
		}
	}
}

static GBytes *
_call_data (struct http_put_s *p)
{
	char b[2048];
	ssize_t r = p->cb_input (p->cb_input_data, b, sizeof(b));
	return (r < 0) ? NULL : g_bytes_new (b, r);
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

gboolean
http_put_done (struct http_put_s *p)
{
	g_assert (p != NULL);
	return p->state == HTTP_WHOLE_FINISHED;
}

GError *
http_put_step (struct http_put_s *p)
{
	int rc;
	guint count_dests = 0, count_up = 0, count_waiting_for_data = 0;

	g_assert (p != NULL);

	if (!p->dests) {
		GRID_DEBUG("Empty upload detected");
		p->state = HTTP_WHOLE_FINISHED;
		return NULL;
	}
	if (p->state == HTTP_WHOLE_FINISHED) {
		GRID_DEBUG("BUG: Stepping on a finished upload");
		return NULL;
	}

	count_dests = g_slist_length(p->dests);
	GRID_TRACE("STEP on %u destinations", count_dests);

	/* consume the CURL notifications for terminated actions */
	_manage_curl_events(p);

	/* Ensure the data-pipe doesn't become empty and maybe call for more */
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		if (!d->buffer && d->state < HTTP_SINGLE_FINISHED)
			count_waiting_for_data ++;
	}
	if (count_waiting_for_data >= count_dests) {
		GBytes *buf = g_queue_pop_head (p->buffer_tail);
		if (!buf && p->cb_input) {
			/* No data immediately available, try to call some from the hook */
			if (!(buf = _call_data (p)))
				return SYSERR("No data collected from the user callback");
		}
		if (buf) {
			for (GSList *l=p->dests; l ;l=l->next) {
				struct http_put_dest_s *d = l->data;
				d->buffer = g_bytes_ref (buf);
			}
			g_bytes_unref (buf);
		}
	}

	if (p->state == HTTP_WHOLE_BEGIN) {
		GRID_DEBUG("Starting %u uploads", count_dests);
		_start_upload(p);
		p->state = HTTP_WHOLE_READY;
	}

	/* pause CURL actions that have no data to manage immediately, 
	 * and ensure the action with data ready are registered. */
	for (GSList *l=p->dests; l ;l=l->next) {
		struct http_put_dest_s *d = l->data;
		if (d->state == HTTP_SINGLE_FINISHED)
			continue;
		GRID_DEBUG("%s : %p %d", d->url, d->buffer, d->state); 
		if (d->buffer) {
			if (d->state == HTTP_SINGLE_PAUSED) {
				curl_easy_pause (d->handle, CURLPAUSE_CONT);
				d->state = d->bytes_sent ? HTTP_SINGLE_REQUEST : HTTP_SINGLE_BEGIN;
			}
		}
	}

	count_up= _count_up_dests (p);
	p->state = count_up ? HTTP_WHOLE_READY : HTTP_WHOLE_PAUSED;

	GRID_TRACE("Uploads: %u total, %u up (%u wanted to data)",
			count_dests, count_up, count_waiting_for_data);

	if (count_up) {
		fd_set fdread, fdwrite, fdexcep;
		int maxfd = -1;
		struct timeval tv = {1,0};
		FD_ZERO(&fdread);
		FD_ZERO(&fdwrite);
		FD_ZERO(&fdexcep);

		long timeout = 0;
		curl_multi_timeout (p->mhandle, &timeout);
		if (timeout < 1000) {
			tv.tv_sec = 0;
			tv.tv_usec = timeout * 1000;
		}
		curl_multi_fdset(p->mhandle, &fdread, &fdwrite, &fdexcep, &maxfd);

retry:
		rc = select(maxfd+1, &fdread, &fdwrite, &fdexcep, &tv);
		if (rc < 0) {
			if (errno == EINTR) goto retry;
			return SYSERR("select() error: (%d) %s", errno, strerror(errno));
		}
	}

	/* Do the I/O things now */
	curl_multi_perform(p->mhandle, &rc);

	if (!(count_up = _count_up_dests (p))) {
		GRID_TRACE("Uploads: finishing");
		_manage_curl_events(p);
		p->state = HTTP_WHOLE_FINISHED;
	}

	return NULL;
}

GError *
http_put_run(struct http_put_s *p)
{
	g_assert(p != NULL);
	while (p->state != HTTP_WHOLE_FINISHED)
		http_put_step (p);
	return NULL;
}

guint
http_put_get_failure_number(struct http_put_s *p)
{
	g_assert(p != NULL);
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
	g_assert(p != NULL);
	g_assert(k != NULL);
	g_assert(h != NULL);
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
	g_assert(p != NULL);
	g_assert(k != NULL);
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
	/* XXX */
	g_assert (p != NULL);
	g_assert (buffer != NULL);
	memset (buffer, 0, size);
}

static int
_trace(CURL *h, curl_infotype t, char *data, size_t size, void *u)
{
	(void) h, (void) u, (void) data, (void) size;
	switch (t) {
		case CURLINFO_TEXT:
			GRID_TRACE("CURL: %.*s", (int)size, data);
			return 0;
		case CURLINFO_HEADER_IN:
			GRID_TRACE("CURL< %.*s", (int)size, data);
			return 0;
		case CURLINFO_HEADER_OUT:
			GRID_TRACE("CURL> %.*s", (int)size, data);
			return 0;
		default:
			return 0;
	}
}

CURL *
_curl_get_handle (void)
{
	CURL *h = curl_easy_init ();
	curl_easy_setopt (h, CURLOPT_USERAGENT, OIOSDS_http_agent);
	curl_easy_setopt (h, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt (h, CURLOPT_PROXY, NULL);
	if (GRID_TRACE_ENABLED()) {
		curl_easy_setopt (h, CURLOPT_DEBUGFUNCTION, _trace);
		curl_easy_setopt (h, CURLOPT_VERBOSE, 1L);
	}
	return h;
}

void
http_put_feed (struct http_put_s *p, GBytes *b)
{
	g_assert (p != NULL);
	g_assert (b != NULL);
	g_queue_push_tail (p->buffer_tail, g_bytes_ref(b));
}

