#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "http.pipe"
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <poll.h>

#include <glib.h>

#include <curl/curl.h>
#include <curl/multi.h>

#include "./http_pipe.h"

struct slice_s
{
	guint8 *buf;
	gsize buf_len;
	gsize buf_read;
};

struct http_pipe_end_s
{
	gboolean started;
	gchar *url;
	CURL *handle;
	struct curl_slist *headers; // Structure passed to the request
};

struct http_pipe_s
{
	struct http_pipe_end_s from;
	struct http_pipe_end_s to;
	int is_running;
	CURLM *mhandle;

	gpointer header_filter_u;
	http_pipe_header_filter_cb header_filter;

	gpointer data_filter_u;
	http_pipe_data_filter_cb data_filter;

	double content_length;

	GSList *copied_headers; // Got from the upload side, passed the filter
	GSList *forced_headers; // Configured by the caller, ignore the filter

	GQueue *queue; // real pipe of <struct slice_s*>
	size_t queue_max;
	size_t queue_current;
};

void
http_pipe_force_header(struct http_pipe_s *p, const gchar *n, const gchar *v)
{
	g_assert(p != NULL);
	gchar *formatted = g_strdup_printf("%s: %s", n, v);
	p->forced_headers = g_slist_prepend(p->forced_headers, formatted);
}

struct http_pipe_s *
http_pipe_create(const gchar *from, const gchar *to)
{
	struct http_pipe_s *p;
	p = g_malloc0(sizeof(struct http_pipe_s));
	p->content_length = -1;
	p->copied_headers = NULL;
	p->forced_headers = NULL;
	p->from.url = g_strdup(from);
	p->to.url = g_strdup(to);
	p->mhandle = curl_multi_init();
	p->queue = g_queue_new();
	p->queue_current = 0;
	p->queue_max = 131072;
	return p;
}

static void
_endpoint_cleanup(struct http_pipe_end_s *e)
{
	if (e->url)
		g_free(e->url);
	if (e->handle)
		curl_easy_cleanup(e->handle);
	if (e->headers)
		curl_slist_free_all(e->headers);
}

void
http_pipe_destroy(struct http_pipe_s *p)
{
	g_assert(p != NULL);
	_endpoint_cleanup(&p->to);
	_endpoint_cleanup(&p->from);
	if (p->mhandle)
		curl_multi_cleanup(p->mhandle);
	if (p->queue)
		g_queue_free(p->queue);
	if (p->copied_headers)
		g_slist_free_full(p->copied_headers, g_free);
	if (p->forced_headers)
		g_slist_free_full(p->forced_headers, g_free);
	g_free(p);
}

void
http_pipe_filter_headers(struct http_pipe_s *p, http_pipe_header_filter_cb f,
		gpointer u)
{
	g_assert(p != NULL);
	p->header_filter = f;
	p->header_filter_u = u;
}

void
http_pipe_filter_data(struct http_pipe_s *p, http_pipe_data_filter_cb f,
		gpointer u)
{
	g_assert(p != NULL);
	p->data_filter = f;
	p->data_filter_u = u;
}

static void _pipe_run(struct http_pipe_s *p);
static void _start_upload(struct http_pipe_s *p);
static void _start_download(struct http_pipe_s *p);

GError *
http_pipe_run(struct http_pipe_s *p)
{
	g_assert(p != NULL);
	_pipe_run(p);
	return NULL;
}

static size_t
cb_enqueue(void *data, size_t s, size_t n, struct http_pipe_s *p)
{
	curl_easy_getinfo(p->from.handle, CURLINFO_CONTENT_LENGTH_DOWNLOAD,
			&p->content_length);

	struct slice_s slice;
	slice.buf_read = 0;
	slice.buf_len = s * n;
	slice.buf = g_memdup(data, slice.buf_len);

	if (p->data_filter)
		p->data_filter(p->data_filter_u, slice.buf, slice.buf_len);

	p->queue_current += slice.buf_len;
	g_queue_push_tail(p->queue, g_memdup(&slice, sizeof(struct slice_s)));

	if (p->queue_current > p->queue_max) {
		if (p->from.handle) {
			curl_easy_pause(p->from.handle, CURLPAUSE_RECV);
		}
	}

	if (p->queue_current > 0) {
		if (p->to.handle) {
			curl_easy_pause(p->to.handle, CURLPAUSE_SEND_CONT);
		}
	}

	if (!p->to.started)
		 _start_upload(p);
	return slice.buf_len;
}

static size_t
cb_dequeue(void *data, size_t s, size_t n, struct http_pipe_s *p)
{
	struct slice_s *slice;

	if (!s || !n)
		return 0;

	if (p->queue_current == 0) {
		if (p->from.handle == NULL) {
			g_debug("Download and upload finished.");
		} else if (p->to.handle) {
			curl_easy_pause(p->to.handle, CURLPAUSE_SEND);
		}
		return 0;
	}

	slice = g_queue_pop_head(p->queue);
	g_assert(slice);

	size_t max = s * n;
	if (max > slice->buf_len - slice->buf_read)
		max = slice->buf_len - slice->buf_read;
	memcpy(data, slice->buf + slice->buf_read, max);
	slice->buf_read += max;
	p->queue_current -= max;

	if (slice->buf_read < slice->buf_len) {
		g_queue_push_head(p->queue, slice);
	} else {
		g_free(slice->buf);
		memset(slice, 0, sizeof(struct slice_s));
		g_free(slice);
	}

	if (p->queue_current < p->queue_max) {
		if (p->from.handle) {
			curl_easy_pause(p->from.handle, CURLPAUSE_RECV_CONT);
		}
	}

	return max;
}

static size_t
_parse_dl_headers(void *ptr, size_t s, size_t n, struct http_pipe_s *p)
{
	const size_t hsize = s * n;
	p->copied_headers = g_slist_prepend(p->copied_headers,
			g_strstrip(g_strndup((gchar*)ptr, hsize)));
	return hsize;
}

static void
_start_download(struct http_pipe_s *p)
{
	g_debug("starting DOWNLOAD");
	p->from.handle = curl_easy_init();
	g_assert(p->from.handle != NULL);

	curl_easy_setopt(p->from.handle, CURLOPT_PRIVATE, &p->from);
	curl_easy_setopt(p->from.handle, CURLOPT_USERAGENT, "http_pipe/1.0");
	curl_easy_setopt(p->from.handle, CURLOPT_URL, p->from.url);
	curl_easy_setopt(p->from.handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(p->from.handle, CURLOPT_WRITEFUNCTION, cb_enqueue);
	curl_easy_setopt(p->from.handle, CURLOPT_WRITEDATA, p);
	curl_easy_setopt(p->from.handle, CURLOPT_HEADERFUNCTION, _parse_dl_headers);
	curl_easy_setopt(p->from.handle, CURLOPT_HEADERDATA, p);
	CURLMcode rc = curl_multi_add_handle(p->mhandle, p->from.handle);
	g_assert(rc == CURLM_OK);
}

static void
_start_upload(struct http_pipe_s *p)
{
	g_assert(!p->to.started);
	g_debug("starting UPLOAD");
	p->to.handle = curl_easy_init();
	g_assert(p->to.handle != NULL);

	// Recopy the headers from the DL side
	long content_length = p->content_length;
	p->to.headers = curl_slist_append(p->to.headers, "Expect:");
	if (p->header_filter) {
		for (GSList *l = p->copied_headers; l ;l=l->next) {
			gchar *h = l->data;
			if (p->header_filter(p->header_filter_u, h))
				p->to.headers = curl_slist_append(p->to.headers, h);
		}
	}
	for (GSList *l = p->forced_headers; l ;l=l->next) {
		gchar *h = l->data;
		p->to.headers = curl_slist_append(p->to.headers, h);
	}

	// Start the upload
	curl_easy_setopt(p->to.handle, CURLOPT_PRIVATE, &p->to);
	curl_easy_setopt(p->to.handle, CURLOPT_USERAGENT, "http_pipe/1.0");
	curl_easy_setopt(p->to.handle, CURLOPT_URL, p->to.url);
	curl_easy_setopt(p->to.handle, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(p->to.handle, CURLOPT_UPLOAD, 1L);
	curl_easy_setopt(p->to.handle, CURLOPT_PUT, 1L);
	curl_easy_setopt(p->to.handle, CURLOPT_INFILESIZE, content_length);
	curl_easy_setopt(p->to.handle, CURLOPT_READFUNCTION, cb_dequeue);
	curl_easy_setopt(p->to.handle, CURLOPT_READDATA, p);
	curl_easy_setopt(p->to.handle, CURLOPT_HTTPHEADER, p->to.headers);

	CURLMcode rc = curl_multi_add_handle(p->mhandle, p->to.handle);
	g_assert(rc == CURLM_OK);
	p->to.started = TRUE;
}

static void
check_multi_info(struct http_pipe_s *p)
{
	char *eff_url;
	int msgs_left;
	CURLMsg *msg;

	while ((msg = curl_multi_info_read(p->mhandle, &msgs_left))) {
		if (msg->msg == CURLMSG_DONE) {
			CURL *easy = msg->easy_handle;
			CURLcode res = msg->data.result;
			struct http_pipe_end_s *end = NULL;

			(void) res;
			curl_easy_getinfo(easy, CURLINFO_PRIVATE, &end);
			curl_easy_getinfo(easy, CURLINFO_EFFECTIVE_URL, &eff_url);
			g_assert(easy == end->handle);
			g_debug("DONE! %s", end == &p->from ? "from" : "to");
			if (end == &p->from && p->to.handle)
				curl_easy_pause(p->to.handle, CURLPAUSE_SEND_CONT);

			curl_multi_remove_handle(p->mhandle, end->handle);
			curl_easy_cleanup(end->handle);
			end->handle = NULL;
		}
	}
}

static void
_pipe_run(struct http_pipe_s *p)
{
	_start_download(p);

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
}

