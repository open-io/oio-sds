#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "http_put.test"
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>


#include <glib.h>

#include "http_put.h"

#define TEST_START_PORT 		10000

/* ******************* HTTP SERVER for unit tests ********************** */

struct mhd_request_state_s
{
	gboolean initiated;
	gsize content_length;
	gsize content_offset;
};
typedef struct mhd_request_state_s mhd_request_state_t;

struct mhd_request_s
{
	gchar *method;
	gchar *url;
	GHashTable *headers;
	GHashTable *resp_headers;
	const gchar *data;
	gsize data_len;
	guint return_code;
	int timeout; /* ask to wait timeout secondes during request processing */
	mhd_request_state_t state;
};
typedef struct mhd_request_s mhd_request_t;

mhd_request_t *mhd_req_new(const gchar *method, const gchar *url,
		const gchar *data, gsize data_len, int timeout, guint return_code)
{
	mhd_request_t *request;

	request = g_malloc(sizeof(mhd_request_t));
	request->method = g_strdup(method);
	request->url = g_strdup(url);
	request->headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	request->resp_headers = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	request->data = data;
	request->data_len = data_len;
	request->return_code = return_code;
	request->timeout = timeout;
	request->state.initiated = FALSE;
	request->state.content_length = 0;
	request->state.content_offset = 0;

	return request;
}

/**
 * @note No need to free req after this call
 */
void mhd_req_add_header(mhd_request_t *req, const gchar *key,
		const gchar *value)
{
	g_assert(req != NULL);
	g_hash_table_insert(req->headers, g_strdup(key), g_strdup(value));
}

/**
 * @note No need to free req after this call
 */
void mhd_req_add_resp_header(mhd_request_t *req, const gchar *key,
		const gchar *value)
{
	g_assert(req != NULL);
	g_hash_table_insert(req->resp_headers, g_strdup(key), g_strdup(value));
}

void mhd_req_destroy(gpointer req)
{
	mhd_request_t *request = req;

	g_assert(request != NULL);

	if (request->headers)
		g_hash_table_destroy(request->headers);
	if (request->resp_headers)
		g_hash_table_destroy(request->resp_headers);
	if (request->method)
		g_free(request->method);
	if (request->url)
		g_free(request->url);
	g_free(request);
}

struct mhd_context_s
{
	guint16 port;
	struct MHD_Daemon *server;
	GSList *requests;
};
typedef struct mhd_context_s mhd_context_t;

mhd_context_t *mhd_init(guint port)
{
	mhd_context_t *context;

	context = g_malloc(sizeof(mhd_context_t));
	context->port = port;
	context->server = NULL;
	context->requests = NULL;

	return context;
}

void mhd_add_req(mhd_context_t *context, mhd_request_t *request)
{
	g_assert(context != NULL);
	g_assert(request != NULL);

	context->requests = g_slist_append(context->requests, request);
}

static void _put_check_headers(struct MHD_Connection *connection,
		GHashTable *wanted_headers)
{
	GHashTableIter iter;
	gpointer key, value;
	const gchar *rec_value;

	g_hash_table_iter_init(&iter, wanted_headers);
	while (g_hash_table_iter_next(&iter, &key, &value)) 
	{
		rec_value = MHD_lookup_connection_value(connection,
				MHD_HEADER_KIND, key);
		g_assert(rec_value != NULL && "Missing required header");
		g_assert_cmpstr(value, ==, rec_value);
	}
}

static void _put_check_upload_data(const gchar *wanted_data,
		gsize wanted_data_len, const char *received_data,
		size_t received_data_len, size_t offset)
{
	g_assert((offset + received_data_len <= wanted_data_len)
			&& "Too much data received !");

	g_assert(memcmp(wanted_data + offset, received_data, received_data_len) == 0
				&& "Data received different from data sent");
}

static void _put_send_response(struct MHD_Connection *connection,
		mhd_request_t *request)
{
	const char *page = "<html><body>Dummy body</body></html>";
	struct MHD_Response *response;
	GHashTableIter iter;
	gpointer key, value;
	int ret;

	/* Send a dummy response to client */
	response = MHD_create_response_from_buffer(strlen (page),
			(void*) page, MHD_RESPMEM_PERSISTENT);
	g_assert(response != NULL && "MHD internal error");

	g_hash_table_iter_init(&iter, request->resp_headers);
	while (g_hash_table_iter_next(&iter, &key, &value)) 
	{
		ret = MHD_add_response_header(response, key, value);
		g_assert(ret == MHD_YES && "MHD internal error");
	}

	ret = MHD_queue_response(connection, request->return_code, response);
	g_assert(ret == MHD_YES && "MHD internal error");

	MHD_destroy_response(response);
}

static int _put_answer_to_connection(mhd_request_t *request,
		struct MHD_Connection *connection, gboolean first_call,
		const char *upload_data, size_t *upload_data_size)
{
	const gchar *content_length;

	if (first_call)
	{
		/* Check header values and get the content lentgh */
		_put_check_headers(connection, request->headers);

		content_length = MHD_lookup_connection_value(connection, MHD_HEADER_KIND,
				MHD_HTTP_HEADER_CONTENT_LENGTH);
		g_assert(content_length != NULL && "Missing Content-Length");

		request->state.content_length = g_ascii_strtoull(content_length, NULL, 10);

		g_assert(request->state.content_length == request->data_len &&
				"Bad content length header");

		/* On the first call, no data have been read
		 */
		g_assert(*upload_data_size == 0);

		return MHD_YES;
	}

	if (*upload_data_size == 0)
	{
		/* No more data to read, its the last call
		 * so we must send a response to client
		 */
		_put_send_response(connection, request);

		return MHD_YES;
	}

	/* Next calls, we must check the uploaded data
	 */

	/* Check uploaded data */
	if (request->data != NULL)
	{
		_put_check_upload_data(request->data, request->data_len,
				upload_data, *upload_data_size, request->state.content_offset);
		/* All the current data are good
		 */
		request->state.content_offset += *upload_data_size;
		*upload_data_size = 0;
	}

	return MHD_YES;
}

static int _answer_to_connection(void *cls, struct MHD_Connection *connection, 
		const char *url, 
		const char *method, const char *version, 
		const char *upload_data, 
		size_t *upload_data_size, void **con_cls)
{
	int ret;
	GSList *i_list;
	mhd_context_t *context = cls;
	mhd_request_t *request;
	gboolean first_call;

	(void)version;

	if (*con_cls == NULL)
	{
		/* First call for this request
		 */

		/* Search the next expected request */
		for (i_list = context->requests ; i_list != NULL ; i_list = g_slist_next(i_list))
		{
			request = i_list->data;
			if (request->state.initiated == FALSE)
				break;
		}
		g_assert(i_list != NULL && "Request required");
		request->state.initiated = TRUE;

		g_assert_cmpstr(request->url, ==, url);
		g_assert_cmpstr(request->method, ==, method);

		/* store this request for future calls of this function
		 */
		*con_cls = request;
		first_call = TRUE;
	}
	else
	{
		/* Next calls: restore the current request */
		request = *con_cls;
		first_call = FALSE;
	}

	if (request->timeout > 0)
	{
		sleep(request->timeout);
		/* Don't sleep several times because one sleep must be enough
		 * to cause timeout.
		 * Even after client gets timeout and so closes the connection, 
		 * libmicrohttpd continue to process this request...
		 */
		request->timeout = 0;
	}

	if (g_strcmp0(method, "PUT") == 0)
	{
		ret = _put_answer_to_connection(request, connection, first_call,
				upload_data, upload_data_size);
		g_assert(ret == MHD_YES && "Internal error with put processing");
	}
	else if (g_strcmp0(method, "GET") == 0)
	{
		g_assert(!"GET request not yet supported");
	}
	else
	{
		g_assert(!"Unknow request method");
	}

	return MHD_YES;
}

void mhd_run(mhd_context_t *context)
{
	g_assert(context != NULL);

	context->server = MHD_start_daemon (MHD_USE_SELECT_INTERNALLY,
			context->port, NULL, NULL,
			_answer_to_connection, context, MHD_OPTION_END);
	g_assert(context->server != NULL && "MHD internal error while starting server");
}

void mhd_destroy(mhd_context_t *context)
{
	g_assert(context != NULL);

	if (context->server)
		MHD_stop_daemon(context->server);
	if (context->requests)
		g_slist_free_full(context->requests, mhd_req_destroy);
	g_free(context);

}

/* *********************** HTTP PUT test units ************************* */

struct mydest_s
{
	gchar *url;
};
typedef struct mydest_s mydest_t;

struct data_source_s
{
	gsize len;
	gsize cursor;
	gchar *buffer;
};
typedef struct data_source_s data_source_t;

static data_source_t *source_initialize(gsize size)
{
	gsize i;

	data_source_t *source = g_malloc(sizeof(data_source_t));
	source->len = size;
	source->cursor = 0;
	source->buffer = g_malloc(size);

	for (i = 0; i < source->len ; i++)
		source->buffer[i] = i % 20 + 60;

	return source;
}

static void source_destroy(data_source_t *source)
{
	g_free(source->buffer);
	g_free(source);
}

static ssize_t feed_from_buffer (void *uData, char *b, size_t s)
{
	struct data_source_s *source;
	size_t nb;
	
	source = (data_source_t *)uData;
	nb = MIN(source->len - source->cursor, s);
	
	if (nb == 0)
		return 0;

	memcpy(b, source->buffer + source->cursor, nb);
	source->cursor += nb;

	return nb;
}

struct test_put_config
{
	int nb_req;
	int data_len;
};

#define TEST_START_HTTP_CODE	200
static void test_put(gconstpointer user_data)
{
	const struct test_put_config *test_config = user_data;
	mhd_context_t *server[test_config->nb_req];
	mhd_request_t *req_tmp;
	struct http_put_s *http_put;
	struct http_put_dest_s *dest_tmp;
	mydest_t mydest[test_config->nb_req];
	GSList *dest_list;
	const gchar *resp_header;
	gchar str_tmp1[128], str_tmp2[128];
	GError *error;
	int i;
	data_source_t *source;

	/* Initialize data source */
	source = source_initialize(test_config->data_len);

	/* Start and configure servers */
	for (i = 0 ; i < test_config->nb_req ; i++)
	{
		server[i] = mhd_init(TEST_START_PORT + i);
		req_tmp = mhd_req_new("PUT", "/test", source->buffer, source->len,
				0, TEST_START_HTTP_CODE + i);
		g_snprintf(str_tmp1, sizeof(str_tmp1), "reqheader%d", i);
		g_snprintf(str_tmp2, sizeof(str_tmp2), "reqvalue%d", i);
		mhd_req_add_header(req_tmp, str_tmp1, str_tmp2);
		g_snprintf(str_tmp1, sizeof(str_tmp1), "respheader%d", i);
		g_snprintf(str_tmp2, sizeof(str_tmp2), "respvalue%d", i);
		mhd_req_add_resp_header(req_tmp, str_tmp1, str_tmp2);
		mhd_add_req(server[i], req_tmp);
		mhd_run(server[i]);
	}

	/* Setup and send all the requests */
	http_put = http_put_create(feed_from_buffer, source, source->len, 5, 5);
	g_assert(http_put != NULL && "http_put_create internal error");

	for (i = 0 ; i < test_config->nb_req ; i++)
	{
		mydest[i].url = g_strdup_printf("http://127.0.0.1:%d/test",
				TEST_START_PORT + i);

		dest_tmp = http_put_add_dest(http_put, mydest[i].url, &mydest[i]);
		g_snprintf(str_tmp1, sizeof(str_tmp1), "reqheader%d", i);
		g_snprintf(str_tmp2, sizeof(str_tmp2), "reqvalue%d", i);
		http_put_dest_add_header(dest_tmp, str_tmp1, str_tmp2);
	}

	error = http_put_run(http_put);
	g_assert(error == NULL && "http_put_run internal error");

	/* All requests ended successfully */
	g_assert(http_put_get_failure_number(http_put) == 0);

	/* Check status */
	dest_list = http_put_get_success_dests(http_put);
	for (i = 0 ; i < test_config->nb_req ; i++)
	{
		g_assert_cmpuint(http_put_get_http_code(http_put, &mydest[i]), ==,
				TEST_START_HTTP_CODE + i);
		g_assert(g_slist_find(dest_list, &mydest[i]) != NULL &&
				"Destination not found in success list");

		/* Check response headers */
		g_snprintf(str_tmp1, sizeof(str_tmp1), "respheader%d", i);
		g_snprintf(str_tmp2, sizeof(str_tmp2), "respvalue%d", i);
		resp_header = http_put_get_header(http_put, &mydest[i], str_tmp1);
		g_assert(resp_header != NULL && "Missing response header");
		g_assert_cmpstr(resp_header, ==, str_tmp2);
	}
	g_slist_free(dest_list);

	dest_list = http_put_get_failure_dests(http_put);
	g_assert(dest_list == NULL);

	/* Clean up */
	http_put_destroy(http_put);
	for (i = 0 ; i < test_config->nb_req ; i++)
	{
		mhd_destroy(server[i]);
		g_free(mydest[i].url);
	}
	source_destroy(source);
}
#undef TEST_START_HTTP_CODE

/* Http server returned an error (500)
 */
static void test_put_http_error(void)
{
	mhd_context_t *server1;
	mhd_request_t *req;
	struct http_put_s *http_put;
	mydest_t mydest1;
	GSList *dest_list;
	GError *error;
	data_source_t *source;

	/* Initialize data source */
	source = source_initialize(100);

	/* Setup the test http server */
	server1 = mhd_init(9999);
	req = mhd_req_new("PUT", "/test", source->buffer, source->len, 0, 500);
	mhd_add_req(server1, req);
	mhd_run(server1);

	/* Setup and send the request */
	mydest1.url = "http://127.0.0.1:9999/test";

	http_put = http_put_create(feed_from_buffer, source, source->len, 5, 5);
	g_assert(http_put != NULL && "http_put_create internal error");

	http_put_add_dest(http_put, mydest1.url, &mydest1);

	error = http_put_run(http_put);
	g_assert(error == NULL && "http_put_run internal error");

	g_assert(http_put_get_failure_number(http_put) == 1);

	/* Check http put status */
	g_assert_cmpuint(http_put_get_http_code(http_put, &mydest1), ==, 500);

	/* Check destination status */
	dest_list = http_put_get_success_dests(http_put);
	g_assert(dest_list == NULL);

	dest_list = http_put_get_failure_dests(http_put);
	g_assert(dest_list->data == &mydest1);
	g_assert(dest_list->next == NULL);
	g_slist_free(dest_list);

	/* Clean up */
	http_put_destroy(http_put);
	mhd_destroy(server1);
	source_destroy(source);
}

/* We send data to one server, then clear destinations, add a new one and
 * send the same data to the new one.
 */
#define TEST_NB_RETRY 2
static void test_put_clear_put(void)
{
	mhd_context_t *server;
	mhd_request_t *req_tmp;
	struct http_put_s *http_put;
	mydest_t mydest[TEST_NB_RETRY];
	GSList *dest_list;
	GError *error;
	data_source_t *source;
	int i;

	/* Initialize data source */
	source = source_initialize(10000);

	/* Setup the request manager */
	http_put = http_put_create(feed_from_buffer, source, source->len, 5, 5);
	g_assert(http_put != NULL && "http_put_create internal error");

	for (i = 0 ; i < TEST_NB_RETRY ; i++)
	{
		/* Setup the test http servers */
		server = mhd_init(TEST_START_PORT + i);
		req_tmp = mhd_req_new("PUT", "/test", source->buffer, source->len, 0, 200);
		mhd_add_req(server, req_tmp);
		mhd_run(server);

		/* Setup and send the request for the first server */
		mydest[i].url = g_strdup_printf("http://127.0.0.1:%d/test",
				TEST_START_PORT + i);
		http_put_add_dest(http_put, mydest[i].url, &mydest[i]);

		error = http_put_run(http_put);
		g_assert(error == NULL && "http_put_run internal error");

		g_assert(http_put_get_failure_number(http_put) == 0);

		/* Check http put status */
		g_assert_cmpuint(http_put_get_http_code(http_put, &mydest[i]), ==, 200);

		/* Check destination status */
		dest_list = http_put_get_success_dests(http_put);
		g_assert(dest_list->data == &mydest[i]);
		g_assert(dest_list->next == NULL);
		g_slist_free(dest_list);

		dest_list = http_put_get_failure_dests(http_put);
		g_assert(dest_list == NULL);

		/* Clear previous destinations */
		http_put_clear_dests(http_put);

		mhd_destroy(server);
		g_free(mydest[i].url);
	}

	/* Clean up */
	http_put_destroy(http_put);
	source_destroy(source);
}
#undef TEST_NB_RETRY

/* There is no http server so connection will fail
 */
static void test_put_no_server(void)
{
	struct http_put_s *http_put;
	mydest_t mydest1;
	GSList *dest_list;
	GError *error;
	data_source_t *source;

	/* Initialize data source */
	source = source_initialize(100);

	/* Setup and send the request */
	mydest1.url = "http://127.0.0.1:9999/test";

	http_put = http_put_create(feed_from_buffer, source, source->len, 5, 5);
	g_assert(http_put != NULL && "http_put_create internal error");

	http_put_add_dest(http_put, mydest1.url, &mydest1);

	error = http_put_run(http_put);
	g_assert(error == NULL && "http_put_run internal error");

	g_assert(http_put_get_failure_number(http_put) == 1);

	/* Check http put status */
	g_assert_cmpuint(http_put_get_http_code(http_put, &mydest1), ==, 0);

	/* Check destination status */
	dest_list = http_put_get_success_dests(http_put);
	g_assert(dest_list == NULL);

	dest_list = http_put_get_failure_dests(http_put);
	g_assert(dest_list->data == &mydest1);
	g_assert(dest_list->next == NULL);
	g_slist_free(dest_list);

	/* Clean up */
	http_put_destroy(http_put);
	source_destroy(source);
}

/* Http is too too long to respond
 */
static void test_put_server_timeout(void)
{
	mhd_context_t *server1;
	mhd_request_t *req;
	struct http_put_s *http_put;
	mydest_t mydest1;
	GSList *dest_list;
	GError *error;
	data_source_t *source;

	/* Initialize data source */
	source = source_initialize(100);

	/* Setup the test http server */
	server1 = mhd_init(9999);
	req = mhd_req_new("PUT", "/test", source->buffer, source->len, 7, 200);
	mhd_add_req(server1, req);
	mhd_run(server1);

	/* Setup and send the request */
	mydest1.url = "http://127.0.0.1:9999/test";

	http_put = http_put_create(feed_from_buffer, source, source->len, 3, 6);
	g_assert(http_put != NULL && "http_put_create internal error");

	http_put_add_dest(http_put, mydest1.url, &mydest1);

	error = http_put_run(http_put);
	g_assert(error == NULL && "http_put_run internal error");

	g_assert(http_put_get_failure_number(http_put) == 1);

	/* Check http put status */
	g_assert_cmpuint(http_put_get_http_code(http_put, &mydest1), ==, 0);

	/* Check destination status */
	dest_list = http_put_get_success_dests(http_put);
	g_assert(dest_list == NULL);

	dest_list = http_put_get_failure_dests(http_put);
	g_assert(dest_list->data == &mydest1);
	g_assert(dest_list->next == NULL);
	g_slist_free(dest_list);

	/* Clean up */
	http_put_destroy(http_put);
	mhd_destroy(server1);
	source_destroy(source);
}

/* The feeder function return an error and so, http_put can't send
 * all the data.
 * To simulate this problem, we just need to use a content-length bigger
 * than the buffer.
 */
static void test_put_feeder_fail(void)
{
	mhd_context_t *server1;
	mhd_request_t *req;
	struct http_put_s *http_put;
	mydest_t mydest1;
	GSList *dest_list;
	GError *error;
	data_source_t *source;

	/* Initialize data source */
	source = source_initialize(100);

	/* Setup the test http server */
	server1 = mhd_init(9999);
	req = mhd_req_new("PUT", "/test", source->buffer, source->len + 100, 7, 200);
	mhd_add_req(server1, req);
	mhd_run(server1);

	/* Setup and send the request */
	mydest1.url = "http://127.0.0.1:9999/test";

	http_put = http_put_create(feed_from_buffer, source, source->len + 100, 3, 6);
	g_assert(http_put != NULL && "http_put_create internal error");

	http_put_add_dest(http_put, mydest1.url, &mydest1);

	error = http_put_run(http_put);
	g_assert(error == NULL && "http_put_run internal error");

	g_assert(http_put_get_failure_number(http_put) == 1);

	/* Check http put status */
	g_assert_cmpuint(http_put_get_http_code(http_put, &mydest1), ==, 0);

	/* Check destination status */
	dest_list = http_put_get_success_dests(http_put);
	g_assert(dest_list == NULL);

	dest_list = http_put_get_failure_dests(http_put);
	g_assert(dest_list->data == &mydest1);
	g_assert(dest_list->next == NULL);
	g_slist_free(dest_list);

	/* Clean up */
	http_put_destroy(http_put);
	mhd_destroy(server1);
	source_destroy(source);
}

/* We want to cause an assert in the request processing to be sure
 * it can arrive...
 * To do that, we will use two different beginning for the sending buffer.
 */
#define TEST_BEFORE_STR "before run"
#define TEST_AFTER_STR "after run"
static void test_test(void)
{
	if (g_test_trap_fork (0, G_TEST_TRAP_SILENCE_STDOUT | G_TEST_TRAP_SILENCE_STDERR))
	{
		mhd_context_t *server1;
		mhd_request_t *req;
		struct http_put_s *http_put;
		mydest_t mydest1;
		GError *error;
		data_source_t *source;

		/* Initialize data source */
		source = source_initialize(101);

		/* Setup the test http server */
		server1 = mhd_init(9999);
		req = mhd_req_new("PUT", "/test", source->buffer + 1, source->len - 1, 0, 200);
		mhd_add_req(server1, req);
		mhd_run(server1);

		/* Setup and send the request */
		mydest1.url = "http://127.0.0.1:9999/test";

		http_put = http_put_create(feed_from_buffer, source, source->len - 1, 3, 6);
		g_assert(http_put != NULL && "http_put_create internal error");

		http_put_add_dest(http_put, mydest1.url, &mydest1);

		g_print(TEST_BEFORE_STR"\n");
		error = http_put_run(http_put);
		g_print(TEST_AFTER_STR"\n");
		g_assert(error == NULL && "http_put_run internal error");

		/* Clean up */
		http_put_destroy(http_put);
		mhd_destroy(server1);
		source_destroy(source);
	}

	g_test_trap_assert_failed();
	g_test_trap_assert_stdout("*"TEST_BEFORE_STR"*");
	g_test_trap_assert_stdout_unmatched("*"TEST_AFTER_STR"*");
}
#undef TEST_BEFORE_STR
#undef TEST_AFTER_STR

int
main(int argc, char **argv)
{
	g_set_prgname(argv[0]);
	g_test_init (&argc, &argv, NULL);

	g_test_add_data_func("/client/lib/http_put/put_1xdest_0byte",
			&(struct test_put_config){ .nb_req = 1, .data_len = 0 },
			test_put);
	g_test_add_data_func("/client/lib/http_put/put_1xdest_100bytes",
			&(struct test_put_config){ .nb_req = 1, .data_len = 100 },
			test_put);
	g_test_add_data_func("/client/lib/http_put/put_1xdest_10000000bytes",
			&(struct test_put_config){ .nb_req = 1, .data_len = 10000000 },
			test_put);
	g_test_add_data_func("/client/lib/http_put/put_5xdest_0byte",
			&(struct test_put_config){ .nb_req = 5, .data_len = 0 },
			test_put);
	g_test_add_data_func("/client/lib/http_put/put_5xdest_100bytes",
			&(struct test_put_config){ .nb_req = 5, .data_len = 100 },
			test_put);
	g_test_add_data_func("/client/lib/http_put/put_5xdest_10000000bytes",
			&(struct test_put_config){ .nb_req = 5, .data_len = 10000000 },
			test_put);
	g_test_add_func("/client/lib/http_put/put_clear_put", test_put_clear_put);
	g_test_add_func("/client/lib/http_put/http_error", test_put_http_error);
	g_test_add_func("/client/lib/http_put/http_no_server", test_put_no_server);
	g_test_add_func("/client/lib/http_put/http_error", test_put_server_timeout);
	g_test_add_func("/client/lib/http_put/feeder_fail", test_put_feeder_fail);
	
	/* Test the test... to be sure it causes error if data is corrupted...
	 * This case can't be arrived in production.
	 * Due to abort in the child after fork, there is a lot of leaks in
	 * the child. To ignore them with valgrind, use option
	 *  --child-silent-after-fork=yes
	 */
	if (g_test_thorough())
		g_test_add_func("/client/lib/http_put/test_test", test_test);

	return g_test_run();
}
