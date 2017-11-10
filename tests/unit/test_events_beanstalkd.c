/*
OpenIO SDS unit tests
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

#include <stdlib.h>
#include <assert.h>
#include <poll.h>
#include <unistd.h>

#include <glib.h>
#include <core/oio_core.h>
#include <metautils/lib/metautils.h>
#include <server/network_server.h>
#include <server/server_variables.h>
#include <events/oio_events_queue.h>
#include <events/oio_events_queue_beanstalkd.h>

#include "../../events/oio_events_queue_beanstalkd.c"

#define BAD_FORMAT_STR "BAD_FORMAT\r\n"
#define OUT_OF_MEMORY_STR "OUT_OF_MEMORY\r\n"
#define INTERNAL_ERROR_STR "INTERNAL_ERROR\r\n"
#define UNKNOWN_COMMAND_STR "UNKNOWN_COMMAND\r\n"
#define JOB_TOO_BIG_STR "JOB_TOO_BIG\r\n"
#define DRAINING_STR "DRAINING\r\n"
#define EXPECTED_CRLF "EXPECTED_CRLF\r\n"
#define PUT_REQUEST "put"
#define USE_REQUEST "use"
#define PORT_USED 4269

static void
_wrap_with_beanstalkd (gchar ** requests, gchar ** replies,
		void (*test_hook) (struct oio_events_queue_s *q))
{
	gchar ** next_request = requests;
	gchar ** next_reply = replies;

	/* Each time a request has been sent, check its format matches the
	 * expected input then return the prepared reply. */
	void _on_line (struct network_client_s *clt, const char *request) {
		GRID_DEBUG("< %s", request);

		g_assert_true (next_request != NULL && *next_request != NULL);
		GError *err = NULL;
		GRegex *regex = g_regex_new(*next_request, G_REGEX_NEWLINE_CRLF,
				G_REGEX_MATCH_NEWLINE_CRLF, &err);
		g_assert_no_error (err);
		g_assert_nonnull (regex);
		GMatchInfo *mi = NULL;
		GRID_TRACE("~ %s", *next_request);
		g_assert_true (g_regex_match (regex, request, 0, &mi));
		g_assert_nonnull (mi);
		g_match_info_free (mi);
		g_regex_unref(regex);

		/* the requests passed all the tests, send the prepared reply */
		g_assert_true (next_reply != NULL && *next_reply != NULL);
		if ((*next_reply)[0]) {
			GRID_DEBUG("> %s", *next_reply);
			network_client_send_slab (clt,
					data_slab_make_static_string(*next_reply));
		}
		++ next_reply;
		++ next_request;
	}

	/* Each time a buffer is received, find \n and manage the preceeding
	 * characters as a request */
	int _on_input (struct network_client_s *clt) {
		GByteArray *gba = (GByteArray*) clt->transport.client_context;
		g_assert_nonnull (gba);

		GRID_TRACE("beanstalkd: input!");
		while (data_slab_sequence_has_data(&(clt->input))) {
			struct data_slab_s *ds = data_slab_sequence_shift(&clt->input);
			g_assert_nonnull(ds);

			if (!data_slab_has_data(ds)) {
				data_slab_free(ds);
				continue;
			}

			/* Consume some bytes */
			guint8 *buf = NULL;
			gsize len = 1024 * 1024;
			g_assert_true (data_slab_consume(ds, &buf, &len));
			if (len > 0 && buf != NULL)
				g_byte_array_append(gba, buf, len);

			/* maybe match a line */
retry:
			if (gba->len > 0) {
				for (guint i=0; i<gba->len ;++i) {
					if (gba->data[i] != ((guint8)'\n'))
						continue;
					/* We have a line! */
					gchar *str = g_memdup (gba->data, i+2);
					str[i+1] = 0;
					g_byte_array_remove_range(gba, 0, i+1);
					if (*str) _on_line (clt, str);
					g_free (str);
					/* we consumed data, maybe there is another line ready */
					goto retry;
				}
			}
			if (data_slab_has_data(ds))
				data_slab_sequence_unshift(&(clt->input), ds);
			else
				data_slab_free(ds);
		}
		return clt->transport.waiting_for_close ? RC_NODATA : RC_PROCESSED;
	}

	/* For each connection, prepare a line parser */
	void _factory_transport_line (gpointer u UNUSED, struct network_client_s *client) {
		GRID_DEBUG("beanstalkd: connection fd=%d", client->fd);
		client->transport.client_context =
			(struct transport_client_context_s *) g_byte_array_new();
		client->transport.clean_context =
			(network_transport_cleaner_f) metautils_gba_unref;
		client->transport.notify_input = _on_input;
		client->transport.notify_error = NULL;
		network_client_allow_input(client, TRUE);
	}

	/* Prepare a fake beanstalkd server, bond to a random port */
	struct network_server_s *srv = network_server_init();
	g_assert_nonnull (srv);
	network_server_bind_host(srv, "127.0.0.1:0", NULL, _factory_transport_line);
	g_assert_no_error (network_server_open_servers (srv));

	/* Run it in a separate thread */
	gpointer _server (gpointer p) {
		GRID_TRACE("beanstalkd: thread starting");
		GError *err = network_server_run ((struct network_server_s *)p, NULL);
		g_assert_no_error (err);
		return NULL;
	}
	GThread *th = g_thread_new("server", _server, srv);

	/* Run the test in the current thread */
	struct oio_events_queue_s *q = NULL;
	gchar **urlv = network_server_endpoints (srv);
	STRINGV_STACKIFY(urlv);
	g_assert_nonnull (urlv);
	g_assert_nonnull (*urlv);
	GRID_DEBUG("beanstalkd url=%s", *urlv);
	g_assert_no_error (oio_events_queue_factory__create_beanstalkd (*urlv, &q));
	g_assert_nonnull (q);
	if (test_hook)
		(*test_hook)(q);

	gboolean _running (gboolean pending) { return pending; }
	oio_events_queue__run (q, _running);
	oio_events_queue__destroy (q);

	/* stop the server */
	network_server_stop (srv);
	g_thread_join (th);
	network_server_close_servers (srv);
	network_server_clean (srv);
}

static void
test_with_check (void)
{
	gchar *requests[] = {
		"use [A-Za-z0-9]+\\R",
		"stats\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "1\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "2\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "3\\R",

		"use [A-Za-z0-9]+\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "3\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "4\\R",

		"use [A-Za-z0-9]+\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "4\\R",
		NULL
	};
	gchar *replies[] = {
		"USING oio\r\n",
		"OK 0\r\n",

		"", "INSERTED 1\r\n",
		"", "INSERTED 2\r\n",
		"", "OUT_OF_MEMORY 3\r\n",
		/* bad reply -> retry */
		"USING oio\r\n",
		"", "INSERTED 3\r\n",
		"", "ARGL 4\r\n",
		/* bad reply -> no retry */
		"USING oio\r\n",
		NULL
	};

	void check_return (GError *err) {
		static volatile guint i = 0;
		gboolean expected[] = {
			TRUE, TRUE,
			TRUE, TRUE, FALSE,
			TRUE, TRUE, FALSE,
			TRUE,
		};
		if (expected[i++])
			g_assert_no_error(err);
		else
			g_assert_nonnull(err);
	}

	void t(struct oio_events_queue_s *q) {
		intercept_errors = check_return;
		oio_events_queue__send(q, g_strdup("1"));
		oio_events_queue__send(q, g_strdup("2"));
		oio_events_queue__send(q, g_strdup("3"));
		oio_events_queue__send(q, g_strdup("4"));
	}

	oio_events_beanstalkd_check_period = G_TIME_SPAN_SECOND; /* != 0 */
	_wrap_with_beanstalkd(requests, replies, t);
}

static void
test_without_check (void)
{
	gchar *requests[] = {
		"use [A-Za-z0-9]+\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "1\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "2\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "3\\R",

		"use [A-Za-z0-9]+\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "3\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "4\\R",

		"use [A-Za-z0-9]+\\R",
		"put [[:digit:]]+ [[:digit:]]+ [[:digit:]]+ [[:digit:]]+\\R", "4\\R",
		NULL
	};
	gchar *replies[] = {
		"USING oio\r\n",

		"", "INSERTED 1\r\n",
		"", "INSERTED 2\r\n",
		"", "OUT_OF_MEMORY 3\r\n",
		/* bad reply -> retry */
		"USING oio\r\n",
		"", "INSERTED 3\r\n",
		"", "ARGL 4\r\n",
		/* bad reply -> no retry */
		"USING oio\r\n",
		NULL
	};

	void check_return (GError *err) {
		static volatile guint i = 0;
		gboolean expected[] = {
			TRUE,
			TRUE, TRUE, FALSE,
			TRUE, TRUE, FALSE,
			TRUE,
		};
		if (expected[i++])
			g_assert_no_error(err);
		else
			g_assert_nonnull(err);
	}
	void t(struct oio_events_queue_s *q) {
		intercept_errors = check_return;
		oio_events_queue__send(q, g_strdup("1"));
		oio_events_queue__send(q, g_strdup("2"));
		oio_events_queue__send(q, g_strdup("3"));
		oio_events_queue__send(q, g_strdup("4"));
	}

	oio_events_beanstalkd_check_period = 0;
	_wrap_with_beanstalkd(requests, replies, t);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc, argv);
	g_test_add_func("/event/beanstalkd/with_check", test_with_check);
	g_test_add_func("/event/beanstalkd/without_check", test_without_check);
	server_fd_max_passive = metautils_syscall_count_maxfd();
	return g_test_run();
}
