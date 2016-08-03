#include "server.h"
#include <assert.h>
#include <poll.h>
#include <unistd.h>
#include <events/oio_events_queue.h>
#include <events/oio_events_queue_beanstalkd.h>
#include <core/oio_core.h>
#include <stdlib.h>
#include <metautils/lib/metautils.h>
#include <glib/gprintf.h>
#include "../../../events/oio_events_queue_beanstalkd.c"
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

static const char random_chars[] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789"
	"+/;.$_()";

static GError *
_run_verify_result (struct oio_events_queue_s *self,
		    gboolean (*running) (gboolean pending))
{
	struct _queue_BEANSTALKD_s *q = (struct _queue_BEANSTALKD_s *)self;
	gchar *saved = NULL;
	int fd = -1;
	
	EXTRA_ASSERT (q != NULL && q->vtable == &vtable_BEANSTALKD);
	EXTRA_ASSERT (running != NULL);
	
	while ((*running)(0 < g_async_queue_length(q->queue))) {
		_maybe_send_overwritable(self);
		
		/* find an event, prefering the last that failed */
		gchar *msg = saved;
		saved = NULL;
		if (!msg) msg = g_async_queue_timeout_pop (q->queue, G_TIME_SPAN_SECOND);
		if (!msg) continue;
		
		/* forward the event */
		if (*msg) {
			
			/* lazy-reconnection, with backoff sleeping to avoid crazy-looping */
			if (fd < 0) {
				GError *err = NULL;
				fd = sock_connect(q->endpoint, &err);
				if (!err)
					err = _poll_out (fd);
				if (!err)
					err = _use_tube (fd, q->tube);
				g_assert(!err);
			}
			
			/* prepare the header, and the buffers to be sent */
			if (!_put (fd, msg, strlen(msg))) {
				sock_set_linger(fd, 1, 1);
				metautils_pclose (&fd);
				saved = msg;
				msg = NULL;
			}
		}
	}
	
	if (fd >= 0)
		sock_set_linger(fd, 1, 1);
	metautils_pclose (&fd);
	if (saved)
		g_async_queue_push (q->queue, saved);
	saved = NULL;
	return NULL;
}	
	

				
static gboolean
send_some_things (gboolean p)
{
	return p;
}

static void
test_message_ok (void)
{
	struct oio_events_queue_s *q = NULL;
	gchar *ip = g_strdup_printf("127.0.0.1:%d", PORT_USED);
	GError *err = oio_events_queue_factory__create_beanstalkd(ip, &q);
	g_assert_no_error(err);
	oio_events_queue__set_max_pending(q, 100);
	g_assert_nonnull(q);
	gchar content[32];
	oio_str_randomize(content, oio_ext_rand_int_range(7,32), random_chars);
	oio_events_queue__send(q, content);
	oio_events_queue__run(q, send_some_things);
	oio_events_queue__destroy(q);
	g_free(ip);
}


static gboolean
is_command(gchar *command)
{
	gchar *possible_commands [3]= {PUT_REQUEST, USE_REQUEST, NULL};
	for (guint count_possible_commands = 0;
	     count_possible_commands < g_strv_length(possible_commands);
	     count_possible_commands++) {
		if (g_strcmp0(possible_commands[count_possible_commands],
			      command) == 0)
			return TRUE;
	}
	return FALSE;
}

static gchar*
_get_response_request(char **params)
{
	if (g_str_has_prefix(params[0], PUT_REQUEST) == 0) {
		gchar *last_char;
		gchar *pri = params[1];
		// 2**32
		long val = strtol(pri, &last_char, 10);
		if (val > 4294967295)
			return g_strdup(BAD_FORMAT_STR);
		char *bytes = params [2];
		char *data = params [3];
		val = strtol(bytes, &last_char, 10);
		if ((gint) strlen(data) != val)
			return g_strdup(JOB_TOO_BIG_STR);
		// We don't care about the ID
		return g_strdup("INSERTED 1234\r\n");
	}
		return g_strdup_printf("USING %s\r\n", params[4]);
}

static gchar*
_manage_request(gchar *request)
{
	// TODO : The name can include some specials characters
	gchar *regexp = "put ([[:digit:]]+) [[:digit:]]+ [[:digit:]]+ ([[:digit:]]+)\\R([[:ascii:]]+)\\R|use ([A-Za-z0-9./$+;_()][A-Za-z0-9.\\-/$+;_()]*)\\R";
	GMatchInfo *match_info;
	GError *err = NULL;
	GRegex *regex = g_regex_new(regexp, 0, 0, &err);
	if (err) {
		return g_strdup(INTERNAL_ERROR_STR);
	}
	gboolean has_matched = g_regex_match(regex, request,
					     G_REGEX_NEWLINE_CRLF,
					     &match_info);
	gchar **params_to_recover;
	gchar *result = NULL;
	if (!has_matched){
		params_to_recover = g_strsplit(g_strdup(request)," ", -1);
		if (g_strv_length(params_to_recover) <= 1) {
			result = g_strdup(BAD_FORMAT_STR);
		}
		else if (is_command(params_to_recover[0])) {
			result = g_strdup(BAD_FORMAT_STR);
		}
		else
			result = g_strdup(UNKNOWN_COMMAND_STR);
		goto free_and_return;
			
	}
	params_to_recover = g_match_info_fetch_all(match_info);
	result = _get_response_request(params_to_recover);
	
 free_and_return:
	g_strfreev(params_to_recover);
	g_match_info_free(match_info);
	g_regex_unref(regex);
	return result;
	
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc, argv);
	vtable_BEANSTALKD.run = _run_verify_result;
	launch_server(PORT_USED, _manage_request);
	g_test_add_func("/ok/test_message_ok", test_message_ok);
	g_test_run();
	stop_server();
	return 0;
}
