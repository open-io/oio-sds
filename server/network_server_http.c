#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.utils.test"
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <metautils/lib/metautils.h>

#include "internals.h"
#include "network_server.h"
#include "transport_http.h"

struct http_request_dispatcher_s *dispatcher = NULL;

struct network_server_s *server = NULL;

/* -------------------------------------------------------------------------- */

static enum http_rc_e
m1_handler(gpointer u, struct http_request_s *req, struct http_reply_ctx_s *reply)
{
	(void) u;
	if (0 != g_ascii_strcasecmp(req->req_uri, "/meta1"))
		return HTTPRC_NEXT;
	reply->set_body_gba(metautils_gba_from_string("META1 content..."));
	reply->set_status(200, "OK");
	reply->finalize();
	return HTTPRC_DONE;
}

static enum http_rc_e
m0_handler(gpointer u, struct http_request_s *req, struct http_reply_ctx_s *reply)
{
	(void) u;
	if (0 != g_ascii_strcasecmp(req->req_uri, "/meta0"))
		return HTTPRC_NEXT;
	reply->set_body_gba(metautils_gba_from_string("META0 content..."));
	reply->set_status(200, "OK");
	reply->finalize();
	return HTTPRC_DONE;
}

static enum http_rc_e
any_handler(gpointer u, struct http_request_s *request,
			struct http_reply_ctx_s *reply)
{
	(void) u;
	(void) request;
	reply->set_body_gba(metautils_gba_from_string("No handler suitable"));
	reply->set_status(404, "Not found");
	reply->finalize();
	return HTTPRC_DONE;
}

struct http_request_descr_s all_requests[] =
{
	{ "meta1", m1_handler },
	{ "meta0", m0_handler },
	{ "any", any_handler },
	{ NULL, NULL }
};

/* -------------------------------------------------------------------------- */

static void
grid_main_action(void)
{
	GError *err = NULL;

	g_assert(server != NULL);

	err = network_server_open_servers(server);
	g_assert(err == NULL);

	err = network_server_run(server);
	g_assert(err == NULL);

}

static struct grid_main_option_s *
grid_main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{NULL, 0, {.i=0}, NULL}
	};

	return options;
}

static void
grid_main_set_defaults(void)
{
	server = network_server_init();
	dispatcher = transport_http_build_dispatcher(NULL, all_requests);
}

static void
grid_main_specific_fini(void)
{
	if (server) {
		network_server_close_servers(server);
		network_server_clean(server);
		server = NULL;
	}
	if (dispatcher) {
		http_request_dispatcher_clean(dispatcher);
		dispatcher = NULL;
	}
}

static gboolean
grid_main_configure(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	network_server_bind_host_lowlatency(server, "127.0.0.1:6000",
			dispatcher, transport_http_factory);

	return TRUE;
}

static const char *
grid_main_get_usage(void)
{
	return "";
}

static void
grid_main_specific_stop(void)
{
	if (server)
		network_server_stop(server);
}

static struct grid_main_callbacks main_callbacks = {
	.options = grid_main_get_options,
	.action = grid_main_action,
	.set_defaults = grid_main_set_defaults,
	.specific_fini = grid_main_specific_fini,
	.configure = grid_main_configure,
	.usage = grid_main_get_usage,
	.specific_stop = grid_main_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main(argc, argv, &main_callbacks);
}

