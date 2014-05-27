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

#include "network_server.h"

static gchar *path = "/tmp/in";

struct network_server_s *server = NULL;

static void
__send_path(struct network_client_s *clt)
{
	network_client_send_slab(clt, data_slab_make_path(path, FALSE));
}

static void
transport_static_factory(gpointer factory_udata, struct network_client_s *clt)
{
	(void) factory_udata;

	memset(&(clt->transport), 0, sizeof(clt->transport));

	__send_path(clt);
	network_client_close_output(clt, 0);
}

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
}

static void
grid_main_specific_fini(void)
{
	if (server) {
		network_server_close_servers(server);
		network_server_clean(server);
		server = NULL;
	}
}

static gboolean
grid_main_configure(int argc, char **argv)
{
	(void) argc;
	(void) argv;

	network_server_bind_host_throughput(server, "127.0.0.1:6000", NULL,
			transport_static_factory);

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

