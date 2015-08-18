/*
OpenIO SDS server
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

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/epoll.h>

#include <metautils/lib/metautils.h>

#include "network_server.h"

static struct network_server_s *server = NULL;

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

	network_server_bind_host_throughput(server, "127.0.0.1:6000",
			NULL, transport_devnull_factory);

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

