/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <unistd.h>

#include <glib.h>

#include "./loggers.h"
#include "./network_server.h"
#include "./grid_daemon.h"
#include "./transport_gridd.h"
#include "./common_main.h"

static GString *url = NULL;

static struct network_server_s *server = NULL;

static struct gridd_request_dispatcher_s *dispatcher = NULL;

static void
main_action(void)
{
	GError *err = NULL;

	dispatcher = transport_gridd_build_empty_dispatcher();
	server = network_server_init();
	grid_daemon_bind_host(server, url->str, dispatcher);

	err = network_server_open_servers(server);
	g_assert(err == NULL);

	err = network_server_run(server);
	g_assert(err == NULL);

	network_server_close_servers(server);
	network_server_clean(server);
	server = NULL;

	gridd_request_dispatcher_clean(dispatcher);
	dispatcher = NULL;
}

static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{"Endpoint", OT_STRING, {.str=&url}, "URL to bind to"},
		{NULL, 0, {.i=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	url = g_string_new("127.0.0.1:0");
}

static void
main_specific_fini(void)
{
}

static gboolean
main_configure(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	return TRUE;
}

static const char *
main_get_usage(void)
{
	return "";
}

static void
main_specific_stop(void)
{
	if (server)
		network_server_stop(server);
}

static struct grid_main_callbacks main_callbacks = {
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop,
};

int
main(int argc, char ** argv)
{
	return grid_main_cli(argc, argv, &main_callbacks);
}

