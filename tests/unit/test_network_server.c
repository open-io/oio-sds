/*
OpenIO SDS unit tests
Copyright (C) 2018 OpenIO SAS, as part of OpenIO SDS

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

#include <errno.h>

#include <glib.h>

#include <core/oio_core.h>
#include <core/internals.h>

#include <server/network_server.h>

#define GQ_SERVER() g_quark_from_static_string("oio.srv")


static void
_do_nothing(gpointer u UNUSED, struct network_client_s *client UNUSED)
{
}

static void
_test_bad_bind_address(const char *netloc)
{
	GError *err = NULL;
	struct network_server_s *srv = network_server_init();
	g_assert_nonnull(srv);
	network_server_bind_host(srv, netloc, NULL, _do_nothing);
	err = network_server_open_servers(srv);
	g_assert_error(err, GQ_SERVER(), EINVAL);
	g_clear_error(&err);
	network_server_clean(srv);
}

static void
test_bad_bind_address_quotes(void)
{
	_test_bad_bind_address("\"127.0.0.1\":12345");
}

static void
test_bad_bind_address_257(void)
{
	_test_bad_bind_address("257.0.0.1:12345");
}

static void
test_bad_bind_address_empty_ip(void)
{
	_test_bad_bind_address(":12345");
}

static void
test_bad_bind_address_empty_brackets(void)
{
	_test_bad_bind_address("[]:12345");
}

int
main(int argc, char **argv)
{
	OIO_TEST_INIT(argc, argv);
	g_test_add_func("/server/core/bad_bind_address/empty_brackets",
			test_bad_bind_address_empty_brackets);
	g_test_add_func("/server/core/bad_bind_address/empty_ip",
			test_bad_bind_address_empty_ip);
	g_test_add_func("/server/core/bad_bind_address/quotes",
			test_bad_bind_address_quotes);
	g_test_add_func("/server/core/bad_bind_address/257",
			test_bad_bind_address_257);
	return g_test_run();
}
