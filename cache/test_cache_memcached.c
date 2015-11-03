/*
OpenIO SDS cache
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <core/oiolog.h>
#include <cache/cache.h>
#include <cache/cache_memcached.h>

#include "test_cache_abstract.c"

static void
test_cache_cycle_memcached (void)
{
	// TODO those should probably be passed as args
	char *ip = "127.0.0.1";
	int port = 11211;

	struct oio_cache_s * c = oio_cache_make_memcached (ip, port);

	test_cache_cycle (c);
	oio_cache_destroy (c);
}

int
main(int argc, char **argv)
{
	g_test_init(&argc, &argv, NULL);
	oio_log_lazy_init ();
	oio_log_init_level(GRID_LOGLVL_INFO);
	g_log_set_default_handler(oio_log_stderr, NULL);

	g_test_add_func("/cache/cycle/memcached", test_cache_cycle_memcached);
	return g_test_run();
}

