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

#include <core/oio_core.h>
#include <cache/cache.h>
#include <cache/cache_redis.h>

#include "tests/common/test_cache_abstract.c"

#define DEFAULT_IP "127.0.0.1"
#define DEFAULT_PORT 6379
static void
test_cache_cycle_redis (void)
{
	
	char *ip = DEFAULT_IP;
	int port = DEFAULT_PORT;
	
	struct timeval timeout = {0,0};

	struct oio_cache_s * c = oio_cache_make_redis (ip, port, timeout, -1);

	test_cache_cycle (c);
	oio_cache_destroy (c);
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/cache/cycle/redis", test_cache_cycle_redis);
	return g_test_run();
}
