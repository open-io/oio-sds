/*
OpenIO SDS unit tests
Copyright (C) 2017 OpenIO SAS, as part of OpenIO SDS

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

#include "../../sqliterepo/gridd_client_pool.c"

static void
test_increment_active_clients_limit (void)
{
	struct gridd_client_pool_s *pool = gridd_client_pool_create();

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 32;
	pool->active_clients_threshold = 1024;
	_increment_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 64);
	g_assert_cmpint(pool->active_clients_threshold, ==, 1024);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 1023;
	pool->active_clients_threshold = 1024;
	_increment_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 1024);
	g_assert_cmpint(pool->active_clients_threshold, ==, 1024);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 1024;
	pool->active_clients_threshold = 1024;
	_increment_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 1024);
	g_assert_cmpint(pool->active_clients_threshold, ==, 1024);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 64;
	pool->active_clients_threshold = 64;
	_increment_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 65);
	g_assert_cmpint(pool->active_clients_threshold, ==, 64);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 128;
	pool->active_clients_threshold = 64;
	_increment_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 129);
	g_assert_cmpint(pool->active_clients_threshold, ==, 64);
}

static void
test_decrement_active_clients_limit (void)
{
	struct gridd_client_pool_s *pool = gridd_client_pool_create();

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 32;
	pool->active_clients_threshold = 1024;
	_decrement_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 32);
	g_assert_cmpint(pool->active_clients_threshold, ==, 32);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 1024;
	pool->active_clients_threshold = 1024;
	_decrement_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 32);
	g_assert_cmpint(pool->active_clients_threshold, ==, 512);

	pool->active_clients_max = 1024;
	pool->active_clients_min = 32;
	pool->active_clients_limit = 512;
	pool->active_clients_threshold = 32;
	_decrement_active_clients_limit(pool);
	g_assert_cmpint(pool->active_clients_max, ==, 1024);
	g_assert_cmpint(pool->active_clients_min, ==, 32);
	g_assert_cmpint(pool->active_clients_limit, ==, 32);
	g_assert_cmpint(pool->active_clients_threshold, ==, 256);
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/sqliterepo/gridd_client_pool/increment_active_clients_limit",
			test_increment_active_clients_limit);
	g_test_add_func("/sqliterepo/gridd_client_pool/decrement_active_clients_limit",
			test_decrement_active_clients_limit);
	return g_test_run();
}
