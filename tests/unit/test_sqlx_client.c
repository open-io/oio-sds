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

#include <core/oio_core.h>
#include <core/oio_sds.h>
#include <sqlx/sqlx_client.h>
#include <sqlx/sqlx_client_local.h>
#include <sqlx/sqlx_client_direct.h>

const char *ns = "NS";
const char *acct = "ACCT";
const char *user = "JFS";

#include "tests/common/test_sqlx_abstract.c"

static void
test_mem (void)
{
	struct oio_sqlx_client_factory_s *factory = NULL;
	factory = oio_sqlx_client_factory__create_local ("NS",
			"CREATE TABLE IF NOT EXISTS admin (k TEXT PRIMARY KEY, v TEXT NOT NULL);"
			"CREATE TABLE IF NOT EXISTS sequence (i INTEGER PRIMARY KEY, v TEXT NOT NULL);"
			"CREATE TABLE IF NOT EXISTS sequence2 (i INT PRIMARY KEY, v TEXT NOT NULL);");
	g_assert_nonnull (factory);
	_test_round (factory);
	oio_sqlx_client_factory__destroy (factory);
	factory = NULL;
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/sqlx/client/mem", test_mem);
	return g_test_run();
}
