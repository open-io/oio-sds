/*
OpenIO SDS functional tests
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

const char *ns = NULL;
const char *acct = NULL;
const char *user = NULL;

#include "tests/common/test_sqlx_abstract.c"

static void
test_sds (void)
{
	struct oio_sqlx_client_factory_s *factory = NULL;
	struct oio_directory_s *dir = oio_directory__create_proxy (ns);
	factory = oio_sqlx_client_factory__create_sds (ns, dir);
	g_assert_nonnull (factory);
	_test_round (factory);
	oio_sqlx_client_factory__destroy (factory);
	factory = NULL;
	oio_directory__destroy (dir);
	dir = NULL;
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	ns = g_getenv ("OIO_NS");
	acct = g_getenv ("OIO_ACCOUNT");
	user = g_getenv ("OIO_USER");
	g_assert_nonnull (g_getenv ("OIO_NS"));
	g_assert_nonnull (g_getenv ("OIO_ACCOUNT"));
	g_assert_nonnull (g_getenv ("OIO_USER"));
	g_test_add_func("/sqlx/client/sds", test_sds);
	return g_test_run();
}
