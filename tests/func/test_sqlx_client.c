/*
OpenIO SDS sqlx
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <core/oio_core.h>
#include <core/oio_sds.h>
#include <sqlx/sqlx_client.h>
#include <sqlx/sqlx_client_local.h>
#include <sqlx/sqlx_client_direct.h>

#include "tests/common/test_sqlx_abstract.c"

static void
test_sds (void)
{
	struct oio_sqlx_client_factory_s *factory = NULL;
	struct oio_directory_s *dir = oio_directory__create_proxy ("NS");
	factory = oio_sqlx_client_factory__create_sds ("NS", dir);
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
	g_test_add_func("/sqlx/client/sds", test_sds);
	return g_test_run();
}
