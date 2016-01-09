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

#include <core/oiourl.h>
#include <core/oiodir.h>
#include <metautils/lib/metautils.h>
#include <sqlx/sqlx_client.h>
#include <sqlx/sqlx_client_local.h>
#include <sqlx/sqlx_client_direct.h>

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
