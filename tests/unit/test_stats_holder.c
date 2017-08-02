/*
OpenIO SDS unit tests
Copyright (C) 2014 Worldline, as part of Redcurrant
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

#include "metautils/lib/metautils.h"

#undef GQ
#define GQ() g_quark_from_static_string("oio.server")

static void
_round_rrd (void)
{
	struct grid_single_rrd_s *rrd = grid_single_rrd_create(2, 60);
	for (int i=0; i<16 ;++i) {
		grid_single_rrd_push(rrd, 1 + 61*i, 0);
		grid_single_rrd_push(rrd, 61*i, 0);
	}
	grid_single_rrd_destroy(rrd);
}

static void
test_rrd (void)
{
	for (int i=0; i<16 ;++i)
		_round_rrd ();
}

int
main (int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/server/rrd", test_rrd);
	return g_test_run();
}

