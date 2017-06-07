/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/storage_policy.h>
#include <metautils/lib/storage_policy_internals.h>

static void
_init_ns (struct namespace_info_s *ni)
{
	gchar *s = g_strdup_printf(
			"{"
				"\"ns\":\"%s\","
				"\"storage_policy\":{"
					"\"rain32\":\"5RAWX:RAIN32\","
					"\"dupli3\":\"3RAWX:DUPLI3\","
					"\"classic\":\"2RAWX:DUPONETWO\","
					"\"polcheck\":\"3RAWX3ZONES:DUPONETHREE\","
					"\"secure\":\"2RAWX2ZONES:DUP_SECURE\""
				"},"
				"\"data_security\":{"
					"\"DUPLI3\":\"plain/distance=0,nb_copy=3\","
					"\"RAIN32\":\"ec/algo=isa_l_rs_vand,distance=0,k=3,m=2\","
					"\"DUPONETWO\":\"plain/distance=1,nb_copy=2\","
					"\"DUPONETHREE\":\"plain/distance=1,nb_copy=3\","
					"\"DUP_SECURE\":\"plain/distance=4,nb_copy=2\""
				"},"
				"\"service_pools\":{"
					"\"2RAWX\":\"2,rawx\","
					"\"3RAWX\":\"3,rawx\","
					"\"5RAWX\":\"5,rawx\","
					"\"3RAWX3ZONES\":\"1,rawx-USA,rawx;1,rawx-EUROPE,rawx;1,rawx-ASIA,rawx\","
					"\"2RAWX2ZONES\":\"1,rawx-USA,rawx-EUROPE;1,rawx-ASIA\""
				"},"
			"}", "NS");

	memset(ni, 0, sizeof(struct namespace_info_s));
	namespace_info_reset(ni);
	GError *err = namespace_info_init_json(s, ni);
	g_assert_no_error(err);
	g_free(s);
}

static void
test_service_pool(void)
{
	struct namespace_info_s ni;
	_init_ns(&ni);
	g_assert_cmpuint(g_hash_table_size(ni.service_pools), ==, 5);
	namespace_info_clear(&ni);
}

#if 0
static void
test_datasec ()
{
	// @todo TODO Not yet implemented
}

static void
test_stgpol ()
{
	// @todo TODO Not yet implemented
}
#endif

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/metautils/svcpool", test_service_pool);
#if 0
	g_test_add_func("/metautils/datasec", test_datasec);
	g_test_add_func("/metautils/stgpol", test_stgpol);
#endif
	return g_test_run();
}
