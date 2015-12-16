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
				"\"chunksize\":%i,"
				"\"storage_policy\":{"
					"\"rain32\":\"NONE:RAIN32:NONE\","
					"\"dupli3\":\"NONE:DUPLI3:NONE\","
					"\"classic\":\"NONE:DUPONETWO:NONE\","
					"\"polcheck\":\"NONE:DUPONETHREE:SIMCOMP\","
					"\"secure\":\"NONE:DUP_SECURE:NONE\""
				"},"
				"\"data_security\":{"
					"\"DUPLI3\":\"DUP:distance=0|nb_copy=3\","
					"\"RAIN32\":\"RAIN:distance=0|k=3|m=2\","
					"\"DUPONETWO\":\"DUP:distance=1|nb_copy=2\","
					"\"DUPONETHREE\":\"DUP:distance=1|nb_copy=3\","
					"\"DUP_SECURE\":\"DUP:distance=4|nb_copy=2\""
				"},"
				"\"data_treatments\":{"
					"\"SIMCOMP\":\"COMP:algo=ZLIB|blocksize=262144\""
				"},"
				"\"storage_class\":{"
					"\"GOLD\":\"SILVER:BRONZE:CLAY\","
					"\"SILVER\":\"BRONZE:CLAY\","
					"\"BRONZE\":\"CLAY\","
					"\"CLAY\":\"\""
				"},"
				"\"options\":{"
				"}"
			"}", "NS", 1024);

	memset(ni, 0, sizeof(struct namespace_info_s));
	namespace_info_reset(ni);
	GError *err = namespace_info_init_json(s, ni);
	g_assert_no_error(err);
	g_free(s);
}

static void
test_stgclass_not_found ()
{
	struct namespace_info_s ni;
	_init_ns(&ni);

	struct storage_class_s *sc = storage_class_init(&ni, "PLATINE");
	g_assert(sc == NULL);

	namespace_info_clear(&ni);
}

static void
test_stgclass_no_fallback ()
{
	struct namespace_info_s ni;
	_init_ns(&ni);

	struct storage_class_s *sc = storage_class_init(&ni, "CLAY");
	g_assert(sc != NULL);
	g_assert(0 == g_slist_length(sc->fallbacks));
	g_assert(storage_class_is_satisfied2(sc, "CLAY", TRUE));
	g_assert(storage_class_is_satisfied2(NULL, "CLAY", TRUE));
	g_assert(storage_class_is_satisfied("DUMMY", "CLAY"));
	g_assert(storage_class_is_satisfied("NONE", "CLAY"));
	g_assert(storage_class_is_satisfied("", "CLAY"));
	g_assert(storage_class_is_satisfied(NULL, "CLAY"));
	storage_class_clean(sc);

	namespace_info_clear(&ni);
}

static void
test_stgclass_with_fallback ()
{
	struct namespace_info_s ni;
	_init_ns(&ni);

	struct storage_class_s *sc = storage_class_init(&ni, "SILVER");
	g_assert(sc != NULL);
	g_assert(2 == g_slist_length(sc->fallbacks));
	g_assert(0 == strcmp("BRONZE", (gchar*) g_slist_nth_data(sc->fallbacks, 0)));
	g_assert(0 == strcmp("CLAY", (gchar*) g_slist_nth_data(sc->fallbacks, 1)));
	g_assert(!storage_class_is_satisfied2(sc, "CLAY", TRUE));
	g_assert(storage_class_is_satisfied2(sc, "CLAY", FALSE));
	storage_class_clean(sc);

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
	g_test_add_func("/metautils/stgclass/not_found", test_stgclass_not_found);
	g_test_add_func("/metautils/stgclass/with_fallback", test_stgclass_with_fallback);
	g_test_add_func("/metautils/stgclass/no_fallback", test_stgclass_no_fallback);
#if 0
	g_test_add_func("/metautils/datasec", test_datasec);
	g_test_add_func("/metautils/stgpol", test_stgpol);
#endif
	return g_test_run();
}
