/*
OpenIO SDS sqliterepo
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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/election.h>
#include <sqliterepo/version.h>
#include <sqliterepo/sqlx_remote.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.sqlite")

static const char *
_get_id (gpointer ctx)
{
	(void) ctx;
	return "0.0.0.0:0";
}

static GError*
_get_peers (gpointer ctx, struct sqlx_name_s *n, gboolean nocache,
		gchar ***result)
{
	(void) ctx, (void) n, (void) nocache;
	*result = g_malloc0(sizeof(gchar*));
	return NULL;
}

static GError*
_get_vers (gpointer ctx, struct sqlx_name_s *n, GTree **result)
{
	(void) ctx, (void) n;
	*result = version_empty();
	return NULL;
}

static void
test_create_bad_config(void)
{
	struct election_manager_s *m = NULL;
	GError *err;

	struct replication_config_s cfg0 = { NULL, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg0, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg1 = { _get_id, NULL, _get_vers,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg1, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg2 = { _get_id, _get_peers, NULL,
		NULL, ELECTION_MODE_NONE};
	err = election_manager_create(&cfg2, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);

	struct replication_config_s cfg3 = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE+3};
	err = election_manager_create(&cfg3, &m);
	g_assert_error(err, GQ(), ERRCODE_PARAM);
	g_clear_error(&err);
}

static void
test_election_init(void)
{
	struct replication_config_s cfg = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	struct election_manager_s *m = NULL;
	GError *err = NULL;

	err = election_manager_create(&cfg, &m);
	g_assert_no_error(err);

	for (int i=0; i<8 ;++i) {
		struct sqlx_name_mutable_s n = {
			.ns="NS",
			.base="base",
			.type="type"
		};
		n.base = g_strdup_printf("base-%"G_GUINT32_FORMAT, g_random_int());
		err = election_init(m, sqlx_name_mutable_to_const(&n));
		g_assert_no_error(err);
		err = election_exit(m, sqlx_name_mutable_to_const(&n));
		g_assert_no_error(err);
		g_free (n.base);
	}

	election_manager_clean(m);
}

static void
test_create_ok(void)
{
	struct replication_config_s cfg = { _get_id, _get_peers, _get_vers,
		NULL, ELECTION_MODE_NONE};
	for (int i=0; i<8 ;++i) {
		struct election_manager_s *m = NULL;
		GError *err = election_manager_create(&cfg, &m);
		g_assert_no_error(err);
		election_manager_clean(m);
	}
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/sqlx/election/create_bad_config",
			test_create_bad_config);
	g_test_add_func("/sqlx/election/create_ok",
			test_create_ok);
	g_test_add_func("/sqlx/election/election_init",
			test_election_init);
	return g_test_run();
}
