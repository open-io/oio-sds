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

#include <unistd.h>
#include <stdio.h>

#include <metautils/lib/metautils.h>

#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/sqlx_remote.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/internals.h>

#define SCHEMA \
	"CREATE TABLE IF NOT EXISTS admin (k TEXT PRIMARY KEY, v NOT NULL);" \
	"CREATE TABLE IF NOT EXISTS content (" \
	" path TEXT NOT NULL PRIMARY KEY," \
	" size INTEGER NOT NULL" \
	")"

static const gchar nsname[] = "NS";
static const gchar type[] = NAME_SRVTYPE_META2;
static const gchar name[] =
		"0123456789ABCDEF"
		"0123456789ABCDEF"
		"0123456789ABCDEF"
		"0123456789ABCDEF";

static void
_locator (gpointer u, const struct sqlx_name_s *n, GString *file_name)
{
	(void) u;
	g_assert_nonnull (n);
	g_assert_nonnull (file_name);
	g_assert_nonnull (n->ns);
	g_assert_nonnull (n->base);
	g_assert_nonnull (n->type);
	g_string_assign (file_name, ":memory:");
}

static void
_round_init (void)
{
	struct sqlx_repo_config_s cfg = {0};
	sqlx_repository_t *repo = NULL;
	GError *err;

	err = sqlx_repository_init("/tmp", &cfg, &repo);
	g_assert_no_error (err);
	for (int i=0; i<5 ;i++)
		sqlx_repository_set_locator (repo, _locator, NULL);
	for (int i=0; i<5 ;i++)
		g_assert_true (sqlx_repository_running (repo));
	for (int i=0; i<5 ;i++) {
		err = sqlx_repository_configure_type(repo, type, SCHEMA);
		g_assert_no_error (err);
	}
	sqlx_repository_clean(repo);
}

static void
test_init (void)
{
	for (int i=0; i<16 ;i++)
		_round_init ();
}

static void
_round_open_close (void)
{
	struct sqlx_repo_config_s cfg = {0};
	sqlx_repository_t *repo = NULL;
	GError *err;

	err = sqlx_repository_init("/tmp", &cfg, &repo);
	g_assert_no_error (err);
	g_assert_true (sqlx_repository_running (repo));
	err = sqlx_repository_configure_type(repo, type, SCHEMA);
	g_assert_no_error (err);
	sqlx_repository_set_locator (repo, _locator, NULL);

	for (int i=0; i<5 ;i++) {
		struct sqlx_sqlite3_s *sq3 = NULL;
		struct sqlx_name_s n = { .base = name, .type = type, .ns = nsname, };

		err = sqlx_repository_open_and_lock(repo, &n, SQLX_OPEN_LOCAL, &sq3, NULL);
		g_assert_no_error (err);
		g_assert_nonnull (sq3);

		sqlx_admin_set_i64 (sq3, "plop", 5345);
		sqlx_admin_save_lazy_tnx (sq3);

		struct sqlx_repctx_s *repctx = NULL;
		err = sqlx_transaction_begin (sq3, &repctx);
		g_assert_no_error (err);

		sqlx_admin_set_i64 (sq3, "plop", 5346);
		sqlx_admin_save_lazy (sq3);
		sqlx_admin_set_i64 (sq3, "plop", 5347);

		err = sqlx_transaction_end (repctx, SYSERR("fake error"));
		g_assert_error (err, GQ(), CODE_INTERNAL_ERROR);
		g_clear_error (&err);

		err = sqlx_repository_unlock_and_close(sq3);
		g_assert_no_error (err);
	}

	sqlx_repository_clean(repo);
}

static void
test_open_close (void)
{
	for (int i=0; i<5 ;i++)
		_round_open_close ();
}

int
main(int argc, char **argv)
{
	HC_TEST_INIT(argc,argv);
	g_test_add_func("/sqliterepo/init", test_init);
	g_test_add_func("/sqliterepo/open", test_open_close);
	return g_test_run();
}

