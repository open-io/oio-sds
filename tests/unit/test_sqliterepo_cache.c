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

#include <unistd.h>
#include <stdio.h>

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/internals.h>
#include <sqliterepo/sqliterepo_variables.h>

#undef GQ
#define GQ() g_quark_from_static_string("oio.sqlite")

const char *name0 = "AAAAAAA";
const char *name1 = "AAAAAAB";

static void
sqlite_close (gpointer handle)
{
	g_debug("Closing base with handle %p", handle);
}

static void
_round_lock(sqlx_cache_t *cache)
{
	hashstr_t *hn0 = NULL, *hn1 = NULL;
	HASHSTR_ALLOCA(hn0, name0);
	HASHSTR_ALLOCA(hn1, name1);

	gint id0;
	GError *err = sqlx_cache_open_and_lock_base(cache, hn0, FALSE, &id0, 0);
	g_assert_no_error (err);

	for (int i=0; i<5 ;i++) {
		gint id = oio_ext_rand_int();
		err = sqlx_cache_open_and_lock_base(cache, hn0, FALSE, &id, 0);
		g_assert_no_error (err);
		g_assert_cmpint(id0, ==, id);
	}
	for (int i=0; i<6 ;i++) {
		err = sqlx_cache_unlock_and_close_base(cache, id0, FALSE);
		g_assert_no_error (err);
	}
	err = sqlx_cache_unlock_and_close_base(cache, id0, FALSE);
	g_assert_error (err, GQ(), CODE_INTERNAL_ERROR);
	g_clear_error (&err);

	for (int i=0; i<5 ;i++) {
		gint id = oio_ext_rand_int ();
		err = sqlx_cache_open_and_lock_base(cache, hn1, FALSE, &id, 0);
		g_assert_no_error (err);
		err = sqlx_cache_unlock_and_close_base(cache, id, FALSE);
		g_assert_no_error (err);
	}
}

static void
test_lock (void)
{
	sqlx_cache_t *cache = sqlx_cache_init();
	g_assert(cache != NULL);
	sqlx_cache_set_close_hook(cache, sqlite_close);
	for (int j=g_random_int_range(3,5); j>0 ;j--) {
		for (int i=g_random_int_range(5,7); i>0 ;i--)
			_round_lock (cache);
		sqlx_cache_debug(cache);
		sqlx_cache_expire(cache, 0, 0);
	}
	sqlx_cache_clean(cache);
}

static void
_round_init (void)
{
	sqlx_cache_t *cache = sqlx_cache_init();
	g_assert(cache != NULL);
	for (int j=g_random_int_range(3,5); j>0 ;j--) {
		sqlx_cache_set_close_hook(cache, sqlite_close);
		sqlx_cache_debug(cache);
		sqlx_cache_expire(cache, 0, 0);
	}
	sqlx_cache_clean(cache);
}

static void
test_init (void)
{
	for (int i=g_random_int_range(3,5); i>0; i--)
		_round_init ();
}

static void
_test_cache_limit (sqlx_cache_t *cache, guint max)
{
	gint ids[max];

	// 1 Until the limit, Opens must succeed
	for (guint i=0; i<max ;++i) {
		gchar name[16];
		g_snprintf(name, sizeof(name), "base-%u", i);
		hashstr_t *hname = hashstr_create(name);
		GError *err = sqlx_cache_open_and_lock_base (
				cache, hname, FALSE, ids+i, 0);
		g_assert_no_error(err);
		g_assert_cmpint(ids[i], >=, 0);
		g_free(hname);
	}

	// 2 Then they must fail, past that limit
	do {
		gint id0 = -1;
		hashstr_t *hn = hashstr_create("X");
		GError *err = sqlx_cache_open_and_lock_base (cache, hn, FALSE, &id0, 0);
		g_assert_error (err, GQ(), CODE_UNAVAILABLE);
		g_clear_error (&err);
		g_free(hn);
	} while (0);

	// 3 a bit of cleanup
	for (guint i=0; i<max ;++i) {
		GError *err = sqlx_cache_unlock_and_close_base(cache, ids[i], FALSE);
		g_assert_no_error(err);
	}
}

static void
test_limit (void)
{
	guint all_maxes[] = {1, 2, 4, 8, 0};
	for (guint imax=0; all_maxes[imax] != 0 ;++imax) {

		sqliterepo_repo_max_bases_hard = all_maxes[imax];
		sqliterepo_repo_max_bases_soft = all_maxes[imax];
		sqlx_cache_t *cache = sqlx_cache_init();
		g_assert_nonnull(cache);
		_test_cache_limit (cache, sqliterepo_repo_max_bases_hard);
		if (sqliterepo_repo_max_bases_hard > 1) {
			sqliterepo_repo_max_bases_soft = sqliterepo_repo_max_bases_hard / 2;
			sqlx_cache_reconfigure(cache);
			_test_cache_limit (cache, sqliterepo_repo_max_bases_soft);
		}
		sqlx_cache_debug(cache);
		sqlx_cache_expire(cache, 0, 0);
		sqlx_cache_clean(cache);

		// restore a value that is high-enough
		sqliterepo_repo_max_bases_hard = 8192;
	}
}

int
main(int argc, char ** argv)
{
	HC_TEST_INIT(argc, argv);
	g_test_add_func("/sqliterepo/cache/init", test_init);
	g_test_add_func("/sqliterepo/cache/lock", test_lock);
	g_test_add_func("/sqliterepo/cache/limit", test_limit);
	return g_test_run();
}

