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

#include <glib.h>

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqliterepo.h>
#include <sqliterepo/cache.h>
#include <sqliterepo/internals.h>

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
	GError *err = sqlx_cache_open_and_lock_base(cache, hn0, &id0);
	g_assert_no_error (err);

	for (int i=0; i<5 ;i++) {
		gint id = g_random_int();
		err = sqlx_cache_open_and_lock_base(cache, hn0, &id);
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
		gint id = g_random_int ();
		err = sqlx_cache_open_and_lock_base(cache, hn1, &id);
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
	for (int i=0; i<5 ;++i)
		_round_lock (cache);
	sqlx_cache_expire(cache, 0, 0);
	sqlx_cache_clean(cache);
}

static void
_round_init (void)
{
	sqlx_cache_t *cache = sqlx_cache_init();
	g_assert(cache != NULL);
	sqlx_cache_set_close_hook(cache, sqlite_close);
	sqlx_cache_debug(cache);
	sqlx_cache_expire(cache, 0, 0);
	sqlx_cache_clean(cache);
}

static void
test_init (void)
{
	for (int i=0; i<5 ;++i)
		_round_init ();
}

int
main(int argc, char ** argv)
{
	HC_TEST_INIT(argc, argv);
	g_test_add_func("/sqliterepo/cache/init", test_init);
	g_test_add_func("/sqliterepo/cache/lock", test_lock);
	return g_test_run();
}

