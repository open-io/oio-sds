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

const gchar *name0 = "AAAAAAA";
const gchar *name1 = "AAAAAAB";

static void
test_lock_unlock(sqlx_cache_t *cache, gint bd)
{
	GError *err;
	int i, max = 5;

	hashstr_t *hname = NULL;
	HASHSTR_ALLOCA(hname, name0);

	for (i=0; i<max ;i++) {
		err = sqlx_cache_open_and_lock_base(cache, hname, &bd);
		g_assert_no_error (err);
	}

	for (i=0; i<max ;i++) {
		err = sqlx_cache_unlock_and_close_base(cache, bd, FALSE);
		g_assert_no_error (err);
	}
}

static void
test_regular(sqlx_cache_t *cache)
{
	gint bd = -1;
	GError *err;

	hashstr_t *hname = NULL;
	HASHSTR_ALLOCA(hname, name0);

	err = sqlx_cache_open_and_lock_base(cache, hname, &bd);
	g_assert_no_error (err);
	g_debug("open(%s) = %d OK", name0, bd);

	test_lock_unlock(cache, bd);

	err = sqlx_cache_unlock_and_close_base(cache, bd, FALSE);
	g_assert_no_error (err);
	g_debug("close(%d) OK", bd);
}

static void
sqlite_close (gpointer handle)
{
	g_debug("Closing base with handle %p", handle);
}

int
main(int argc, char ** argv)
{
	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);

	(void) argc;
	sqlx_cache_t *cache = sqlx_cache_init();
	g_assert(cache != NULL);
	sqlx_cache_set_close_hook(cache, sqlite_close);

	test_regular(cache);

	sqlx_cache_debug(cache);
	sqlx_cache_expire(cache, 0, 0);
	sqlx_cache_clean(cache);
	return 0;
}

