/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.sqlx.test"
#endif

#include <unistd.h>
#include <stdio.h>

#include <glib.h>

#include <metautils.h>

#include "./internals.h"
#include "./cache.h"

#define FAIL(E) g_error("<%s:%d> FAIL : (code=%d) %s", \
		__FUNCTION__, __LINE__,						\
		(E)->code, (E)->message)

const gchar *name0 = "AAAAAAA";
const gchar *name1 = "AAAAAAB";

static GQuark gquark_log;

static void
test_fail(sqlx_cache_t *cache)
{
	GError *err;

	/* Lock an negative base ID */
	err = sqlx_cache_lock_base(cache, -1);
	if (err == NULL) {
		err = g_error_new(gquark_log, 0, "DESIGN ERROR");
		FAIL(err);
	}
	g_debug("sqlx_cache_lock_base(-1) : failed as expected : code=%d %s", err->code, err->message);
	g_error_free(err);


	/* Lock an big base ID */
	err = sqlx_cache_lock_base(cache, 32767);
	if (err == NULL) {
		err = g_error_new(gquark_log, 0, "DESIGN ERROR");
		FAIL(err);
	}
	g_debug("sqlx_cache_lock_base(32767) : failed as expected : code=%d %s", err->code, err->message);
	g_error_free(err);


	/* Lock an closed base ID */
	err = sqlx_cache_lock_base(cache, 0);
	if (err == NULL) {
		err = g_error_new(gquark_log, 0, "DESIGN ERROR");
		FAIL(err);
	}
	g_debug("sqlx_cache_lock_base(0) : failed as expected : code=%d %s", err->code, err->message);
	g_error_free(err);
}

static void
test_lock_unlock(sqlx_cache_t *cache, gint bd)
{
	GError *err;
	int i, max = 5;

	for (i=0; i<max ;i++) {
		/* Lock the same base */
		err = sqlx_cache_lock_base(cache, bd);
		if (err != NULL)
			FAIL(err);
	}

	for (i=0; i<max ;i++) {
		/* Release the same base */
		err = sqlx_cache_unlock_base(cache, bd);
		if (err != NULL)
			FAIL(err);
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
	if (err != NULL)
		FAIL(err);
	g_debug("open(%s) = %d OK", name0, bd);

	test_lock_unlock(cache, bd);

	err = sqlx_cache_unlock_and_close_base(cache, bd, FALSE);
	if (err != NULL)
		FAIL(err);
	g_debug("close(%d) OK", bd);
}

static void
sqlite_close(const struct hashstr_s *name, gpointer handle)
{
	g_debug("Closing base [%s] with handle %p", hashstr_str(name), handle);
}

int
main(int argc, char ** argv)
{
	sqlx_cache_t *cache = NULL;

	(void) argc;
	(void) argv;
	if (!g_thread_supported())
		g_thread_init(NULL);
	g_log_set_handler(NULL, G_LOG_LEVEL_MASK|G_LOG_FLAG_FATAL,
			logger_stderr, NULL);
	gquark_log = g_quark_from_static_string(G_LOG_DOMAIN);

	cache = sqlx_cache_init();
	g_assert(cache != NULL);
	sqlx_cache_set_close_hook(cache, sqlite_close);

	test_fail(cache);
	test_regular(cache);

	sqlx_cache_debug(cache);
	sqlx_cache_expire(cache, 0, NULL, NULL);
	sqlx_cache_clean(cache);
	return 0;
}

