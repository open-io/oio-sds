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

#include <metautils/metautils.h>

#include "sqliterepo.h"
#include "cache.h"
#include "internals.h"

#define SCHEMA_META2 "CREATE TABLE IF NOT EXISTS content (" \
	" path TEXT NOT NULL PRIMARY KEY," \
	" size INTEGER NOT NULL" \
	")"

#define FAIL(E) g_error("<%s:%d> FAIL : (code=%d) %s", \
		__FUNCTION__, __LINE__,						\
		(E)->code, (E)->message)

static const gchar nsname[] = "NS";
static const gchar type[] = NAME_SRVTYPE_META2;
static const gchar name[] =
		"0123456789ABCDEF"
		"0123456789ABCDEF"
		"0123456789ABCDEF"
		"0123456789ABCDEF";
int
main(int argc, char **argv)
{
	guint i;
	GError *err = NULL;
	sqlx_repository_t *repo = NULL;

	HC_PROC_INIT(argv, GRID_LOGLVL_TRACE2);
	g_assert(argc == 2);

	err = sqlx_repository_init(argv[1], NULL, &repo);
	if (err != NULL)
		FAIL(err);

	for (i=0; i<5 ;i++) {
		err = sqlx_repository_configure_type(repo, type, SCHEMA_META2);
		if (err != NULL)
			FAIL(err);
	}

	for (i=0; i<20 ;i++) {

		g_debug("Test round");

		struct sqlx_sqlite3_s *sq3 = NULL;
		struct sqlx_name_s n = { .base = name, .type = type, .ns = nsname, };

		err = sqlx_repository_open_and_lock(repo, &n, SQLX_OPEN_LOCAL, &sq3, NULL);
		if (err != NULL)
			FAIL(err);
		g_debug("Base [%s|%s] open", type, name);

		err = sqlx_repository_unlock_and_close(sq3);
		if (err != NULL)
			FAIL(err);
		g_debug("Base [%s|%s] closed", type, name);
	}

	sqlx_repository_clean(repo);
	return 0;
}

