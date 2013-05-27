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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.client.bench.m2v2_db_convert"
#endif

#include <stdlib.h>
#include <glib.h>
#include <glib/gprintf.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "gs_bench.h"
#include "grid_client.h"
#include "metautils.h"
#include "../../../meta2v2/meta2_backend_dbconvert.h"

static gboolean
test(const gchar *db_path, sqlite3 *db)
{
	GTimeVal timeval;
	GError *e;

	GTimer *timer = g_timer_new();
	e = m2_convert_db(db);
	guint elapsed = 1000 * g_timer_elapsed(timer, NULL);
	g_timer_destroy(timer);

	g_get_current_time(&timeval);
	g_printf("%lli,%u,%s,%s,,,%s,0\n",
			(timeval.tv_sec*1000LL)+(timeval.tv_usec/1000),
			elapsed,
			db_path,
			e ? e->message : "",
			e ? "true" : "false");
	if (e)
		return TRUE;

	g_error_free(e);
	return FALSE;
}

static void
_convert_db(gpointer _m2_db_path, gpointer _pret)
{
	sqlite3 *db = NULL;
	gboolean *pret = _pret;

	if (SQLITE_OK != sqlite3_open(_m2_db_path, &db)) {
		*pret = FALSE;
	}
	else {
		if (!test(_m2_db_path, db)) {
			*pret = FALSE;
		}
		sqlite3_close(db);
	}
}

gboolean m2v2_db_convert(struct scenario_data *sdata, gchar *result_str, gint result_str_len)
{
	gchar *input_file_name = sdata->callback_userdata;
	GSList *container_list = get_txtfile_lines(input_file_name);
	gboolean ret = TRUE;

	m2v2_init_db();
	gs_g_slist_foreach_until_stop(container_list, _convert_db, &ret);
	g_slist_free_full(container_list, g_free);
	m2v2_clean_db();

	g_snprintf(result_str, result_str_len, "CONVERT ALL %s", ret ? "OK":"NOK");
	return TRUE;
}
