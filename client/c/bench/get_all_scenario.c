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
#define G_LOG_DOMAIN "grid.client.bench.get_all_scenario"
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

#define BENCHOUTFILE "/tmp/BENCHOUTFILE"

static ssize_t
write_to_tmpfile(void *uData, const char *b, const size_t bSize)
{
	ssize_t nbW;
	int *p_out_file = uData;

	nbW = write(*p_out_file, b, bSize);
	return nbW;
}

static void _get_content(gpointer _content_name, gpointer _cdata)
{
	const t_content_data *cdata = _cdata;
	const gchar *content_name = _content_name;

	gs_content_t *content = NULL;
	gs_error_t *err = NULL;
	gs_download_info_t dl_info;
	int out_file;
	gboolean *p_use_cache = NULL;

	GTimer * timer = g_timer_new();
	GTimeVal timeval;
	guint elapsed = 0;
	gchar result_str[256];

	memset(result_str, '\0', sizeof(result_str));

	if (!cdata || !cdata->container)
		return;

	DEBUG("getting %s", content_name);

	dl_info.offset = 0;
	dl_info.size = 0;
	dl_info.writer = write_to_tmpfile;
	dl_info.user_data = &out_file;

	errno = 0;
	out_file = open(BENCHOUTFILE, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if (out_file == -1) {
		ERROR("Cannot open file [%s]: [%s]", BENCHOUTFILE, strerror(errno));
		return;
	}

	p_use_cache = cdata->user_data;
	g_timer_start(timer);
	if (*p_use_cache) {
		gs_download_content_by_name(cdata->container, content_name, &dl_info, &err);
	} else {
		content = gs_get_content_from_path (cdata->container, content_name, &err);
		if (!content) {
			ERROR("content %s not found\n", content_name);
		} else {
			if (!gs_download_content(content, &dl_info, &err))
				ERROR("content %s not retrieved\n", content_name);
			gs_content_free (content);
		}
	}

	elapsed = 1000*g_timer_elapsed(timer, NULL);
	g_get_current_time(&timeval);
	g_snprintf(result_str, sizeof(result_str), "GET_CONTENT %s/%s", cdata->container_name, content_name);
	g_printf("%lli,%u,%s,,,,%s,0\n", (timeval.tv_sec*1000LL)+(timeval.tv_usec/1000), elapsed, result_str,
			err == NULL ? "true" : "false");

	g_timer_destroy(timer);

	errno = 0;
	if (close(out_file)) {
		ERROR("Cannot close file [%s]: [%s]", BENCHOUTFILE, strerror(errno));
	}

	if (err)
		gs_error_free(err);
} 

gboolean get_all_scenario(struct scenario_data *sdata, gchar *result_str, gint result_str_len)
{
	g_assert(sdata);
	g_assert(result_str);

	/* The first option is always the use_cache flag. */
	gboolean *p_use_cache = sdata->options->data;
	
	GHashTable *content_ht = _init_content_ht(sdata->gs, sdata->callback_userdata);
	if (content_ht) {
		gboolean res = _apply_callback_to_ht(content_ht, _get_content, sdata->gs, p_use_cache);
		g_hash_table_destroy(content_ht);
		g_snprintf(result_str, result_str_len, "GET_ALL");
		return res;
	}

	return FALSE;
}

