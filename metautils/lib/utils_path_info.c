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

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "metautils.path_info"
#endif

#include <string.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"


gint
path_info_to_string(const path_info_t * src, gchar * dst, gsize dstSize)
{
	if (!src || !dst)
		return -1;
	if (!dstSize)
		return 0;

	return g_snprintf(dst, dstSize, "path=%*.*s size=%"G_GINT64_FORMAT" hasSize=%i",
	    1, LIMIT_LENGTH_CONTENTPATH, src->path, src->hasSize ? src->size : 0, src->hasSize ? 1 : 0);
}

void
path_info_print_all(const gchar * domain, const gchar * header, GSList * list)
{
	GSList *l;
	gchar str_pi[2048];

	if (!list || !TRACE_ENABLED())
		return;
	for (l = list; l; l = l->next) {
		if (!l->data)
			continue;
		memset(str_pi, 0x00, sizeof(str_pi));
		path_info_to_string((path_info_t *) (l->data), str_pi, sizeof(str_pi) - 1);
		TRACE_DOMAIN(domain, "%s%s", header, str_pi);
	}
}

void
path_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		path_info_clean((path_info_t *) d);
}

void
path_info_clean(path_info_t * pi)
{
	if (!pi)
		return;

	if (pi->system_metadata)
		g_byte_array_free(pi->system_metadata, TRUE);
	if (pi->user_metadata)
		g_byte_array_free(pi->user_metadata, TRUE);

	if (pi->version) 
		g_free(pi->version);
	
	pi->version = NULL;
	pi->system_metadata = NULL;
	pi->user_metadata = NULL;
	g_free(pi);
}
