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
#define LOG_DOMAIN "metautils.volume_stat"
#endif

#include <string.h>
#include "./metautils.h"

gint
volume_stat_to_string(const volume_stat_t * src, gchar * dst, gsize dstSize)
{
	gsize offset = 0;

	if (!src || !dst)
		return -1;

	if (dstSize == 0)
		return 0;

	offset += g_snprintf(dst + offset, dstSize - offset, "%i:%i:%i ", src->cpu_idle, src->io_idle, src->free_chunk);
	offset += volume_info_to_string(&(src->info), dst + offset, dstSize - offset);

	return offset;
}

void
volume_stat_print_all(const gchar * domain, const gchar * header, GSList * list)
{
	gchar str_pi[2048];

	void func_debug_volumestat(gpointer d, gpointer u)
	{
		(void) u;

		if (d) {
			memset(str_pi, 0x00, sizeof(str_pi));
			volume_stat_to_string((volume_stat_t *) d, str_pi, sizeof(str_pi) - 1);
			TRACE_DOMAIN(domain, "%s%s", header, str_pi);
		}
	}

	g_slist_foreach(list, func_debug_volumestat, NULL);
}

void
volume_stat_gclean(gpointer d, gpointer u)
{
	(void) u;

	if (d)
		g_free(d);
}
