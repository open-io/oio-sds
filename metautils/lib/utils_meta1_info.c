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
#define LOG_DOMAIN "metautils.meta1_info"
#endif

#include <string.h>
#include "./metautils.h"

gint
meta1_info_to_string(const meta1_info_t * src, gchar * dst, gsize dstSize)
{
	gsize offset = 0;

	if (!src || !dst)
		return -1;

	if (dstSize == 0)
		return 0;

	offset += addr_info_to_string(&(src->addr), dst + offset, dstSize - offset);
	offset += g_snprintf(dst + offset, dstSize - offset, ":");
	offset += score_to_string(&(src->score), dst + offset, dstSize - offset);

	return offset;
}

void
meta1_info_print_all(const gchar * domain, const gchar * header, GSList * list)
{
	gchar str_pi[2048];

	void func_debug_meta1info(gpointer d, gpointer u)
	{
		(void) u;

		if (d) {
			memset(str_pi, 0x00, sizeof(str_pi));
			meta1_info_to_string((meta1_info_t *) d, str_pi, sizeof(str_pi) - 1);
			TRACE_DOMAIN(domain, "%s%s", header, str_pi);
		}
	}

	g_slist_foreach(list, func_debug_meta1info, NULL);
}

void
meta1_info_gclean(gpointer d, gpointer u)
{
	(void) u;

	if (d)
		g_free(d);
}

gint
meta1_info_sort_by_score(gconstpointer a, gconstpointer b)
{
	meta1_info_t *m1 = (meta1_info_t *) a;
	meta1_info_t *m2 = (meta1_info_t *) b;

	if (m1->score.value < m2->score.value)
		return (1);

	if (m1->score.value == m2->score.value)
		return (0);

	if (m1->score.value > m2->score.value)
		return (-1);

	return (0);
}

gint
meta1_info_comp(gconstpointer a, gconstpointer b)
{
	meta1_info_t *m1 = (meta1_info_t *) a;
	meta1_info_t *m2 = (meta1_info_t *) b;

	/* compare net ports */
	if (m1->addr.port != m2->addr.port)
		return (-1);

	/* compare net ip */
	if (m1->addr.type != m2->addr.type)
		return (-1);

	if (m1->addr.type == m2->addr.type && m1->addr.type == TADDR_V4 && m1->addr.addr.v4 != m2->addr.addr.v4)
		return (-1);

	if (m1->addr.type == m2->addr.type && m1->addr.type == TADDR_V6)
		return (-1);

	return (0);
}
