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
#define LOG_DOMAIN "metautils.container_event"
#endif

#include <string.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"


gint
container_event_to_string(container_event_t * src, gchar * dst, gsize dstSize)
{
	gsize o;

	if (!src || !dst)
		return -1;
	if (!dstSize)
		return 0;

	o = g_snprintf(dst, dstSize, "row=%"G_GINT64_FORMAT" time=%"G_GINT64_FORMAT" type=%s ref=%s msg=",
			src->rowid, src->timestamp, src->type, src->ref);

	if (o < dstSize)
		o += metautils_gba_data_to_string(src->message, dst+o, dstSize-o);
	return o;
}

void
container_event_print_all(const gchar * domain, const gchar * header, GSList * list)
{
	GSList *l;
	gchar str_ce[2048];

	if (!list || !TRACE_ENABLED())
		return;
	for (l = list; l; l = l->next) {
		if (!l->data)
			continue;
		memset(str_ce, 0x00, sizeof(str_ce));
		container_event_to_string((container_event_t *) (l->data), str_ce, sizeof(str_ce) - 1);
		TRACE_DOMAIN(domain, "%s%s", header, str_ce);
	}
}

void
container_event_clean(container_event_t * ce)
{
	if (!ce)
		return;
	if (ce->message)
		g_byte_array_free(ce->message, TRUE);
	g_free(ce);
}

void
container_event_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (!d)
		return;
	container_event_clean((container_event_t *) d);
}

