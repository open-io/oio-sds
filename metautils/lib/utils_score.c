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
#define LOG_DOMAIN "metautils.score"
#endif

#include <string.h>
#include "./metautils.h"

gint
score_to_string(const score_t * src, gchar * dst, gsize dstSize)
{
	if (!src || !dst)
		return -1;

	if (dstSize == 0)
		return 0;

	return g_snprintf(dst, dstSize, "%i:%i", src->value, src->timestamp);
}

void
score_gclean(gpointer d, gpointer u)
{
	(void) u;

	if (d)
		g_free(d);
}

