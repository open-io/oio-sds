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
#define LOG_DOMAIN "metacomm.meta1_raw_container"
#endif

#include <errno.h>
#include <glib.h>

#include "./metautils.h"

void
meta1_raw_container_clean(struct meta1_raw_container_s *r)
{
	if (!r)
		return;
	if (r->meta2) {
		g_slist_foreach(r->meta2, addr_info_gclean, NULL);
		g_slist_free(r->meta2);
	}
	g_free(r);
}

void
meta1_raw_container_gclean(gpointer r, gpointer ignored)
{
	(void) ignored;
	meta1_raw_container_clean(r);
}

