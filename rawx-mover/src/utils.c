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
#ifndef  LOG_DOMAIN
# define LOG_DOMAIN "mover.utils"
#endif

#include <glib.h>
#include "./mover.h"

static void
init_valid_hexa(gchar *tab)
{
	guint8 c;

	for (c=255; c!=0 ; c--) {
		*(tab + (guint8)c) = (
			   (c>='a' && c<='f')
			|| (c>='A' && c<='F')
			|| (c>='0' && c<='9'));
	}
}

gboolean
chunk_path_is_valid(const gchar *path)
{
	gchar valid_hexa[256];
	guint count = 0;
	const gchar *s;
	register gchar c;

	init_valid_hexa(valid_hexa);

	/* s + strlen(s) */
	for (s=path; *s ;s++);

	for (s=s-1; (c = *s) && s>=path ;s--) {
		if (c == G_DIR_SEPARATOR)
			break;
		if (!valid_hexa[(guint8)c])
			return FALSE;
		if (++count > 64)
			return FALSE;
	}

	return count == 64U;
}

