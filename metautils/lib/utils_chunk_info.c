/*
OpenIO SDS metautils
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

#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"

gint
chunk_id_to_string(const chunk_id_t * ci, gchar * dst, gsize dstSize)
{
	gsize offset;
	gchar str_addr[STRLEN_ADDRINFO+1];

	if (!dst || !ci)
		return 0;

	bzero(str_addr, sizeof(str_addr));
	addr_info_to_string(&(ci->addr), str_addr, sizeof(str_addr));

	/*ecrire id.id */
	offset = g_snprintf(dst, dstSize,
			"%02X%02X%02X%02X%02X%02X%02X%02X"
			"%02X%02X%02X%02X%02X%02X%02X%02X"
			"%02X%02X%02X%02X%02X%02X%02X%02X"
			"%02X%02X%02X%02X%02X%02X%02X%02X:%s:%.*s",
			ci->id[0], ci->id[1], ci->id[2], ci->id[3], ci->id[4], ci->id[5], ci->id[6], ci->id[7],
			ci->id[8], ci->id[9], ci->id[10], ci->id[11], ci->id[12], ci->id[13], ci->id[14], ci->id[15],
			ci->id[16], ci->id[17], ci->id[18], ci->id[19], ci->id[20], ci->id[21], ci->id[22], ci->id[23],
			ci->id[24], ci->id[25], ci->id[26], ci->id[27], ci->id[28], ci->id[29], ci->id[30], ci->id[31],
			str_addr,
			LIMIT_LENGTH_VOLUMENAME, ci->vol);

	return MIN(offset,dstSize);
}

void
chunk_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		g_free(d);
}

gchar *
assemble_chunk_id(const gchar *straddr, const gchar *strvol, const gchar *strid)
{
	void _append(GString *gstr, const gchar *s) {
		if (gstr->str[gstr->len - 1] != '/' && *s != '/')
			g_string_append_c(gstr, '/');
		g_string_append(gstr, s);
	}

	GString *gstr = g_string_new("http://");
	_append(gstr, straddr);
	(void) strvol;
	_append(gstr, strid);
	return g_string_free(gstr, FALSE);
}

