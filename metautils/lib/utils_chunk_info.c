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
#define LOG_DOMAIN "metautils"
#endif

#include <string.h>
#include "./metautils.h"

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

	/*ALERT("dstSize = %"G_GSIZE_FORMAT" offset = %"G_GSIZE_FORMAT, dstSize, offset);*/
	return MIN(offset,dstSize);
}


gint
chunk_info_to_string(const chunk_info_t * src, gchar * dst, gsize dstSize)
{
	int i;
	gsize offset;

	if (!src || !dst)
		return -1;
	if (!dstSize)
		return 0;

	offset = chunk_id_to_string(&(src->id), dst, dstSize);
	offset += g_snprintf(dst + offset, dstSize - offset,
		":%"G_GINT64_FORMAT":%"G_GUINT32_FORMAT":", src->size, src->position);
	for (i = 0; i < 16; i++)
		offset += g_snprintf(dst + offset, dstSize - offset, "%02X", ((guint8 *) (src->hash))[i]);
	return offset;
}


void
chunk_info_print_all(const gchar * domain, const gchar * header, GSList * list)
{
	GSList *l;
	gchar str_ci[256];

	if (!list || !TRACE_ENABLED())
		return;
	for (l = list; l; l = l->next) {
		if (!l->data)
			continue;
		memset(str_ci, 0x00, sizeof(str_ci));
		chunk_info_to_string((chunk_info_t *) (l->data), str_ci, sizeof(str_ci) - 1);
		TRACE_DOMAIN(domain, "%s%s", header, str_ci);
	}
}


void
chunk_info_gclean(gpointer d, gpointer u)
{
	(void) u;
	if (d)
		g_free(d);
}
