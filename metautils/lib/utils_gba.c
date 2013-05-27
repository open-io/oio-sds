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

#include "./metatypes.h"
#include "./metautils.h"

gsize
metautils_gba_len(const GByteArray *gba)
{
	if (!gba)
		return 0;
	return gba->len;
}

int
metautils_gba_cmp(GByteArray *a, GByteArray *b)
{
	if (a == b)
		return 0;
	if (!a && b)
		return 1;
	if (a && !b)
		return -1;
	if (a->len < b->len)
		return -1;
	if (a->len > b->len)
		return 1;
	return memcmp(a->data, b->data, a->len);
}

GByteArray*
metautils_gba_dup(GByteArray *gba)
{
	GByteArray *gba_copy = g_byte_array_new();
	if (gba && gba->data && gba->len)
		g_byte_array_append(gba_copy, gba->data, gba->len);
	return gba_copy;
}

gsize
metautils_gba_data_to_string(GByteArray *gba, gchar *dst, gsize dst_size)
{
	gsize i, imax, idst;

	if (!gba || !dst || !dst_size)
		return 0;
	if (!gba->data || !gba->len)
		return 0;

	bzero(dst, dst_size);
	imax = MIN(gba->len,dst_size);
	for (i=0,idst=0; i<imax && idst<dst_size-5;i++) {
		gchar c = (gchar)(gba->data[i]);
		if (g_ascii_isprint(c) && c != '\\')
			dst[ idst++ ] = c;
		else
			idst += g_snprintf(dst+idst, dst_size-idst, "\\x%02X", c);
	}

	return idst;
}

GByteArray*
metautils_gba_from_string(const gchar *str)
{
	size_t len;
	GByteArray *gba;

	if (!str || !*str)
		return g_byte_array_new();

	len = strlen(str);
	gba = g_byte_array_sized_new(len + 1);
	g_byte_array_append(gba, (guint8*)str, len+1);
	g_byte_array_set_size(gba, gba->len - 1);
	return gba;
}

void
metautils_gba_gunref(gpointer p0, gpointer p1)
{
	(void) p1;
	if (p0)
		g_byte_array_unref((GByteArray*)p0);
}

void
metautils_gba_unref(gpointer p)
{
	if (p)
		g_byte_array_unref((GByteArray*)p);
}

void
metautils_gba_clean(gpointer p)
{
	if (p)
		g_byte_array_free((GByteArray*)p, TRUE);
}

void
meatutils_gba_gclean(gpointer p1, gpointer p2)
{
	(void) p2;
	metautils_gba_clean(p1);
}

GByteArray*
metautils_gba_from_cid(const container_id_t cid)
{
	UTILS_ASSERT(cid != NULL);
	return g_byte_array_append(
			g_byte_array_sized_new(sizeof(container_id_t)),
			cid, sizeof(container_id_t));
}

GString*
metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba)
{
	guint max, len;

	if (!gstr)
		gstr = g_string_new("");

	len = gstr->len;
	max = gba->len * 2;
	g_string_set_size(gstr, max + len);
	buffer2str(gba->data, gba->len, gstr->str + len, gstr->len - len + 1);

	return gstr;
}

