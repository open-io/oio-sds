/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include "metautils.h"

static int
metautils_buffer_cmp(const guint8 * const d0, const guint l0,
		const guint8 * const d1, const guint l1)
{
	EXTRA_ASSERT(d0 != NULL);
	EXTRA_ASSERT(d1 != NULL);
	register gint cmp_data = memcmp(d0, d1, MIN(l0, l1));
	return MACRO_COND(cmp_data, cmp_data, CMP(l0, l1));
}

int
metautils_gba_cmp(const GByteArray *a, const GByteArray *b)
{
	EXTRA_ASSERT(a != NULL);
	EXTRA_ASSERT(b != NULL);
	return metautils_buffer_cmp(a->data, a->len, b->data, b->len);
}

GByteArray*
metautils_gba_dup(const GByteArray *gba)
{
	if (!gba || !gba->data || !gba->len)
		return g_byte_array_new();
	GByteArray *gba_copy = g_byte_array_sized_new(gba->len);
	g_byte_array_append(gba_copy, gba->data, gba->len);
	return gba_copy;
}

GByteArray*
metautils_gba_from_string(const gchar *str)
{
	if (!str || !*str)
		return g_byte_array_new();

	const size_t len = strlen(str);
	GByteArray *gba = g_byte_array_sized_new(len + 1);
	g_byte_array_append(gba, (guint8*)str, len+1);
	g_byte_array_set_size(gba, gba->len - 1);
	return gba;
}

GByteArray*
metautils_gba_from_hexstring(const gchar *str)
{
	if (!str)
		return NULL;
	size_t len = strlen(str);
	if (len % 2)
		return NULL;
	GByteArray *gba = g_byte_array_sized_new(len / 2);
	g_byte_array_set_size(gba, len/2);
	if (len && !oio_str_hex2bin(str, gba->data, gba->len)) {
		g_byte_array_unref (gba);
		return NULL;
	}
	return gba;
}

void
metautils_gba_unref(gpointer p)
{
	if (p != NULL)
		g_byte_array_unref((GByteArray*)p);
}

void
metautils_gba_clean(gpointer p)
{
	if (p != NULL)
		g_byte_array_free((GByteArray*)p, TRUE);
}

void
metautils_gba_cleanv(GByteArray **tab)
{
	if (tab) {
		for (GByteArray **p=tab; *p ;++p) {
			g_byte_array_unref (*p);
			*p = NULL;
		}
		g_free(tab);
	}
}

GString*
metautils_gba_to_hexgstr(GString *gstr, GByteArray *gba)
{
	if (!gstr)
		gstr = g_string_sized_new(2 * gba->len);

	const guint len = gstr->len;
	const guint max = gba->len * 2;
	g_string_set_size(gstr, max + len);
	oio_str_bin2hex (gba->data, gba->len, gstr->str + len, gstr->len - len + 1);

	return gstr;
}

