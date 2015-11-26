/*
OpenIO SDS core library
Copyright (C) 2015 OpenIO, original work as part of OpenIO Software Defined Storage

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

#include <string.h>

#include <glib.h>

#include "oiostr.h"
#include "oiourl.h"
#include "internals.h"

static guint8 masks[] = {
	0x00, 0x80, 0xC0, 0xE0,
	0xF0, 0xF8, 0xFC, 0xFE,
	0xFF
};

static gchar b2h[][2] =
{
	{'0','0'}, {'0','1'}, {'0','2'}, {'0','3'}, {'0','4'}, {'0','5'}, {'0','6'}, {'0','7'},
	{'0','8'}, {'0','9'}, {'0','A'}, {'0','B'}, {'0','C'}, {'0','D'}, {'0','E'}, {'0','F'},
	{'1','0'}, {'1','1'}, {'1','2'}, {'1','3'}, {'1','4'}, {'1','5'}, {'1','6'}, {'1','7'},
	{'1','8'}, {'1','9'}, {'1','A'}, {'1','B'}, {'1','C'}, {'1','D'}, {'1','E'}, {'1','F'},
	{'2','0'}, {'2','1'}, {'2','2'}, {'2','3'}, {'2','4'}, {'2','5'}, {'2','6'}, {'2','7'},
	{'2','8'}, {'2','9'}, {'2','A'}, {'2','B'}, {'2','C'}, {'2','D'}, {'2','E'}, {'2','F'},
	{'3','0'}, {'3','1'}, {'3','2'}, {'3','3'}, {'3','4'}, {'3','5'}, {'3','6'}, {'3','7'},
	{'3','8'}, {'3','9'}, {'3','A'}, {'3','B'}, {'3','C'}, {'3','D'}, {'3','E'}, {'3','F'},
	{'4','0'}, {'4','1'}, {'4','2'}, {'4','3'}, {'4','4'}, {'4','5'}, {'4','6'}, {'4','7'},
	{'4','8'}, {'4','9'}, {'4','A'}, {'4','B'}, {'4','C'}, {'4','D'}, {'4','E'}, {'4','F'},
	{'5','0'}, {'5','1'}, {'5','2'}, {'5','3'}, {'5','4'}, {'5','5'}, {'5','6'}, {'5','7'},
	{'5','8'}, {'5','9'}, {'5','A'}, {'5','B'}, {'5','C'}, {'5','D'}, {'5','E'}, {'5','F'},
	{'6','0'}, {'6','1'}, {'6','2'}, {'6','3'}, {'6','4'}, {'6','5'}, {'6','6'}, {'6','7'},
	{'6','8'}, {'6','9'}, {'6','A'}, {'6','B'}, {'6','C'}, {'6','D'}, {'6','E'}, {'6','F'},
	{'7','0'}, {'7','1'}, {'7','2'}, {'7','3'}, {'7','4'}, {'7','5'}, {'7','6'}, {'7','7'},
	{'7','8'}, {'7','9'}, {'7','A'}, {'7','B'}, {'7','C'}, {'7','D'}, {'7','E'}, {'7','F'},
	{'8','0'}, {'8','1'}, {'8','2'}, {'8','3'}, {'8','4'}, {'8','5'}, {'8','6'}, {'8','7'},
	{'8','8'}, {'8','9'}, {'8','A'}, {'8','B'}, {'8','C'}, {'8','D'}, {'8','E'}, {'8','F'},
	{'9','0'}, {'9','1'}, {'9','2'}, {'9','3'}, {'9','4'}, {'9','5'}, {'9','6'}, {'9','7'},
	{'9','8'}, {'9','9'}, {'9','A'}, {'9','B'}, {'9','C'}, {'9','D'}, {'9','E'}, {'9','F'},
	{'A','0'}, {'A','1'}, {'A','2'}, {'A','3'}, {'A','4'}, {'A','5'}, {'A','6'}, {'A','7'},
	{'A','8'}, {'A','9'}, {'A','A'}, {'A','B'}, {'A','C'}, {'A','D'}, {'A','E'}, {'A','F'},
	{'B','0'}, {'B','1'}, {'B','2'}, {'B','3'}, {'B','4'}, {'B','5'}, {'B','6'}, {'B','7'},
	{'B','8'}, {'B','9'}, {'B','A'}, {'B','B'}, {'B','C'}, {'B','D'}, {'B','E'}, {'B','F'},
	{'C','0'}, {'C','1'}, {'C','2'}, {'C','3'}, {'C','4'}, {'C','5'}, {'C','6'}, {'C','7'},
	{'C','8'}, {'C','9'}, {'C','A'}, {'C','B'}, {'C','C'}, {'C','D'}, {'C','E'}, {'C','F'},
	{'D','0'}, {'D','1'}, {'D','2'}, {'D','3'}, {'D','4'}, {'D','5'}, {'D','6'}, {'D','7'},
	{'D','8'}, {'D','9'}, {'D','A'}, {'D','B'}, {'D','C'}, {'D','D'}, {'D','E'}, {'D','F'},
	{'E','0'}, {'E','1'}, {'E','2'}, {'E','3'}, {'E','4'}, {'E','5'}, {'E','6'}, {'E','7'},
	{'E','8'}, {'E','9'}, {'E','A'}, {'E','B'}, {'E','C'}, {'E','D'}, {'E','E'}, {'E','F'},
	{'F','0'}, {'F','1'}, {'F','2'}, {'F','3'}, {'F','4'}, {'F','5'}, {'F','6'}, {'F','7'},
	{'F','8'}, {'F','9'}, {'F','A'}, {'F','B'}, {'F','C'}, {'F','D'}, {'F','E'}, {'F','F'}
};

static gchar hexa[] =
{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

void
oio_str_reuse(gchar **dst, gchar *src)
{
	oio_pfree(dst, src);
}

void
oio_str_clean(gchar **s)
{
	oio_pfree(s, NULL);
}

void
oio_str_replace(gchar **dst, const gchar *src)
{
	if (src)
		oio_str_reuse(dst, g_strdup(src));
	else
		oio_str_reuse(dst, NULL);
}

gboolean
oio_str_ishexa(const char *s, gsize slen)
{
	if (!slen || (slen%2))
		return FALSE;
	for (; *s && slen > 0 ;++s,--slen) {
		if (!g_ascii_isxdigit(*s))
			return FALSE;
	}
	return !*s && !slen;
}

gboolean
oio_str_ishexa1(const char *s)
{
	gsize len = 0;
	for (; *s ;++s) {
		if (!g_ascii_isxdigit(*s))
			return FALSE;
		len ++;
	}
	return len > 0 && (len%2) == 0;
}

gboolean
oio_str_hex2bin(const char *s0, guint8 *d, gsize dlen)
{
	const guint8 *s = (const guint8*) s0;
	if (!s || !d)
		return FALSE;

	gsize sS = strlen(s0);
	if (sS > dlen * 2)
		return FALSE;

	while ((dlen--) > 0) {
		if (!*s)
			return TRUE;
 		if (!*(s+1))
			return FALSE; 
		register int i0, i1;

		i0 = hexa[*(s++)];
		i1 = hexa[*(s++)];

		if (i0<0 || i1<0)
			return FALSE;

		*(d++) = (i0 & 0x0F) << 4 | (i1 & 0x0F);
	}

	return TRUE;
}

gsize
oio_str_bin2hex(const void *s, size_t sS, char *d, size_t dS)
{
	gsize i, j;

	if (!d || !dS)
		return 0;
	*d = 0;
	if (!s || !sS)
		return 0;

	for (i=j=0; i<sS && j<(dS-1) ;) {
		register const gchar *h = b2h[((guint8*)s)[i++]];
		d[j++] = h[0];
		d[j++] = h[1];
	}

	d[(j<dS ? j : dS-1)] = 0;
	return j;
}

void
oio_str_hash_name(guint8 *p, const char *ns, const char *account, const char *user)
{
	g_assert (ns != NULL && *ns != 0);
	g_assert (account != NULL && *account != 0);
	g_assert (user != NULL && *user != 0);

	guint8 zero = 0;
	GChecksum *sum = g_checksum_new(G_CHECKSUM_SHA256);

	g_checksum_update(sum, (guint8*)account, strlen(account));
	g_checksum_update(sum, &zero, 1);
	g_checksum_update(sum, (guint8*)user, strlen(user));

	gsize s = 32;
	memset(p, 0, 32);
	g_checksum_get_digest(sum, p, &s);
	g_checksum_free(sum);
}

void
oio_str_randomize(guint8 *buf, gsize buflen)
{
	union {
		guint32 r32;
		guint8 r8[4];
	} raw;
	GRand *r = g_rand_new();

	if (NULL == buf || 0 == buflen)
		return;

	// Fill 4 by 4
	gsize mod32 = buflen % 4;
	gsize max32 = buflen / 4;
	for (register gsize i32=0; i32 < max32 ; ++i32) {
		raw.r32 = g_rand_int(r);
		((guint32*)buf)[i32] = raw.r32;
	}

	// Finish with the potentially remaining unset bytes
	raw.r32 = g_rand_int(r);
	switch (mod32) {
		case 3:
			buf[ (max32*4) + 2 ] = raw.r8[2];
		case 2:
			buf[ (max32*4) + 1 ] = raw.r8[1];
		case 1:
			buf[ (max32*4) + 0 ] = raw.r8[0];
	}

	g_rand_free(r);
}

const char *
oio_str_autocontainer_name (const char *path, gchar *dst,
		const struct oio_str_autocontainer_config_s *cfg)
{
	guint8 bin[64];

	g_assert (path != NULL);
	g_assert (dst != NULL);
	g_assert (cfg != NULL);

	gsize len = strlen (path);
	gsize src_offset = cfg->src_offset;
	gsize src_size = cfg->src_size;
	if (src_offset + src_size > len)
		return NULL;
	/* TODO check the sum doesn't cause an overflow... */

	if (!src_size)
		src_size = len - src_offset;

	GChecksum *checksum = g_checksum_new (G_CHECKSUM_SHA256);
	g_checksum_update (checksum, (guint8*)(path+src_offset), src_size);
	len = sizeof(bin);
	g_checksum_get_digest (checksum, bin, &len);
	g_checksum_free (checksum);

	return oio_str_autocontainer_hash (bin, 64, dst, cfg);
}

const char *
oio_str_autocontainer_hash (const guint8 *bin, gsize len, gchar *dst,
		const struct oio_str_autocontainer_config_s *cfg)
{
	g_assert (bin != NULL);
	g_assert (len > 0);
	g_assert (dst != NULL);
	g_assert (cfg != NULL);

	const gsize dst_bits = cfg->dst_bits;

	if (!dst_bits || dst_bits >= len*8)
		return NULL;

	const gsize div = dst_bits / 8;
	const gsize mod = dst_bits % 8;
	const gsize last = mod ? div+1 : div;
	if (last > len)
		return NULL;

	gchar *p = dst;
	for (gsize i=0; i<div ;i++) {
		const char *s = b2h[ bin[i] ];
		*(p++) = s[0];
		*(p++) = s[1];
	}
	if (mod) {
		register guint8 x = bin[last-1] & masks[mod];
		const char *s = b2h[x];
		*(p++) = s[0];
		if (mod > 4)
			*(p++) = s[1];
	}
	*p = '\0';

	return dst;
}

gchar **
oio_strv_append(gchar **tab, gchar *s)
{
	g_assert (tab != NULL);
	g_assert (s != NULL);
	gsize l = g_strv_length (tab);
	tab = g_try_realloc (tab, (l+2) * sizeof(gchar*));
	tab[l] = s;
	tab[l+1] = NULL;
	return tab;
}

