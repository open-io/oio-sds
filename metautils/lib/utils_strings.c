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
# define G_LOG_DOMAIN "metautils"
#endif

#include <string.h>

#include "metautils_bits.h"
#include "metautils_macros.h"
#include "metautils_errors.h"
#include "metautils_strings.h"
#include "metautils_containers.h"

void
metautils_str_reuse(gchar **dst, gchar *src)
{
	metautils_pfree(dst, src);
}

void
metautils_str_clean(gchar **s)
{
	metautils_pfree(s, NULL);
}

void
metautils_str_replace(gchar **dst, const gchar *src)
{
	if (src)
		metautils_str_reuse(dst, g_strdup(src));
	else
		metautils_str_reuse(dst, NULL);
}

void
metautils_rstrip(register gchar *src, register gchar c)
{
	if (!src || !*src)
		return;
	for (gchar *s = src + strlen(src) - 1; s>=src && *s == c ;s--)
		*s = '\0';
}

const char *
metautils_lstrip(register const char *s, register char c)
{
	for (; *s == c; ++s) {
	}
	return s;
}

void
metautils_str_upper(register gchar *s)
{
	for (; *s ;++s) {
		*s = g_ascii_toupper(*s);
	}
}

void
metautils_str_lower(register gchar *s)
{
	for (; *s ;++s) {
		*s = g_ascii_tolower(*s);
	}
}

int
metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored)
{
	(void) ignored;
	return g_strcmp0(a, b);
}

static const gchar *
strchr_guarded(const gchar *start, const gchar *end, gchar needle)
{
	for (; start < end ;start++) {
		if (needle == *start)
			return start;
	}
	return NULL;
}

static gboolean
strn_isprint(const gchar *start, const gchar *end)
{
	while (start < end) {
		register gchar c = *(start++);
		if (!g_ascii_isprint(c) && !g_ascii_isspace(c) && c!='\n')
			return FALSE;
	}
	return TRUE;
}

gchar **
metautils_decode_lines(const gchar *start, const gchar *end)
{
	if (!start)
		return NULL;
	if (!end)
		end = start + strlen(start);
	else if (end < start)
		return NULL;
	if (!strn_isprint(start, end))
		return NULL;

	GSList *lines = NULL;
	while (start < end) {
		for (; start < end && *start == '\n'; start++);
		const gchar *p;
		if (!(p = strchr_guarded(start, end, '\n'))) {
			gchar *l = g_strndup(start, end-start);
			lines = g_slist_prepend(lines, l);
			break;
		}
		else {
			if (p > start) {
				gchar *l = g_strndup(start, p-start);
				lines = g_slist_prepend(lines, l);
			}
			start = p + 1;
		}
	}

	gchar **result = (gchar**) metautils_list_to_array(lines);
	g_slist_free(lines);
	return result;
}

GByteArray*
metautils_encode_lines(gchar **strv)
{
	GByteArray *gba = g_byte_array_new();
	if (strv) {
		gchar **p;
		for (p=strv; *p ;++p) {
			g_byte_array_append(gba, (guint8*)*p, strlen(*p));
			g_byte_array_append(gba, (guint8*)"\n", 1);
		}
	}

	g_byte_array_append(gba, (guint8*)"", 1);
	g_byte_array_set_size(gba, gba->len - 1);
	return gba;
}

static void
_strv_pointers_concat(gchar **ptrs, gchar *d, gchar **src)
{
	gchar *s;
	register gchar c;

	while (NULL != (s = *(src++))) {
		*(ptrs++) = d;
		do {
			*(d++) = (c = *(s++));
		} while (c);
	}
}

static gsize
_strv_total_length(gchar **v)
{
	gsize total = 0;
	for (; *v; v++)
		total += 1+strlen(*v);
	return total;
}

gchar **
g_strdupv2(gchar **src)
{
	gsize header_size = sizeof(void*) * (1+g_strv_length(src));
	gchar *raw = g_malloc0(header_size + _strv_total_length(src));
	_strv_pointers_concat((gchar**)raw, raw + header_size, src);
	return (gchar**)raw;
}

gchar **
buffer_split(const void *buf, gsize buflen, const gchar *sep, gint max_tokens)
{
	gchar **sp, *tmp;

	if (!buf || buflen <= 0)
		return NULL;

	tmp = g_strndup((gchar*)buf, buflen);
	sp = g_strsplit(tmp, sep, max_tokens);
	g_free(tmp);
	return sp;
}

gsize
strlen_len(const void * s, const gsize l)
{
	gsize i = 0;

	if (!s)
		return 0;
	for (i = 0; i < l; i++) {
		if (!((guint8*)s)[i])
			return i;
	}
	return i;
}

gboolean
data_is_zeroed(const void *data, gsize data_size)
{
	if (data != NULL) {
		for (gsize i=0; i<data_size ;++i) {
			if (((guint8*)data)[i])
				return FALSE;
		}
	}
	return TRUE;
}

gboolean
metautils_cfg_get_bool(const gchar *value, gboolean def)
{
	static const gchar *array_yes[] = {"yes", "true", "on", "enable", "enabled", NULL};
	static const gchar *array_no[] = {"no", "false", "off", "disable", "disabled", NULL};

	if (!value)
		return def;

	for (const gchar **s=array_yes; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return TRUE;
	}

	for (const gchar **s=array_no; *s ;s++) {
		if (!g_ascii_strcasecmp(value, *s))
			return FALSE;
	}

	return def;
}

gboolean
metautils_str_ishexa(const gchar *s, gsize slen)
{
	for (; *s && slen > 0 ;++s,--slen) {
		if (!g_ascii_isxdigit(*s))
			return FALSE;
	}
	return !*s && !slen;
}

gchar **
metautils_strv_append (gchar **tab, gchar *s)
{
	EXTRA_ASSERT(tab != NULL);
	EXTRA_ASSERT(s != NULL);
	gsize l = g_strv_length (tab);
	tab = g_try_realloc (tab, (l+2) * sizeof(gchar*));
	tab[l] = s;
	tab[l+1] = NULL;
	return tab;
}

