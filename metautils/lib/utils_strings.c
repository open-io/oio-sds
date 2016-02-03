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

#include <string.h>

#include "metautils_bits.h"
#include "metautils_macros.h"
#include "metautils_errors.h"
#include "metautils_strings.h"
#include "metautils_containers.h"

void g_free0(gpointer p) { if (p) g_free(p); }
void g_free1(gpointer p1, gpointer p2) { (void) p2; g_free0(p1); }
void g_free2(gpointer p1, gpointer p2) { (void) p1; g_free0(p2); }

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

gchar **
g_strdupv_inline(gchar **src)
{
	// get the tail size
	gsize header = sizeof(void*) * (1+g_strv_length(src));
	gsize tail = 0;
	for (gchar **v=src; *v; v++)
		tail += 1+strlen(*v);
	gsize total = header + tail;

	gchar *raw = g_malloc0(total);
	gchar **ptrs = (gchar**)raw;
	gchar *d = raw + header;
	gchar *s = NULL;
	while (NULL != (s = *(src++))) {
		register gchar c;
		*(ptrs++) = d;
		do {
			*(d++) = (c = *(s++));
		} while (c);
	}

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
metautils_str_has_caseprefix (const char *str, const char *prefix)
{
	const char *s = str, *p = prefix;
	for (; *s && *p ;++s,++p) {
		if (g_ascii_tolower (*s) != g_ascii_tolower (*p))
			return FALSE;
	}
	return !*p;
}

