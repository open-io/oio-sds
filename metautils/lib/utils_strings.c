/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2023 OVH SAS

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

#include <core/oiostr.h>

#include "metautils_macros.h"
#include "metautils_errors.h"
#include "metautils_strings.h"
#include "metautils_containers.h"

void g_free0(gpointer p) { if (p) g_free(p); }

int metautils_strcmp3(gconstpointer a, gconstpointer b, gpointer ignored) {
	(void) ignored;
	return strcmp(a, b);
}

gchar ** g_strdupv_inline(gchar **src) {
	if (!src)
		return NULL;
	if (!*src)
		return g_malloc0(sizeof(void*));

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

gchar*
string_to_ltsv_value(const gchar *value)
{
	if (value == NULL) {
		return NULL;
	}
	char **split = g_strsplit(value, "\n", -1);
	gchar *ltsv_value = g_strjoinv("#012", split);
	g_strfreev(split);
	split = g_strsplit(ltsv_value, "\t", -1);
	g_free(ltsv_value);
	ltsv_value = g_strjoinv("#009", split);
	g_strfreev(split);
	return ltsv_value;
}
