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

#include <core/oiostr.h>

#include "metautils_bits.h"
#include "metautils_macros.h"
#include "metautils_errors.h"
#include "metautils_strings.h"
#include "metautils_containers.h"

void g_free0(gpointer p) { if (p) g_free(p); }
void g_free1(gpointer p1, gpointer p2) { (void) p2; g_free0(p1); }

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

gchar ** buffer_split(const void *buf, gsize buflen, const gchar *sep,
		gint max_tokens) {
	gchar **sp, *tmp;

	if (!buf || buflen <= 0)
		return NULL;

	tmp = g_strndup((gchar*)buf, buflen);
	sp = g_strsplit(tmp, sep, max_tokens);
	g_free(tmp);
	return sp;
}
