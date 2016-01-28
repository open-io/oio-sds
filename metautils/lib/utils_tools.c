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

#include "metautils.h"

void g_free0(gpointer p) { if (p) g_free(p); }
void g_free1(gpointer p1, gpointer p2) { (void) p2; g_free0(p1); }
void g_free2(gpointer p1, gpointer p2) { (void) p1; g_free0(p2); }

gsize
metautils_strlcpy_physical_ns(gchar *d, const gchar *s, gsize dlen)
{
    register gsize count = 0;

	if (dlen > 0) {
		-- dlen; // Keep one place for the trailing '\0'
	    for (; count<dlen && *s && *s != '.' ;count++)
			*(d++) = *(s++);
		if (dlen)
			*d = '\0';
	}

    for (; *s && *s != '.' ;count++,s++) { }
    return count;
}

