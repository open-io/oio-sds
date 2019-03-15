/*
OpenIO SDS load-balancing
Copyright (C) 2015-2019 OpenIO SAS, as part of OpenIO SDS

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

#include <core/oioloc.h>

#include "internals.h"

oio_location_t
location_from_dotted_string(const char *dotted)
{
	gchar **toks = g_strsplit(dotted, ".", OIO_LB_LOC_LEVELS);
	oio_location_t location = 0;
	int ntoks = 0;
	// according to g_strsplit documentation, toks cannot be NULL
	for (gchar **tok = toks; *tok; tok++, ntoks++) {
		location = (location << OIO_LB_BITS_PER_LOC_LEVEL) |
				(djb_hash_str0(*tok) & 0xFFFF);
	}
	g_strfreev(toks);
	return location;
}

