/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>

#include "sqlx_remote.h"
#include "hash.h"

void
sqliterepo_hash_name (const struct sqlx_name_s *n, gchar *d, gsize dlen)
{
	EXTRA_ASSERT(dlen > 0);
	EXTRA_ASSERT(d != NULL);

	GChecksum *h = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(h, (guint8*)n->base, strlen(n->base));
	g_checksum_update(h, (guint8*)"@", 1);
	g_checksum_update(h, (guint8*)n->type, strlen(n->type));
	const char *hex = g_checksum_get_string(h);
	/* TODO maybe is it possible to make this in one pass */
	g_strlcpy(d, hex, dlen);
	oio_str_upper(d);
	g_checksum_free(h);

}
