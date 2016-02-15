/*
OpenIO SDS sqliterepo
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

#include <metautils/lib/metautils.h>

#include "sqliterepo.h"
#include "sqlx_remote.h"
#include "hash.h"
#include "internals.h"

struct hashstr_s *
sqliterepo_hash_name(struct sqlx_name_s *n)
{
	GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(hash, (guint8*)n->base, strlen(n->base));
	g_checksum_update(hash, (guint8*)"@", 1);
	g_checksum_update(hash, (guint8*)n->type, strlen(n->type));
	const char *hex0 = g_checksum_get_string(hash);
	const size_t len = 2 * g_checksum_type_get_length (G_CHECKSUM_SHA256);
	gchar *hex = alloca (1 + len);
	gchar *p = hex;
	do { *(p++) = g_ascii_toupper(*hex0); } while (*(hex0++));
	g_checksum_free(hash);

	return hashstr_create_len (hex, len);
}

