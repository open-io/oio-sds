/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "sqlx.repo.hash"
#endif

#include <glib.h>
#include "../metautils/lib/hashstr.h"
#include "./hash.h"
#include "./internals.h"

hashstr_t *
sqliterepo_hash_name(const gchar *name, const gchar *type)
{
	hashstr_t *result;

	GChecksum *hash = g_checksum_new(G_CHECKSUM_SHA256);
	g_checksum_update(hash, (guint8*)name, strlen(name));
	g_checksum_update(hash, (guint8*)"", 1);
	g_checksum_update(hash, (guint8*)type, strlen(type));
	result = hashstr_create(g_checksum_get_string(hash));
	g_checksum_free(hash);

	hashstr_upper(result);
	return result;
}

