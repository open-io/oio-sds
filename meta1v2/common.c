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
# define G_LOG_DOMAIN "grid.meta1"
#endif

#include "./internals.h"
#include "./meta1_remote.h"

MESSAGE
meta1_create_message(const gchar *reqname, const container_id_t cid, GError **err)
{
	MESSAGE result = NULL;

	g_assert(reqname != NULL);
	g_assert(cid != NULL);

	if (!message_create(&result, err)) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	if (!message_set_NAME(result, reqname, strlen(reqname), err)) {
		message_destroy(result, NULL);
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	if (!message_add_field(result, NAME_MSGKEY_CONTAINERID, sizeof(NAME_MSGKEY_CONTAINERID)-1,
				cid, sizeof(container_id_t), err)) {
		message_destroy(result, NULL);
		GSETERROR(err, "Failed to add container ID in header '%s'", NAME_MSGKEY_CONTAINERID);
		return NULL;
	}

	return result;
}

gboolean
meta1_enheader_addr_list(MESSAGE req, const gchar *fname, GSList *addr, GError **err)
{
	gint rc;
	GByteArray *encoded;

	g_assert(req != NULL);
	g_assert(fname != NULL);
	g_assert(addr != NULL);

	if (!(encoded = addr_info_marshall_gba(addr, err))) {
		GSETERROR(err, "Encode error");
		return FALSE;
	}
	
	rc = message_add_field(req, fname, strlen(fname), encoded->data, encoded->len, err);
	g_byte_array_free(encoded, TRUE);

	if (rc > 0)
		return TRUE;
	GSETERROR(err, "Failed to set field '%s'", fname);
	return FALSE;
}

