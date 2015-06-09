/*
OpenIO SDS meta1v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.meta1"
#endif

#include "./internals.h"
#include "./meta1_remote.h"

MESSAGE
meta1_create_message(const gchar *reqname, const container_id_t cid)
{
	EXTRA_ASSERT(reqname != NULL);
	EXTRA_ASSERT(cid != NULL);
	MESSAGE result = metautils_message_create_named(reqname);
	metautils_message_add_cid(result, NAME_MSGKEY_CONTAINERID, cid);
	return result;
}

void
meta1_enheader_addr_list(MESSAGE req, const gchar *fname, GSList *addr)
{
	EXTRA_ASSERT(req != NULL);
	EXTRA_ASSERT(fname != NULL);
	EXTRA_ASSERT(addr != NULL);

	GByteArray *encoded = addr_info_marshall_gba(addr, NULL);
	metautils_message_add_field(req, fname, encoded->data, encoded->len);
	g_byte_array_free(encoded, TRUE);
}

