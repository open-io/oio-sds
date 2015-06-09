/*
OpenIO SDS gridd
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
# define G_LOG_DOMAIN "stats.client.lib"
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>

#include <gridd/plugins/msg_stats/msg_stats.h>

#include "./stats_remote.h"

static gboolean
field_extractor(GError **e, gpointer u, gint code, MESSAGE r)
{
	(void) code;
	if (!r) {
		GSETERROR(e, "invalid parameter");
		return FALSE;
	}

	gchar **fields = metautils_message_get_field_names (r);
	if (fields) {
		for (gchar **field=fields; *field ;field++) {
			gchar *str_val = NULL;
			gdouble val;

			if (!g_str_has_prefix(*field, MSGFIELD_STATPREFIX))
				continue;
			if (!(str_val = metautils_message_extract_string_copy(r, *field)))
				continue;

			if (strchr(str_val, '.'))
				val = g_ascii_strtod (str_val, NULL);
			else {
				gint64 i64 = g_ascii_strtoll(str_val, NULL, 10);
				val = i64;
			}
			g_free(str_val);

			if (errno==ERANGE) {
				WARN("wrong stat for '%s' : overflow/underflow", *field);
				continue;
			}

			g_hash_table_insert(*((GHashTable**)u),
					g_strdup((*field) + strlen(MSGFIELD_STATPREFIX)),
					g_memdup(&val, sizeof(val)));
		}
	}

	g_strfreev(fields);
	return TRUE;
}
	
GHashTable*
gridd_stats_remote (addr_info_t *ai, gint ms, GError **err, const gchar *pattern)
{
	GHashTable *ht=NULL;
	
	struct code_handler_s codes [] = {
		{ CODE_FINAL_OK, REPSEQ_FINAL, NULL, field_extractor },
		{ CODE_PARTIAL_CONTENT, 0, NULL, field_extractor },
		{ 0, 0, NULL, NULL },
	};
	struct reply_sequence_data_s data = { &ht , 0 , codes };

	/*create the result hash table*/
	ht = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	if (!ht) {
		GSETERROR(err, "cannot create a hashtable");
		return NULL;
	}

	/*create and fill the request*/
	GByteArray *gba_pattern = g_byte_array_append(g_byte_array_new(), (guint8*)pattern, strlen(pattern));
	MESSAGE request = metautils_message_create_named("REQ_STATS");
	metautils_message_add_fields_gba (request, MSGKEY_PATTERN, gba_pattern, NULL);
	g_byte_array_free(gba_pattern, TRUE);

	if (!request) {
		GSETERROR(err, "Cannot create a message");
		goto errorLabel;
	}

	/*run the reply sequence*/
	if (!metaXClient_reply_sequence_run_from_addrinfo(err, request, ai, ms, &data)) {
		GSETERROR(err, "Cannot execute the request and parse the answers");
		goto errorLabel;
	}

	metautils_message_destroy (request);	
	return ht;
	
errorLabel:
	if (ht)
		g_hash_table_destroy (ht);
	metautils_message_destroy (request);
	return NULL;
}

