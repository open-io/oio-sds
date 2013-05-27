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

#ifndef LOG_DOMAIN
#define LOG_DOMAIN "rawx.client.parser"
#endif

#include <metautils.h>

//#include "./rawx_client_internals.h"

int
body_reader(void *userdata, const char *buf, size_t len)
{
	GByteArray *buffer = userdata;

	g_byte_array_append(buffer, (guint8*)buf, len);
	return 0;
}

GHashTable *
body_parser(GByteArray * buffer, GError ** err)
{
	GHashTable *result = NULL;
	GRegex *stat_regex = NULL;
	GMatchInfo *match_info = NULL;

	g_byte_array_append(buffer, (guint8*)"", 1);

	stat_regex = g_regex_new("^(\\S+)[ \\t]+(\\S+).*$",
	    G_REGEX_MULTILINE | G_REGEX_RAW, G_REGEX_MATCH_NOTEMPTY, err);

	if (!stat_regex) {
		GSETERROR(err, "Regex compilation error");
		return NULL;
	}

	if (!g_regex_match(stat_regex, (gchar*)(buffer->data), G_REGEX_MATCH_NOTEMPTY, &match_info)) {
		GSETERROR(err, "Invalid stat from the RAWX");
		goto error_label;
	}

	result = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (!result) {
		GSETERROR(err, "Memory allocation failure");
		goto error_label;
	}

	do {
		if (!g_match_info_matches(match_info)) {
			GSETERROR(err, "Invalid matching");
			goto error_label;
		}
		else if (g_match_info_get_match_count(match_info) != 3) {
			GSETERROR(err, "Invalid matching, %d groups found", g_match_info_get_match_count(match_info));
			goto error_label;
		}
		else {
			gchar *str_key, *str_value;

			str_key = g_match_info_fetch(match_info, 1);
			str_value = g_match_info_fetch(match_info, 2);

			if (!str_key || !str_value) {
				GSETERROR(err, "Matching capture failure");
				if (str_value)
					g_free(str_value);
				if (str_key)
					g_free(str_key);
				if (result)
					g_hash_table_destroy(result);
				goto error_label;
			}

			g_hash_table_insert(result, str_key, str_value);
		}
	} while (g_match_info_next(match_info, NULL));

	g_match_info_free(match_info);
	g_regex_unref(stat_regex);

	return result;

      error_label:
	if (match_info)
		g_match_info_free(match_info);
	if (result)
		g_hash_table_destroy(result);
	g_regex_unref(stat_regex);

	return NULL;
}
