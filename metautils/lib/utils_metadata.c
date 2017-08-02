/*
OpenIO SDS metautils
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#define METADATA_HT_CREATE() g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free)

GHashTable*
metadata_unpack_buffer(const guint8 *data, gsize size, GError **error)
{
	GHashTable *ht;
	gchar **tokens, **tok;

	if (!data) {
		GSETERROR(error, "Invalid paramater (%p)", data);
		return NULL;
	}

	if (!size)
		return METADATA_HT_CREATE();

	tokens = buffer_split(data, size, ";", 0);
	if (!tokens) {
		GSETERROR(error,"split error");
		return NULL;
	}

	ht = METADATA_HT_CREATE();
	for (tok=tokens; *tok && **tok ;tok++) {
		gchar **pair_tokens, *stripped;

		pair_tokens = g_strsplit(*tok, "=", 2);
		if (!pair_tokens)/*skip this empty pair*/
			continue;
		switch (g_strv_length(pair_tokens)) {
		case 0U:/*strange case, let's happily ignore it*/
			break;
		case 1U:/*single key with no value*/
			stripped = g_strstrip(pair_tokens[0]);
			if (stripped && *stripped)
				g_hash_table_insert(ht, g_strdup(stripped), g_strdup(""));
			break;
		case 2U:
			stripped = g_strstrip(pair_tokens[0]);
			if (stripped && *stripped)
				g_hash_table_insert(ht, g_strdup(stripped), g_strdup(pair_tokens[1]));
			break;
		}
		g_strfreev(pair_tokens);
	}

	g_strfreev(tokens);
	return ht;
}

GHashTable*
metadata_unpack_string(const gchar *data, GError **error)
{
	if (!data) {
		GSETERROR(error,"Inavalid parameter (str==NULL)");
		return NULL;
	}
	return metadata_unpack_buffer((guint8*)data, strlen(data), error);
}

GByteArray*
metadata_pack(GHashTable *unpacked, GError **error)
{
	gboolean first;
	GByteArray *gba;
	GHashTableIter iter;
	gpointer k, v;
	
	if (!unpacked) {
		GSETERROR(error,"NULL unpacked form");
		return NULL;
	}
	gba = g_byte_array_sized_new(1+(32 * g_hash_table_size(unpacked)));
	g_hash_table_iter_init(&iter, unpacked);
	for (first=TRUE; g_hash_table_iter_next(&iter, &k, &v) ;) {
		if (first)
			first = FALSE;
		else
			g_byte_array_append(gba, (guint8*)";", 1);
		g_byte_array_append(gba, (guint8*)k, strlen((gchar*)k));
		g_byte_array_append(gba, (guint8*)"=", 1);
		g_byte_array_append(gba, (guint8*)v, strlen((gchar*)v));
	}
	return gba;
}

void
metadata_merge(GHashTable *base, GHashTable *complement)
{
	GHashTableIter iter;
	gpointer k, v;

	if (!base || !complement)
		return;

	g_hash_table_iter_init(&iter, complement);
	while (g_hash_table_iter_next(&iter, &k, &v))
		g_hash_table_insert(base, g_strdup(k), g_strdup(v));
}

