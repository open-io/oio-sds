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
# define LOG_DOMAIN "gridcluster.events"
#endif
#ifdef HAVE_CONFIG_H
# include "../config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <glib.h>

#include <metautils.h>
#include <metacomm.h>

#include "./gridcluster_events.h"

gridcluster_event_t *
gridcluster_create_event(void)
{
	gridcluster_event_t *event;

	event = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, metautils_gba_unref);
	return event;
}

void
gridcluster_destroy_event(gridcluster_event_t * event)
{
	if (event)
		g_hash_table_destroy(event);
}

void
gridcluster_event_add_buffer(gridcluster_event_t * event, const gchar * key, const guint8 * value, gsize value_size)
{
	GByteArray *gba_value;

	if (!event || !key || !value || !value_size)
		return;
	gba_value = g_byte_array_new();
	g_byte_array_append(gba_value, value, value_size);
	g_hash_table_insert(event, g_strdup(key), gba_value);
}

void
gridcluster_event_add_string(gridcluster_event_t * event, const gchar * key, const gchar * value)
{
	if (value)
		gridcluster_event_add_buffer(event, key, (guint8*)value, strlen(value));
}

void
gridcluster_event_set_type(gridcluster_event_t * event, const gchar * str_type)
{
	gridcluster_event_add_string(event, "TYPE", str_type);
}

gsize
gridcluster_event_get_type(gridcluster_event_t * event, gchar * dst_type, gsize dst_size)
{
	gsize len;
	GByteArray *gba_value;

	if (!event || !dst_type)
		return 0;
	gba_value = g_hash_table_lookup(event, "TYPE");
	if (!gba_value)
		return 0;
	len = MIN(dst_size - 1, gba_value->len);
	memcpy(dst_type, gba_value->data, len);
	dst_type[len] = '\0';
	return len;
}

gridcluster_event_t *
gridcluster_decode_event2(const guint8 * const encoded, gsize encoded_size, GError ** err)
{
	gridcluster_event_t *event;
	GSList *list_kv = NULL;

	if (0 >= key_value_pairs_unmarshall(&list_kv, encoded, &encoded_size, err)) {
		GSETERROR(err, "Event ASN.1->List conversion failure");
		return NULL;
	}

	event = key_value_pairs_convert_to_map(list_kv, TRUE, err);
	if (!event)
		GSETERROR(err, "Event List->Map conversion failure");

	g_slist_foreach(list_kv, key_value_pair_gclean, NULL);
	g_slist_free(list_kv);
	return event;
}

gridcluster_event_t *
gridcluster_decode_event(GByteArray * encoded, GError ** err)
{
	if (!encoded) {
		GSETERROR(err, "Invalid parameter (%p)", encoded);
		return NULL;
	}
	return gridcluster_decode_event2(encoded->data, encoded->len, err);
}

GByteArray *
gridcluster_encode_event(gridcluster_event_t * event, GError ** err)
{
	GByteArray *encoded;
	GSList *list_kv;

	if (!event) {
		GSETERROR(err, "Invalid parameter (event)");
		return NULL;
	}

	/*map the event in a list of key-values */
	list_kv = key_value_pairs_convert_from_map(event, FALSE, err);
	if (!list_kv) {
		GSETERROR(err, "Event Map->List conversion failure");
		return NULL;
	}

	/*serialize the list */
	encoded = key_value_pairs_marshall_gba(list_kv, err);
	if (!encoded)
		GSETERROR(err, "Event Map->ASN.1 conversion failure");

	g_slist_foreach(list_kv, g_free1, NULL);
	g_slist_free(list_kv);

	return encoded;
}

void
gridcluster_event_gclean(gpointer pevent, gpointer ignored)
{
	(void) ignored;
	if (pevent)
		gridcluster_destroy_event(pevent);
}

