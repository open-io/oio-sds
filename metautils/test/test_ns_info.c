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

#include <features.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "../lib/metatypes.h"
#include "../lib/metautils.h"
#include "../lib/metacomm.h"

static GString *
gba_to_hex(GByteArray *gba)
{
	gsize i;
	GString *gstr;

	g_assert(gba != NULL);

	gstr = g_string_sized_new(gba->len * 2 + 1);
	for (i=0; i<gba->len ;i++)
		g_string_append_printf(gstr, "%02X", gba->data[i]);
	return gstr;
}

static GByteArray*
check_ns_info_encoding(void)
{
	g_printerr("building fake ns_info\n");
	namespace_info_t ns_info;
	GError *err = NULL;
	GByteArray *gba = NULL;
	
	memset(&ns_info, 0, sizeof(ns_info));
	g_strlcpy(ns_info.name, "NS", sizeof(ns_info.name)-1);
	ns_info.chunk_size = 1024;
	ns_info.options = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	GByteArray *value = NULL;
	value = g_byte_array_new();
	g_byte_array_append(value, (guint8*)"VALUE2", strlen("VALUE2"));
	g_hash_table_insert(ns_info.options, g_strdup("KEY2"), value);
	
	if (!l4_address_init_with_url(&(ns_info.addr), "127.0.0.1:1025", &err)) {
		g_error("Address init failure : %s", err->message);
		return FALSE;
	}
	ns_info.versions.srvcfg = 1;
	ns_info.versions.evtcfg = 2;
	ns_info.versions.nscfg = 3;
	ns_info.versions.snapshot = 4;
	ns_info.versions.broken = 5;
	ns_info.writable_vns = g_slist_prepend(ns_info.writable_vns, g_strdup("VNS1"));
	ns_info.writable_vns = g_slist_prepend(ns_info.writable_vns, g_strdup("VNS2"));
	ns_info.writable_vns = g_slist_prepend(ns_info.writable_vns, g_strdup("VNS3"));

	g_printerr("ns_info length = %d\n", g_slist_length(ns_info.writable_vns));

	g_printerr("fake ns_info build, marshalling...\n");
	
	/* Marshall / Unmarshall */
	gba = namespace_info_marshall(&ns_info, &err);

	return gba;
}

void
dump_vns(gpointer data, gpointer udata)
{
	(void) udata;
	g_printerr("writable vns :%s\n", (gchar*)data);
}

void
dump_valuelist(gpointer k, gpointer v, gpointer udata)
{
	(void) udata;
	g_printerr("option : k = %s | v = %s\n", (gchar*)k, (gchar*)((GByteArray*)v)->data);
}

static void
dump_ns_info(namespace_info_t *ns_info)
{
	g_printerr("ns_name = %s\n", ns_info->name);
	g_printerr("chunk_size = %"G_GINT64_FORMAT"\n", ns_info->chunk_size);
	g_hash_table_foreach(ns_info->options, dump_valuelist, NULL);
	g_hash_table_foreach(ns_info->storage_policy, dump_valuelist, NULL);
	g_hash_table_foreach(ns_info->data_security, dump_valuelist, NULL);
	g_slist_foreach(ns_info->writable_vns, dump_vns, NULL);
}

static void
try_decode(GByteArray* gba)
{
	namespace_info_t *decoded = NULL;
	GError *err = NULL;

	g_printerr("Data to unmarshall : [%s]\n", (gchar*)gba->data);
	g_printerr("Data to unmarshall length: %d\n", gba->len);

	decoded = namespace_info_unmarshall(gba->data, gba->len, &err);
	g_byte_array_free(gba, TRUE);

	if (decoded) {
		if (err == NULL) {
			g_printerr("encode/decode\tok\n");
			dump_ns_info(decoded);
			}
		else {
			g_printerr("encode/decode\tKO error structure set\n");
			abort();
		}
	}
	else {
		if (err != NULL)
			g_printerr("encode/decode\tKO code=%d %s\n", err->code, err->message);
		else
			g_printerr("encode/decode\tKO error not set\n");
		g_error_free(err);
		abort();
	}
}

static void
_dump(GByteArray *gba)
{
	GString *gstr;

	gstr = gba_to_hex(gba);
	g_printerr("%s\n", gstr->str);
	g_string_free(gstr, TRUE);
}

int
main(int argc, char ** args)
{
	(void) argc;
	(void) args;
	GByteArray *encoded = NULL;

	log4c_init();
	if (!g_thread_supported())
		g_thread_init(NULL);

	encoded = check_ns_info_encoding();
	if(!encoded) {
		g_printerr("ns_info encoding failed\n");	
		return 1;
	}
	_dump(encoded);
	
	try_decode(encoded);

	return 0;
}
