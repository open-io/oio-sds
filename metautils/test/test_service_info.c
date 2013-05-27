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

static GByteArray *
_encode_api(guint max)
{
	GSList *list_srv = NULL;
	GByteArray *gba;
	service_info_t si;
	GError *err = NULL;
	
	memset(&si, 0, sizeof(si));
	g_strlcpy(si.ns_name, "NS", sizeof(si.ns_name)-1);
	g_strlcpy(si.type, "plop", sizeof(si.type)-1);
	si.score.value = 1;
	si.score.timestamp = time(0);
	if (!l4_address_init_with_url(&(si.addr), "127.0.0.1:1025", &err))
		g_error("Address init failure : %s", err->message);

	while (max-- > 0) {
		short hport = ntohs(si.addr.port);
		si.addr.port = htons(hport+1);
		list_srv = g_slist_prepend(list_srv, g_memdup(&si, sizeof(service_info_t)));
	}
	
	gba = service_info_marshall_gba(list_srv, &err);
	g_slist_foreach(list_srv, service_info_gclean, NULL);
	g_slist_free(list_srv);

	if (!gba)
		g_error("Service serialization error : %s", err->message);

	return gba;
}

static GByteArray *
_encode_own(guint max)
{
	guint8 header[] = { 0x30, 0x80 };
	guint8 footer[] = { 0x00, 0x00 };
	GByteArray *gba;
	service_info_t si;
	GError *err = NULL;
	
	memset(&si, 0, sizeof(si));
	g_strlcpy(si.ns_name, "NS", sizeof(si.ns_name)-1);
	g_strlcpy(si.type, "plop", sizeof(si.type)-1);
	si.score.value = 1;
	si.score.timestamp = time(0);
	if (!l4_address_init_with_url(&(si.addr), "127.0.0.1:1025", &err))
		g_error("Address init failure : %s", err->message);

	gba = g_byte_array_new();
	g_byte_array_append(gba, header, sizeof(header));

	while (max-- > 0) {
		GByteArray *si_gba;
		short hport;

		hport = ntohs(si.addr.port);
		si.addr.port = htons(hport+1);
		si_gba = service_info_marshall_1(&si, &err);
		
		if (!si_gba) {
			g_error("Serialisation error : %s", err->message);
		}
		else {
			g_byte_array_append(gba, si_gba->data, si_gba->len);
			g_byte_array_free(si_gba, TRUE);
		}
		if (err)
			g_clear_error(&err);
	}
	
	return g_byte_array_append(gba, footer, sizeof(footer));
}

static void
_try(guint i)
{
	gint rc;
	gsize real_size;
	GSList *decoded = NULL;
	GByteArray *encoded;
	GError *err = NULL;

	encoded = _encode_own(i);
	real_size = encoded->len;
	rc = service_info_unmarshall(&decoded, encoded->data, &real_size, &err);
	g_byte_array_free(encoded, TRUE);
	g_slist_foreach(decoded, service_info_gclean, NULL);
	g_slist_free(decoded);

	if (rc) {
		if (err == NULL)
			g_printerr("encode(%u)/decode\tok\n", i);
		else {
			g_printerr("encode(%u)/decode\tKO error structure set\n", i);
			abort();
		}
	}
	else {
		if (err != NULL)
			g_printerr("encode(%u)/decode\tKO code=%d %s\n", i, err->code, err->message);
		else
			g_printerr("encode(%u)/decode\tKO error not set\n", i);
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
	g_byte_array_free(gba, TRUE);
	g_string_free(gstr, TRUE);
}

int
main(int argc, char ** args)
{
	guint i;

	(void) argc;
	(void) args;

	log4c_init();
	if (!g_thread_supported())
		g_thread_init(NULL);

	_dump(_encode_own(2));
	_dump(_encode_api(2));

	for (i=20; (i--) > 0 ;)
		_try(i);

	return 0;
}

