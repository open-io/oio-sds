/*
OpenIO SDS metautils
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

#include <glib.h>
#include <metautils/lib/metautils.h>

static GError *
_remote_version (const char *to, gchar **out)
{
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_VERSION"));
	return gridd_client_exec_and_concat_string (to, 30.0, encoded, out);
}

static GError *
_remote_ping (const char *to)
{
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_PING"));
	return gridd_client_exec (to, 30.0, encoded);
}

static GError *
_remote_stat (const char *to, gchar ***out)
{
	MESSAGE req = metautils_message_create_named("REQ_STATS");
	GByteArray *encoded = message_marshall_gba_and_clean (req);

	gchar *packed = NULL;
	GError *err = gridd_client_exec_and_concat_string (to, 30.0, encoded, &packed);
	if (err) {
		g_free0 (packed);
		return err;
	}

	*out = metautils_decode_lines(packed, packed + strlen(packed));
	g_free0 (packed);
	return NULL;
}

static int
_do_stat (const char *to)
{
	gchar **tab = NULL;
	GError *err = _remote_stat(to, &tab);
	if (err) {
		g_printerr("Stat failed for %s : (%d) %s\n", to, err->code, err->message);
		g_error_free(err);
		return 1;
	}

	g_print("# COUNT %u\n", g_strv_length(tab));
	for (gchar **p=tab; *p ;p++) {
		gchar *k = *p;
		gchar *v = strchr(k,'=');
		if (v) *(v++) = '\0';
		g_print("%s %s\n", k, v);
	}

	g_strfreev(tab);
	return 0;
}

static int
_do_version (const char *to)
{
	gchar *version = NULL;
	GError *err = _remote_version (to, &version);
	if (!err) {
		g_print ("# VERSION %s - %s\n", to, version);
		g_free (version);
		return 0;
	}
	else {
		g_print("# VERSION %s (%d) %s\n", to, err->code, err->message);
		g_clear_error (&err);
		return 1;
	}
}

static int
_do_ping (const char *to)
{
	GError *err = _remote_ping (to);
	if (!err) {
		g_print ("# PING %s - OK\n", to);
		return 0;
	}
	else {
		g_print("# PING %s (%d) %s\n", to, err->code, err->message);
		g_clear_error (&err);
		return 1;
	}
}

static void
_dump_cid (const char *s)
{
	static gchar bad[] = {
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		'-', '-', '-', '-', '-', '-', '-', '-', 
		0
	};

	char str_id[128];
	const char *dst;
	struct hc_url_s *url = hc_url_init (s);

	if (url && NULL != hc_url_get_id(url)) {
		memset(str_id, 0, sizeof(str_id));
		oio_str_bin2hex(hc_url_get_id(url), hc_url_get_id_size(url),
				str_id, sizeof(str_id));
		dst = str_id;
	}
	else {
		dst = bad;
	}

	g_print("%s %s\n", dst, s);
	hc_url_clean(url);
}

static void
_dump_addr (const char *s)
{
	gchar str[256], hexa[1024];
	struct addr_info_s addr;

	if (grid_string_to_addrinfo(s, NULL, &addr)) {
		memset(str, 0, sizeof(str));
		grid_addrinfo_to_string(&addr, str, sizeof(str));
		memset(hexa, 0, sizeof(hexa));
		oio_str_bin2hex(&addr, sizeof(addr), hexa, sizeof(hexa));
		g_print("%s %s\n", str, hexa);
	}
}

static void
_same_hash (const char *p0)
{
	static gchar* memory[65536];

	GString *prefix = g_string_new(p0);

	gint64 counter;
	GChecksum *c;
	gchar num[64];
	union {
		guint8 b[32];
		guint16 prefix;
	} bin;
	gsize binsize;

	memset(&bin, 0, sizeof(bin));
	counter = 0;
	c = g_checksum_new(G_CHECKSUM_SHA256);

	if (prefix && prefix->len > 0) {
		/* pre-loads the memory with the prefix only */
		g_checksum_update(c, (guint8*) prefix->str, prefix->len);
		binsize = sizeof(bin.b);
		g_checksum_get_digest(c, bin.b, &binsize);
		memory[bin.prefix] = g_strdup(prefix->str);
	}

	for (;;) {

		GString *gstr = g_string_new("");
		if (prefix && prefix->len > 0)
			g_string_append_len(gstr, prefix->str, prefix->len);
		g_snprintf(num, sizeof(num), "%"G_GINT64_FORMAT, counter++);
		g_string_append(gstr, num);

		g_checksum_reset(c);
		g_checksum_update(c, (guint8*) gstr->str, gstr->len);
		binsize = sizeof(bin.b);
		g_checksum_get_digest(c, bin.b, &binsize);

		if (memory[bin.prefix]) {
			g_print("%02X%02X %s %s\n", bin.b[0], bin.b[1],
					memory[bin.prefix], gstr->str);
			g_free(memory[bin.prefix]);
		}

		memory[bin.prefix] = g_string_free(gstr, FALSE);
	}

	g_checksum_free(c);
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		g_printerr ("Usage:i\n");
		g_printerr (" %s addr IP:PORT\n", argv[0]);
		g_printerr (" %s cid  OIOURL\n", argv[0]);
		g_printerr (" %s ping IP:PORT\n", argv[0]);
		g_printerr (" %s hash [PREFIX]\n", argv[0]);
		return 2;
	}
	oio_ext_set_random_reqid ();

	if (!strcmp("addr", argv[1])) {
		for (int i=2; i<argc ;++i)
			_dump_addr (argv[i]);
		return 0;
	} else if (!strcmp("cid", argv[1])) {
		for (int i=2; i<argc ;++i)
			_dump_cid (argv[i]);
		return 0;
	} else if (!strcmp("ping", argv[1])) {
		for (int i=2; i<argc ;++i) {
			const char *url = argv[i];
			_do_ping (url);
			_do_version(url);
			_do_stat (url);
		}
		return 0;
	} else if (!strcmp("hash", argv[1])) {
		_same_hash (argc>2 ? argv[2] : "");
		return 0;
	}
	
	return 1;
}

