/*
oio-tool, a CLI tool of OpenIO
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015-2016 OpenIO, modified as part of OpenIO SDS

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
#include <sqliterepo/sqlx_macros.h>

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
	struct oio_url_s *url = oio_url_init (s);

	if (url && oio_url_has_fq_container(url) && NULL != oio_url_get_id(url)) {
		memset(str_id, 0, sizeof(str_id));
		oio_str_bin2hex(oio_url_get_id(url), oio_url_get_id_size(url),
				str_id, sizeof(str_id));
		dst = str_id;
	}
	else {
		dst = bad;
	}

	g_print("%s %s\n", dst, s);
	oio_url_clean(url);
}

static void
_dump_addr (const char *s)
{
	gchar str[256], hexa[1024];
	struct addr_info_s addr;

	if (grid_string_to_addrinfo(s, &addr)) {
		memset(str, 0, sizeof(str));
		grid_addrinfo_to_string(&addr, str, sizeof(str));
		memset(hexa, 0, sizeof(hexa));
		oio_str_bin2hex(&addr, sizeof(addr), hexa, sizeof(hexa));
		g_print("%s %s\n", str, hexa);
	}
}

static void
_same_hash (const char *acct, const char *p0)
{
	static gchar* memory[65536];

	gint64 counter = 0;
	union {
		guint8 b[32];
		guint16 prefix;
	} bin;

	memset(&bin, 0, sizeof(bin));
	GChecksum *c = g_checksum_new(G_CHECKSUM_SHA256);

	if (*p0) {
		/* pre-loads the memory with the prefix only */
		g_checksum_update(c, (guint8*) acct, strlen(acct));
		g_checksum_update(c, (guint8*)"", 1);
		g_checksum_update(c, (guint8*) p0, strlen(p0));
		gsize binsize = sizeof(bin.b);
		g_checksum_get_digest(c, bin.b, &binsize);
		memory[bin.prefix] = g_strdup(p0);
	}

	for (;;) {

		GString *gstr = g_string_new (p0);
		g_string_append_printf (gstr, "%"G_GINT64_FORMAT, counter++);

		g_checksum_reset(c);

		g_checksum_update(c, (guint8*) acct, strlen(acct));
		g_checksum_update(c, (guint8*)"", 1);
		g_checksum_update(c, (guint8*) gstr->str, gstr->len);
		gsize binsize = sizeof(bin.b);
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

static void
_sysstat (gchar **vols)
{
	GString *tmp = g_string_new("");
	for (;;) {
		g_string_set_size (tmp, 0);
		g_string_append_printf (tmp, "%lu %.03f",
				oio_ext_real_seconds (), 100.0 * oio_sys_cpu_idle ());
		for (gchar **pvol=vols; *pvol ;++pvol) {
			g_string_append_printf (tmp, " %s,%3.03f,%.03f", *pvol,
					100.0 * oio_sys_io_idle (*pvol),
					100.0 * oio_sys_space_idle (*pvol));
		}
		g_print ("%s\n", tmp->str);
		g_usleep (998 * G_TIME_SPAN_MILLISECOND);
	}
	g_string_free (tmp, TRUE);
}

static int
_ping(gchar *dest, gchar *to)
{
	gdouble timeout = g_ascii_strtod(to, NULL);
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_PING"));
	gint64 start = oio_ext_monotonic_time();
	GError *err = gridd_client_exec(dest, timeout, encoded);
	gint64 end = oio_ext_monotonic_time();
	if (err) {
		g_print("KO (%d) %s\n", err->code, err->message);
		g_clear_error(&err);
		return 1;
	} else {
		g_print("OK %lfs\n", (end - start) / (gdouble)G_TIME_SPAN_SECOND);
		return 0;
	}
}

static int
_info(const char *dest)
{
	GByteArray *out = NULL;
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named(NAME_MSGNAME_SQLX_INFO));
	gint64 start = oio_ext_monotonic_time();
	GError *err = gridd_client_exec_and_concat(dest, 10.0, encoded, &out);
	gint64 end = oio_ext_monotonic_time();
	if (err) {
		g_print("KO (%d) %s\n", err->code, err->message);
		g_clear_error(&err);
		return 1;
	} else {
		g_print("OK %lfs\n", (end - start) / (gdouble)G_TIME_SPAN_SECOND);
		g_print("%.*s\n", (int)out->len, (gchar*)out->data);
		return 0;
	}
	if (out) g_byte_array_free(out, TRUE);
}

static void
_print_loc(const char *dotted_loc)
{
	oio_location_t loc = location_from_dotted_string(dotted_loc);
	g_print("%s\t%"OIO_LOC_FORMAT"\n", dotted_loc, loc);
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		g_printerr ("Usage:\n");
		g_printerr ("Print hex representation of the address\n");
		g_printerr (" %s addr IP:PORT\n", argv[0]);
		g_printerr ("Print hex representation of container ID\n");
		g_printerr (" %s cid  OIOURL\n", argv[0]);
		g_printerr ("Generate container names with same hexadecimal prefix\n");
		g_printerr (" %s hash ACCOUNT [PREFIX]\n", argv[0]);
		g_printerr ("Ping a service\n");
		g_printerr (" %s ping IP:PORT [TIMEOUT]\n", argv[0]);
		g_printerr ("Get free CPU, IO and space statistics\n");
		g_printerr (" %s stat [path]...\n", argv[0]);
		g_printerr ("Compute 64b integer location from dotted string\n");
		g_printerr (" %s location DOTTED_STRING...\n", argv[0]);
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
	} else if (!strcmp("hash", argv[1])) {
		if (argc < 2 || argc > 4) {
			g_printerr ("Usage: %s hash ACCOUNT [PREFIX]\n", argv[0]);
			return 1;
		}
		_same_hash (argv[2], argc==4 ? argv[3] : "");
		return 0;
	} else if (!strcmp("info", argv[1])) {
		return _info(argv[2]);
	} else if (!strcmp("ping", argv[1])) {
		if (argc > 3)
			return _ping(argv[2], argv[3]);
		else
			return _ping(argv[2], "10.0");
	} else if (!strcmp("stat", argv[1])) {
		_sysstat (argv+2);
		return 0;
	} else if (!strcmp("location", argv[1])) {
		for (int i = 2; i < argc; ++i)
			_print_loc(argv[i]);
		return 0;
	}

	return 1;
}
