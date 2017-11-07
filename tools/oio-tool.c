/*
oio-tool, a CLI tool of OpenIO
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <glib.h>
#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlx_macros.h>

static gdouble timeout = 10.0;
static gint64 deadline = 0;

static void
_dump_cid (const char *s)
{
	static gchar bad[] =
			"----------------------------------------------------------------";

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
_redirect(const char *dest)
{
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_REDIRECT", deadline));
	gint64 start = oio_ext_monotonic_time();
	GError *err = gridd_client_exec(dest, timeout, encoded);
	gint64 end = oio_ext_monotonic_time();
	if (!err) {
		g_print("KO (%u) %s\n", CODE_INTERNAL_ERROR, "Unexpected success");
		return 1;
	}
	if (err->code != CODE_TOOMANY_REDIRECT) {
		g_print("KO (%u) %s\n", err->code, err->message);
		return 1;
	}
	g_print("OK %lfs\n", (end - start) / (gdouble)G_TIME_SPAN_SECOND);
	return 0;
}

static int
_ping(const char *dest)
{
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_PING", deadline));
	gint64 start = oio_ext_monotonic_time();
	GError *err = gridd_client_exec(dest, timeout, encoded);
	gint64 end = oio_ext_monotonic_time();
	if (err) {
		g_print("PING KO (%d) %s\n", err->code, err->message);
		g_clear_error(&err);
		return 1;
	} else {
		gdouble ping_ms = (end - start) / (gdouble)G_TIME_SPAN_MILLISECOND;
		g_print("PING OK %.3lfms | time=%.3lfms;;;0.0;%.3lf\n",
				ping_ms, ping_ms, timeout * 1000.0);
		return 0;
	}
}

static int
_info(const char *dest)
{
	GByteArray *out = NULL;
	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named(NAME_MSGNAME_SQLX_INFO, deadline));
	gint64 start = oio_ext_monotonic_time();
	GError *err = gridd_client_exec_and_concat(dest, timeout, encoded, &out);
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

static int
_config(const char *ns, gboolean raw, int nbfiles, char **pfiles)
{
	GSList *files = NULL;
	for (int i=0; i<nbfiles; i++)
		files = g_slist_append(files, pfiles[i]);
	oio_var_reset_all();
	const gboolean known = oio_var_value_with_files(ns, TRUE, files);
	g_slist_free(files);

	if (!known) {
		g_printerr("Unknown namespace: [%s]\n", ns);
		return 1;
	}

	if (raw) {
		void _on_var(const char *k, const char *v) {
			g_print("%s=%s\n", k, v);
		}
		oio_var_list_all(_on_var);
	} else {
		GString *out = oio_var_list_as_json();
		g_print("%s", out->str);
		g_string_free(out, TRUE);
	}

	return 0;
}


static void
_print_loc(const char *dotted_loc)
{
	oio_location_t loc = location_from_dotted_string(dotted_loc);
	g_print("%s\t%"OIO_LOC_FORMAT"\n", dotted_loc, loc);
}

static void
_print_usage(const char *name)
{
	g_printerr ("Usage:\n");
	g_printerr ("\nDump a view of all the variables known in the central "
			"configurationn\n");
	g_printerr (" %s config NS [--raw] PATH...\n", name);
	g_printerr ("\nPrint hex representation of the address\n");
	g_printerr (" %s addr IP:PORT\n", name);
	g_printerr ("\nPrint hex representation of container ID\n");
	g_printerr (" %s cid  OIOURL\n", name);
	g_printerr ("\nGenerate container names with same hexadecimal prefix\n");
	g_printerr (" %s hash ACCOUNT [PREFIX]\n", name);
	g_printerr ("\nPing a service (timeout is 10.0 seconds by default)\n");
	g_printerr (" %s ping IP:PORT [TIMEOUT]\n", name);
	g_printerr ("\nGet free CPU, IO and space statistics\n");
	g_printerr (" %s stat [path]...\n", name);
	g_printerr ("\nCompute 64b integer location from dotted string\n");
	g_printerr (" %s location DOTTED_STRING...\n", name);
	g_printerr ("\nCall a handler that always redirects, and succeeds if the "
			"client ends up with a\n'Too many redirections' error\n");
	g_printerr ("  %s redirection IP:PORT\n", name);
}

int
main (int argc, char **argv)
{
	if (argc < 2) {
		_print_usage(argv[0]);
		return 2;
	}

	timeout = 10.0;
	deadline = oio_ext_monotonic_time() + (timeout * G_TIME_SPAN_SECOND);
	oio_ext_set_deadline(deadline);
	oio_ext_set_random_reqid ();

	if (!strcmp("config", argv[1])) {
		gboolean raw = FALSE;
		int idx_files = 3;
		if (argc > idx_files && !strcmp("--raw", argv[idx_files])) {
			idx_files ++;
			raw = TRUE;
		}
		return _config(argv[2], raw, argc - idx_files, argv + idx_files);
	} else if (!strcmp("addr", argv[1])) {
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
		return _ping(argv[2]);
	} else if (!strcmp("stat", argv[1])) {
		_sysstat (argv+2);
		return 0;
	} else if (!strcmp("location", argv[1])) {
		for (int i = 2; i < argc; ++i)
			_print_loc(argv[i]);
		return 0;
	} else if (!strcmp("redirect", argv[1])) {
		if (argc != 3) {
			g_printerr("Usage: %s redirect IP:PORT\n", argv[0]);
			return 1;
		}
		return _redirect(argv[2]);
	} else if (!strcmp("-h", argv[1]) ||
			!strcmp("help", argv[1]) ||
			!strcmp("--help", argv[1])) {
		_print_usage(argv[0]);
		return 0;
	}

	return 1;
}
