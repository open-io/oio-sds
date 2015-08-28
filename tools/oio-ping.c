#include <glib.h>
#include <metautils/lib/metautils.h>

static GError *
_remote_version (const char *to, gchar **out)
{
	if (!to || !metautils_url_valid_for_connect(to))
		return NEWERROR(CODE_BAD_REQUEST, "Bad address");

	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_VERSION"));
	return gridd_client_exec_and_concat_string (to, 30.0, encoded, out);
}

static GError *
_remote_ping (const char *to)
{
	if (!to || !metautils_url_valid_for_connect(to))
		return NEWERROR(CODE_BAD_REQUEST, "Bad address");

	GByteArray *encoded = message_marshall_gba_and_clean (
			metautils_message_create_named("REQ_PING"));
	return gridd_client_exec (to, 30.0, encoded);
}

static GError *
_remote_stat (const char *to, gchar ***out)
{
	if (!to || !metautils_url_valid_for_connect(to))
		return NEWERROR(CODE_BAD_REQUEST, "Bad address");

	MESSAGE req = metautils_message_create_named("REQ_STATS");
	metautils_message_add_field_str (req, "PATTERN", "*");
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

	g_print("#STAT_ADDRESS %s\n", to);
	g_print("#COUNT %u\n", g_strv_length(tab));
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

int
main (int argc, char **argv)
{
	oio_local_set_random_reqid ();

	const char *url = NULL;
	if (argc != 2) {
		g_printerr("Usage: %s IP:PORT\n", argv[0]);
		return 1;
	} else {
		url = argv[1];
	}

	return _do_ping (url) || _do_version(url) || _do_stat (url);
}

