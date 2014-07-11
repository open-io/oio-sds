#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>

#include "./stats_remote.h"

static gboolean flag_xml = FALSE;

static GString *pattern = NULL;

static GArray *addresses = NULL;

/* ------------------------------------------------------------------------- */

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (addresses)
		g_array_free(addresses, TRUE);
	addresses = NULL;
}

static struct grid_main_option_s*
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ "OutputXML", OT_BOOL, {.b=&flag_xml},
			"Write XML instead of the default key=value output"},
		{ "Pattern",   OT_STRING, {.str=&pattern},
			"specific pattern (fnmatch) instead of '*'"},
		{NULL, 0, {.b=0}, NULL}
	};

	return options;
}

static void
main_set_defaults(void)
{
	pattern = g_string_new("*");
	addresses = g_array_sized_new(TRUE, TRUE, sizeof(addr_info_t), 4);
	GRID_DEBUG("Defaults set");
}

static const gchar*
main_get_usage(void)
{
	static const gchar usage[] =
		"(<URL>|<SRV>)...\n"
		"  with:\n"
		"   <URL> : IP ':' PORT\n"
		"   <SRV> : NS '|' TYPE '|' IP ':' PORT\n";
	return usage;
}

static gboolean
_config_single_address(const gchar *arg)
{
	addr_info_t ai;
	GError *err = NULL;
	gchar str_addr[STRLEN_ADDRINFO];

	memset(&ai, 0, sizeof(ai));

	if (!l4_address_init_with_url(&ai, arg, &err)) {
		GRID_ERROR("Invalid address '%s' : %s", arg, err->message);
		g_error_free(err);
		return FALSE;
	}

	g_array_append_vals(addresses, &ai, 1);
	addr_info_to_string(&ai, str_addr, sizeof(str_addr));
	GRID_DEBUG("Configured '%s'", str_addr);
	return TRUE;
}

static gboolean
_config_single_service(const gchar *arg)
{
	gchar **strv = g_strsplit(arg, "|", 4);

	if (g_strv_length(strv) < 3) {
		GRID_ERROR("Invalid service description [%s]", arg);
		g_strfreev(strv);
		return FALSE;
	}
	if (!_config_single_address(strv[2])) {
		g_strfreev(strv);
		return FALSE;
	}

	g_free(strv);
	return TRUE;
}

static gboolean
main_configure(int argc, char **args)
{
	int i;

	if (argc <= 0) {
		GRID_ERROR("Not enough arguments");
		return FALSE;
	}

	for (i=0; i<argc ;i++) {
		gchar *arg = args[i];

		if (strchr(arg, '|')) {
			if (!_config_single_service(arg))
				return FALSE;
		}
		else {
			if (!_config_single_address(arg))
				return FALSE;
		}
	}

	GRID_DEBUG("Configuration done!");
	return TRUE;
}

/* ------------------------------------------------------------------------- */


static void
_stat_addr(addr_info_t *ai)
{
	gchar *escaped_format;
	GHashTableIter iter;
	gpointer k, v;
	GHashTable *ht;
	GError *err = NULL;
	gchar str_addr[STRLEN_ADDRINFO];

	addr_info_to_string(ai, str_addr, sizeof(str_addr));

	ht = gridd_stats_remote(ai, 60000, &err, pattern->str);
	if (!ht) {
		GRID_ERROR("Stat failed for %s : %s", str_addr, err->message);
		g_error_free(err);
		return;
	}

	escaped_format = g_strescape(pattern->str,"");
	if (flag_xml)
		g_print("<stats addr=\"%s\" pattern=\"%s\">\n",
				str_addr, escaped_format);
	else {
		g_print("STAT_ADDRESS='%s'\n", str_addr);
		g_print("STAT_FORMAT=\"%s\"\n", escaped_format);
	}

	g_hash_table_iter_init(&iter, ht);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		gchar *escaped_name = g_strescape((gchar*)k,"");
		if (flag_xml)
			g_print("\t<stat name=\"%s\" value=\"%f\"/>\n", escaped_name, *((gdouble*)v));
		else
			g_print("%s=%f\n", (char*)k, *((gdouble*)v));
		g_free(escaped_name);
	}

	if (flag_xml)
		g_print("</stats>\n");
	g_free(escaped_format);
	g_hash_table_destroy(ht);
}

static void
main_action(void)
{
	guint i;
	addr_info_t *ai;

	for (i=0; i < addresses->len ;i++) {
		ai = &g_array_index(addresses, addr_info_t, i);
		_stat_addr(ai);
	}
}

static struct grid_main_callbacks cb =
{
	.options = main_get_options,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_get_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, &cb);
}

