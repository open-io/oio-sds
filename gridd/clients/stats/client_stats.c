/*
OpenIO SDS gridd
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>

#include "./stats_remote.h"

static gboolean flag_xml = FALSE;

static GString *pattern = NULL;

static GPtrArray *addresses = NULL;

/* ------------------------------------------------------------------------- */

static void
main_specific_stop(void)
{
}

static void
main_specific_fini(void)
{
	if (addresses)
		g_ptr_array_free(addresses, TRUE);
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
	addresses = g_ptr_array_new();
	GRID_DEBUG("Defaults set");
}

static const char*
main_get_usage(void)
{
	static const char usage[] =
		"(<URL>|<SRV>)...\n"
		"  with:\n"
		"   <URL> : IP ':' PORT\n"
		"   <SRV> : NS '|' TYPE '|' IP ':' PORT\n";
	return usage;
}

static gboolean
_config_single_address(const char *arg)
{
	if (!arg || !metautils_url_valid_for_connect(arg)) {
		GRID_ERROR("Invalid adress: %s", arg);
		return FALSE;
	}

	g_ptr_array_add(addresses, g_strdup(arg));
	GRID_DEBUG("Configured '%s'", arg);
	return TRUE;
}

static gboolean
_config_single_service(const char *arg)
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
_stat_addr(const char *url)
{
	GError *err = NULL;
	gchar **tab = NULL;

	err = gridd_stats_remote(url, pattern->str, &tab);
	if (err) {
		GRID_ERROR("Stat failed for %s : (%d) %s", url, err->code, err->message);
		g_error_free(err);
		return;
	}

	gchar *escaped_format = g_strescape(pattern->str,"");
	if (flag_xml)
		g_print("<stats addr=\"%s\" pattern=\"%s\">\n", url, escaped_format);
	else {
		g_print("STAT_ADDRESS='%s'\n", url);
		g_print("STAT_FORMAT=\"%s\"\n", escaped_format);
	}

	for (gchar **p=tab; *p ;p++) {
		gchar *k = *p;
		gchar *v = strchr(k,'=');
		if (v) {
			*v = '\0';
			v++;
		}
		if (flag_xml) {
			gchar *escaped_name = g_strescape(k,"");
			g_print("\t<stat name=\"%s\" value=\"%f\"/>\n", escaped_name, *((gdouble*)v));
			g_free(escaped_name);
		} else {
			g_print("%s=%s\n", k, v);
		}
	}

	if (flag_xml)
		g_print("</stats>\n");
	g_free(escaped_format);
}

static void
main_action(void)
{
	for (guint i=0; i < addresses->len ;i++)
		_stat_addr(addresses->pdata[i]);
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

