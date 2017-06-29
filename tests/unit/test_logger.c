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

static void
main_specific_stop(void)
{
}

static const gchar*
main_get_usage(void)
{
	return "";
}

static void
main_set_defaults(void)
{
}

static struct grid_main_option_s *
main_get_options(void)
{
	static struct grid_main_option_s options[] = {
		{ NULL, 0, {.b=NULL}, NULL }
	};

	return options;
}

static gboolean
main_configure(int argc, char **args)
{
	(void) argc;
	(void) args;
	return TRUE;
}

static void
main_specific_fini(void)
{
}

static void
test_round(void)
{
	GRID_TRACE2("TRACE2\tno domain");
	GRID_TRACE("TRACE\ttab");
	GRID_DEBUG("DEBUG\ttab");
	GRID_INFO("INFO\ttab");
	GRID_NOTICE("NOTICE\ttab default domain");
	GRID_WARN("WARN\ttab");
	GRID_ERROR("ERROR\ttab");
}

static void
main_action(void)
{
	g_printerr("\n*** Default flags enabled\n");
	test_round();

	g_printerr("\n*** All flags enabled\n");
	oio_log_flags = ~0;
	test_round();

	g_printerr("\n*** TRIM_DOMAIN disabled\n");
	oio_log_flags &= ~LOG_FLAG_TRIM_DOMAIN;
	test_round();

	g_printerr("\n*** PURIFY disabled\n");
	oio_log_flags &= ~LOG_FLAG_PURIFY;
	test_round();
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
	return grid_main(argc, argv, &cb);
}

