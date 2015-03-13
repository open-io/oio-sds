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

#include <metautils/lib/metautils.h>
#include <common_main.h>

static struct grid_main_option_s *
main_option(void)
{
	static struct grid_main_option_s options[] = {
		{NULL,0,{.b=NULL},NULL}
	};
	return options;
}

static void
main_action(void)
{
}

static void
main_set_defaults(void)
{
}

static void
main_specific_fini(void)
{
}

static gboolean
main_configure(int argc, char **argv)
{
	(void) argc;
	(void) argv;
	return TRUE;
}

static const char *
main_usage(void)
{
	return "place your positional parameters here";
}

static void
main_specific_stop(void)
{
}

static struct grid_main_callbacks main_callbacks = {
	.options = main_option,
	.action = main_action,
	.set_defaults = main_set_defaults,
	.specific_fini = main_specific_fini,
	.configure = main_configure,
	.usage = main_usage,
	.specific_stop = main_specific_stop
};

int
main(int argc, char **argv)
{
	return grid_main_cli(argc, argv, main_callbacks);
}

