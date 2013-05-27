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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "grid.tools.put"
#endif

#include <stdlib.h>
#include <glib.h>

#include "gs_tools.h"

static void help (void)
{
	g_printerr( "Description:\n");
	g_printerr( "\tHoneycomb container creation utility\n");
	g_printerr( "\tCreate containers in a given namespace.\n");
	g_printerr( "Usage: gs_create [OPTION]... [NAMES]...\n");
	g_printerr( "OPTION can be:\n");
	g_printerr( "\t -h : displays this help section\n");
	g_printerr( "\t -q : quiet mode (no ouput)\n");
	g_printerr( "\t -v : verbose mode, increases debug output\n");
	g_printerr( "\t -m <TOKEN> : provides the name of the Honeycomb namespace\n");
	g_printerr( "\t -d <TOKEN> : the name of the container to create\n");
	g_printerr( "\t [-S <TOKEN> : the name of the storage policy]\n");
	g_printerr( "\t [-W <NUM> : activate versioning on this container]\n");
	g_printerr( "NAMES are additional container whose creation errors are ignored.\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "put", help);
}

