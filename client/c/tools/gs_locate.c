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
# define LOG_DOMAIN "grid.tools.locate"
#endif

#include <stdlib.h>
#include <glib.h>

#include "gs_tools.h"

static void help(void)
{
	g_printerr("Usage: gs_locate [OPTION]... GRIDURL\n");
	g_printerr("OPTION::\n");
	g_printerr("\t -h : displays this help section;\n");
	g_printerr("\t -v : verbose mode, increases debug output;\n");
	g_printerr("\t -F : full details for all chunks;\n");
	g_printerr("GRIDURL:\n");
	g_printerr("\t NS/CONTAINER/CONTENT\n");
	g_printerr("\t NS/CONTENT\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "info", help);
}

