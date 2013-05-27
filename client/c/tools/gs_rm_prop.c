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
# define LOG_DOMAIN "grid.tools.prop.rm"
#endif

#include <stdlib.h>
#include <glib.h>

#include "gs_tools.h"


static void
help(void)
{
	g_printerr("usage: gs_rm_prop [OPTIONS...] |[<NS>/<CONTAINER>/[<CONTENT] <PROPERTY>\n");
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Remove Property utility\n");
	g_printerr("\tRemove a container or content property.\n");
	g_printerr("\tIf an error occurs when removing this property, gs_set_prop\n");
	g_printerr("\texits with an erroneous error code.\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -q : quiet mode, no output\n");
	g_printerr("\t -v : increase the verbosity\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
	g_printerr("\t -c <TOKEN> : the name of the content. (If not specified, it search container properties)\n");
	g_printerr("\t -k <TOKEN> : the name of the property to set.\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "propdel", help);
}
