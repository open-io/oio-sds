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
# define LOG_DOMAIN "grid.tools.destroy"
#endif

#include <stdlib.h>
#include <glib.h>

#include "gs_tools.h"

static void help (void)
{
	g_printerr( "Description:\n");
	g_printerr( "\tGridStorage Container destructor\n");
	g_printerr( "\tDestroys a container in a namespace. The commonly used namespace\n");
	g_printerr( "\tvariable "ENV_CONTAINER" has no effect in this program\n");
	g_printerr( "Options:\n");
	g_printerr( "\t -h : displays this help section\n");
	g_printerr( "\t -q : quiet mode, no output\n");
	/*g_printerr( "\t -r : recurse on the contents (i.e. delete them) (default: false)\n");*/
	g_printerr( "\t -v : increase the verbosity\n");
	g_printerr( "\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr( "\t -d <TOKEN> : provides the name of the container to be destroyed (with error reporting)\n");
}

int main (int argc, char ** argv)
{
	return gs_tools_main(argc, argv, "delete", help);
}
