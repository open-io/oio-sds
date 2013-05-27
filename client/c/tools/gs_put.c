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

static void
help(void)
{
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Put content utility\n");
	g_printerr("\tUpload one file in container of the given GridStorage namespace\n");
	g_printerr("Usage: gs_put [OPTION]... [NAMES]...\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -a : turns on the autocreation flag. If the container does not exist, it will be created\n");
	g_printerr("\t -q : quiet mode (no ouput)\n");
	g_printerr("\t -v : verbose mode, increases debug output\n");
	g_printerr("\t -m <TOKEN> : the name of the namespace (mandatory)\n");
	g_printerr("\t -d <TOKEN> : the name of the container (mandatory)\n");
	g_printerr("\t -c <TOKEN> : the name of the destination content (is not specified, use basename of source file)\n");
	g_printerr("\t -p <PATH> : the path to the source file (mandatory, must exist and be readable)\n");
	g_printerr("\t -t <TOKEN> : the mime-type to set to the content (optional, default: application/octet-stream)\n");
	g_printerr("\t -u <TOKEN> : the user-metadata to set to the content (optional, format: key1=value1;...)\n");
	g_printerr("\t [-W <NUM> : activate versioning on this container]\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "put", help);
}

