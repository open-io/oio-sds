#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.append"
#endif

#include <stdlib.h>

#include "gs_tools.h"

static void
help(void)
{
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Append content utility\n");
	g_printerr("\tAppend one file to an existing contnet in container of the given GridStorage namespace\n");
	g_printerr("Usage: gs_append [OPTION]... [NAMES]...\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -a : turns on the autocreation flag. If the container does not exist, it will be created\n");
	g_printerr("\t -q : quiet mode (no ouput)\n");
	g_printerr("\t -v : verbose mode, increases debug output\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
	g_printerr("\t -c <TOKEN> : the name of the destination content\n");
	g_printerr("\t -p <PATH> : the path to the source file (must exist and be readable)\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "append", help);
}

