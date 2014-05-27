#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.locate"
#endif

#include <stdlib.h>

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

