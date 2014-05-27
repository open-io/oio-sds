#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.put"
#endif

#include <stdlib.h>

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

