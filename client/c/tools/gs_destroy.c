#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.destroy"
#endif

#include <stdlib.h>

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
	g_printerr( "\t -v : increase the verbosity\n");
	g_printerr( "\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr( "\t -d <TOKEN> : provides the name of the container to be destroyed (with error reporting)\n");
}

int main (int argc, char ** argv)
{
	return gs_tools_main(argc, argv, "delete", help);
}

