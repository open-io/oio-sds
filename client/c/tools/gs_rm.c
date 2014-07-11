#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.rm"
#endif

#include "gs_tools.h"

static void help (void)
{
	g_printerr( "Usage:\n");
	g_printerr( "\tgs_rm [OPTION...] [CONTAINERS...]\n");
	g_printerr( "Description:\n");
	g_printerr( "\tGridStorage Content remover\n");
	g_printerr( "\tRemoves a content in a container in the configured namespace\n");
	g_printerr( "Options:\n");
	g_printerr( "\t -h : displays this help section\n");
	g_printerr( "\t -q : quiet mode, no output\n");
	g_printerr( "\t -v : increase the verbosity\n");
	g_printerr( "\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr( "\t -d <TOKEN> : the name of the container\n");
	g_printerr( "\t -c <TOKEN> : the name of the content to remove\n");
}

int
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "delete", help);
}

