#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.prop.set"
#endif

#include "gs_tools.h"

static void
help(void)
{
	g_printerr("usage: gs_set_prop [OPTIONS...]| [<NS>/<CONTAINER>/[<CONTENT>] <PROPERTY> <VALUE>]\n");
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Set Property utility\n");
	g_printerr("\tSet a container or content property.\n");
	g_printerr("\tIf an error occurs when setting this property, gs_set_prop\n");
	g_printerr("\texits with an erroneous error code.\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -q : quiet mode, no output\n");
	g_printerr("\t -v : increase the verbosity\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
	g_printerr("\t -c <TOKEN> : the name of the content. (If not specified, it search container properties)\n");
	g_printerr("\t -k <TOKEN> : the name of the property to set.\n");
	g_printerr("\t -r <TOKEN> : the value of the property to set.\n");
}

int 
main(int argc, char **argv)
{
	return gs_tools_main(argc, argv, "propset", help);
}
