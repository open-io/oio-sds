#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.ls"
#endif

#include <stdlib.h>

#include "gs_tools.h"

static void
help(void)
{
	g_printerr("usage: gs_ls [OPTIONS...] [CONTAINERS...]\n");
	g_printerr("Description:\n");
	g_printerr("\tHoneycomb List container utility\n");
	g_printerr("\tList the contents available in a container. This lists only the online contents\n");
	g_printerr("\t(no content in a pending state will be listed). The container to be listed is\n");
	g_printerr("\tprovided with an option. If an error occurs when listing this container, gs_ls\n");
	g_printerr("\texits with an erroneous error code.\n");
	g_printerr("\tAdditionnal container names can be specified after the options. Erros on these\n");
	g_printerr("\tcontainers will be reported on standard error output but won't cause a program\n");
	g_printerr("\tfailure exit.\n");
	g_printerr("\tOverall, at least one container name must be provided.\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -q : quiet mode, no output\n");
	g_printerr("\t -v : increase the verbosity\n");
	g_printerr("\t -l : prepend information about each content\n");
	g_printerr("\t -m <TOKEN> : provides the name of the Honeycomb namespace\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
}

static gboolean check_args(t_gs_tools_options *gto, gchar **extra_args)
{
	if (is_content_specified(gto, extra_args)) {
		g_printerr("Error: content name must NOT be supplied.  Please refer to usage.\n");
		return FALSE;
	}
	return TRUE;
}

int
main(int argc, char **argv)
{
	return gs_tools_main_with_argument_check(argc, argv, "get", help, check_args);
}

