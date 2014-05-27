#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.put"
#endif

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

