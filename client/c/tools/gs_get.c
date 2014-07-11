#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.get"
#endif

#include <stdlib.h>

#include "gs_tools.h"

static void
help(void)
{
	g_printerr("Description:\n");
	g_printerr("\tGridStorage Get content utility\n");
	g_printerr
	    ("\tDownload one file in the given distant container (on the given GridStorage namespace) into the given local file\n");
	g_printerr("Options:\n");
	g_printerr("\t -h : displays this help section\n");
	g_printerr("\t -f : force flag, the target local file will be truncated if it exists."
	    " If this option is not set, it is an error if the target already exists.\n");
	g_printerr("\t -q : quiet mode (no ouput)\n");
	g_printerr("\t -v : verbose mode, increases debug output\n");
	g_printerr("\t -X : Use cache\n");
	g_printerr("\t -m <URL> : provides the URL to the namespace META0\n");
	g_printerr("\t -d <TOKEN> : the name of the container\n");
	g_printerr("\t -c <TOKEN> : the name of the content\n");
	g_printerr("\t -p <PATH> : a path to a local file (must not exist or must be writeable"
	    " and set the force flag)\n");
	g_printerr("\t -V <version> : version of content to get\n");
	g_printerr("\t -C <PATH> : a path to a directory where the downloaded file must be put\n");
	g_printerr("\t -o <NUMBER> : The offset from which to start the content downloading. (default : 0)\n\n");
}

static gboolean check_args(t_gs_tools_options *gto, gchar **extra_args)
{
	gchar *content_name = NULL;
	gboolean has_content_in_url, has_content_in_options;

	if (extra_args)
		content_name = get_content_name(*extra_args);

	has_content_in_url = (NULL != content_name);
	has_content_in_options = gto && gto->remote_path;

	if (!has_content_in_url && !has_content_in_options) {
		g_printerr("Error: content name must be supplied.  Please refer to usage.\n");
		return FALSE;
	}

	if (!gto->local_path) {
		if (content_name)
			gto->local_path = g_strdup(content_name);
		if (gto->remote_path)
			gto->local_path = g_strdup(gto->remote_path);
	}

	g_free(content_name);

	return TRUE;
}

int
main(int argc, char **argv)
{
	return gs_tools_main_with_argument_check(argc, argv, "get", help, check_args);
}

