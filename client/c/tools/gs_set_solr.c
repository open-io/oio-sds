#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.solr.set"
#endif

/* For fmemopen */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <unistd.h>

#include "../lib/gs_internals.h"
#include "../lib/solr_utils.h"

static gchar progname[50];
static gboolean nocommit = FALSE;

static void
usage(void)
{
	g_print("Usage: %s [-n] <ns_name> <solr_service> <container_name>\n", progname); 
	g_print("       cat <container_list> | %s [-n] <ns_name> <solr_service>\n", progname); 
	g_print("Format of the <solr_service> argument: IP:PORT\n"); 
	g_print("\nOptions:\n");
	g_print("    -n: do not commit, only show what would be changed\n");
}

int
main(int argc, gchar **argv)
{
	gs_grid_storage_t *grid = NULL;
	gchar ns_name[LIMIT_LENGTH_NSNAME];
	gchar container_name[LIMIT_LENGTH_CONTAINERNAME];
	gchar solr_service[LIMIT_LENGTH_SRVTYPE];
	gs_error_t *error = NULL;
	gchar c;
	gint first_arg = 1;
	FILE *container_stream;

	strcpy(progname, argv[0]);
	nocommit = FALSE;

	/* Process options */
	while ((c = getopt(argc, argv, "nh")) != -1) {
		first_arg++;
		switch (c) {
			case 'n':
				g_print("### -n option activated: only show changes. ###\n");
				nocommit = TRUE;
				break;
			case '?':
				g_printerr("Unknown option '-%c'.  Exiting.\n", optopt);
			case 'h':
				usage();
				return 1;
		}
	}

	if (argc < first_arg + 2) {
		g_printerr("Missing arg\n");
		usage();
		return 1;
	}
	
	strcpy(ns_name, argv[first_arg]);
	strcpy(solr_service, argv[first_arg + 1]);

	if (argc == first_arg + 2) {
		g_print("### Reading container names from stdin. ###\n");
		container_stream = stdin;
	} else {
		container_stream = fmemopen(argv[first_arg + 2], strlen(argv[first_arg + 2]), "r");
	}

	/* Init grid */
	grid = gs_grid_storage_init(ns_name, &error);
	if (grid == NULL) {
		g_printerr("Failed to init grid connection : %s\n", gs_error_get_message(error));
		gs_error_free(error);
		return 0;
	}

	/* Read container names */
	memset(container_name, '\0', sizeof(container_name));
	while (fgets(container_name, sizeof(container_name), container_stream)) {
		int length = strlen(container_name);
		if (container_name[length-1] == '\n')
			container_name[length-1] = '\0';
		if (nocommit) {
			g_print("container=%s|new_solr_service=%s\n",
					container_name, solr_service);
		} else {
			if (FALSE == set_solr_service(grid, container_name, solr_service))
				g_printerr("Failed to set service [%s] for container [%s]\n",
						solr_service, container_name);
			else
				g_print("Container %s done\n", container_name);
		}
	}

	if (container_stream != stdin)
		fclose(container_stream);

	return 0;
}

