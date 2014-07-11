#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.tools.solr.unref"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../lib/gs_internals.h"
#include "../lib/solr_utils.h"
#include "./gs_tools.h"

static gboolean
unref_solr(gs_grid_storage_t * grid, const gchar * container_name)
{
	return set_solr_service(grid, container_name, NULL);
}

int
main(int argc, gchar **argv)
{
	gs_grid_storage_t *grid = NULL;
	gchar *ns_name = NULL;
	gchar container_name[LIMIT_LENGTH_CONTAINERNAME];
	gs_error_t *error = NULL;

	if (argc < 2) {
		g_print("Missing arg\n");
		g_print("Usage : %s <ns_name> [container_name]\n", argv[0]); 
		return 1;
	}

	ns_name = argv[1];
	if (argc > 2)
		g_strlcpy(container_name, argv[2], LIMIT_LENGTH_CONTAINERNAME);

	/* Init grid */
	grid = gs_grid_storage_init(ns_name, &error);
	if (grid == NULL) {
		g_printerr("Failed to init grid connection : %s\n", gs_error_get_message(error));
		gs_error_free(error);
		return 0;
	}

	/* Read container names from stdin */
	if (argc < 3) {
		memset(container_name, '\0', sizeof(container_name));
		while (fgets(container_name, sizeof(container_name), stdin)) {
			int length = strlen(container_name);
			if (container_name[length-1] == '\n')
				container_name[length-1] = '\0';
			if (FALSE == unref_solr(grid, container_name))
				g_printerr("Failed to unref container %s\n", container_name);
			else
				g_print("Container %s done\n", container_name);
		}
	}
	else
		return unref_solr(grid, container_name);

	return 0;
}
