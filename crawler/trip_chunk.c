/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <glib.h>
#include <stdlib.h>
#include <string.h>

#include "lib_trip.h"
#include "crawler_constants.h"
#include "crawler_common_tools.h"

static gchar* trip_name = "trip_chunk";
static gchar* source_cmd_opt_name = "s";
static gchar* trip_occur_format_string = "(ss)";

static GSList* source_directory_list = NULL;
static GDir* source_directory_pointer = NULL;

static int total_dirs_nb = 0;
static int current_dir_nb = 0;

static void
dir_explore(gchar* current_path) {
	GDir* sdp = g_dir_open(current_path, 0, NULL);
	const gchar* fn = NULL;

	if (NULL != sdp) {
		source_directory_list = g_slist_prepend(source_directory_list, current_path);
		total_dirs_nb++;

		while ((fn = g_dir_read_name(sdp))) {
			gchar* fn2 = g_strconcat(current_path, G_DIR_SEPARATOR_S, fn, NULL);
			if (TRUE == g_file_test(fn2, G_FILE_TEST_IS_DIR))
				dir_explore(fn2);
			else
				g_free(fn2);
		}

		g_dir_close(sdp);
	}	
}

int
trip_progress(void) {
	if (0 == total_dirs_nb)
		return 0;

	return ((current_dir_nb * 100) / total_dirs_nb);
}

int
trip_start(int argc, char** argv) {
	gchar* source_directory_path = NULL;

	/* Source directory path extraction */
	if (NULL == (source_directory_path = get_argv_value(argc, argv, trip_name, source_cmd_opt_name)))
		return EXIT_FAILURE;

	if (NULL == (source_directory_pointer = g_dir_open(source_directory_path, 0, NULL))) {
                g_free(source_directory_path);

                return EXIT_FAILURE;
        }
	/* ------- */

	dir_explore(source_directory_path);

	return EXIT_SUCCESS;
}

GVariant*
trip_next(void) {
        const gchar* file_name = NULL;

        if (NULL == source_directory_pointer)
                return NULL;

	while (NULL != source_directory_list) {
	        while ((file_name = g_dir_read_name(source_directory_pointer))) {
			gchar* file_path = g_strconcat(g_slist_last(source_directory_list)->data, G_DIR_SEPARATOR_S, (gchar*)file_name, NULL);
			if (FALSE == g_file_test(file_name, G_FILE_TEST_IS_DIR) && TRUE == chunk_path_is_valid(file_path))
				return g_variant_new(trip_occur_format_string, file_path, "");
		}
	
		if (NULL != source_directory_pointer)
                	g_dir_close(source_directory_pointer);

		g_free(g_slist_last(source_directory_list)->data);
		source_directory_list = g_slist_remove(source_directory_list, g_slist_last(source_directory_list)->data);

		while ((NULL != source_directory_list) && NULL == (source_directory_pointer = g_dir_open((gchar*)g_slist_last(source_directory_list)->data, 0, NULL))) {
			current_dir_nb++;

			g_free(g_slist_last(source_directory_list)->data);
			source_directory_list = g_slist_remove(source_directory_list, g_slist_last(source_directory_list)->data);
		}

		current_dir_nb++;
	}

        return NULL;
}

void
trip_end(void) {
	if (NULL != source_directory_list)
                g_slist_free_full(source_directory_list, (GDestroyNotify)g_free);
}
