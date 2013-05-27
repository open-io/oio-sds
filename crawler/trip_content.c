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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>
#include <sys/types.h>
#include <attr/xattr.h>
#include <meta2_remote.h>

#include "lib_trip.h"
#include "crawler_constants.h"
#include "crawler_common_tools.h"

#define LIMIT_LENGTH_URL 23

static gchar* trip_name = "trip_content";
static gchar* source_cmd_opt_name = "s";
static gchar* trip_occur_format_string = "(ss)";

static GSList* source_directory_list = NULL;
static GDir* source_directory_pointer = NULL;
static gchar meta2_url[LIMIT_LENGTH_URL] = "";
static GSList* current_content_list = NULL;
static const gchar* current_container_id_str = NULL;

static int total_dirs_nb = 0;
static int current_dir_nb = 0;

static void refresh_current_content_list(const gchar* container_path) {	
	GError* error = NULL;
	addr_info_t meta2_addr;
	gchar* container_id_str = NULL;
	container_id_t container_id;

	if (NULL == container_path || NULL != current_content_list)
		return;

	memset(&meta2_addr, 0x00, sizeof(addr_info_t));
        l4_address_init_with_url(&meta2_addr, meta2_url, &error);
	if (NULL != error) {
		g_clear_error(&error);
		current_content_list = NULL; /* Just to make sure */
	}
	else {
		container_id_str = g_path_get_basename(container_path);
		container_id_hex2bin(container_id_str, strlen(container_id_str), &container_id, &error);
		g_free(container_id_str);
		if (NULL != error) {
			g_clear_error(&error);
			current_content_list = NULL; /* Just to make sure */
		}
		else {
			current_content_list = meta2_remote_container_list(&meta2_addr, META2_CONNECTION_TIMEOUT * 1000, &error, container_id);
			if (NULL != error) {
				g_clear_error(&error);
				current_content_list = NULL; /* Just to make sure */
			}
		}
	}
}

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

	/* Meta2 URL extraction */
	getxattr(source_directory_path, "user.meta2_server.address", meta2_url, sizeof(meta2_url));
	if (!g_strcmp0("", meta2_url)) {
		g_free(source_directory_path);

                return EXIT_FAILURE;
	}
	/* ------- */

	dir_explore(source_directory_path);

	return EXIT_SUCCESS;
}

static GVariant*
trip_next_content() {
	if (NULL == current_content_list)
		return NULL;

	gchar* temp_val = g_strconcat(current_container_id_str, G_DIR_SEPARATOR_S, ((path_info_t*)(g_slist_last(current_content_list)->data))->path, NULL);
	GVariant* ret = g_variant_new(trip_occur_format_string, temp_val, meta2_url);
	g_free(g_slist_last(current_content_list)->data);
	current_content_list = g_slist_remove(current_content_list, g_slist_last(current_content_list)->data);
	g_free(temp_val);
	
	return ret;
}

GVariant*
trip_next(void) {
        const gchar* file_name = NULL;

        if (NULL == source_directory_pointer)
                return NULL;

	while (NULL != source_directory_list) {
	        if (NULL != current_content_list)
			return trip_next_content();

		while ((file_name = g_dir_read_name(source_directory_pointer))) {
                        current_container_id_str = file_name;
			gchar* file_path = g_strconcat(g_slist_last(source_directory_list)->data, G_DIR_SEPARATOR_S, (gchar*)file_name, NULL);
			if (FALSE == g_file_test(file_name, G_FILE_TEST_IS_DIR) && TRUE == container_path_is_valid(file_path)) {
				refresh_current_content_list(file_path);
				
				return trip_next_content();
			}
			g_free(file_path);
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

	if (NULL != current_content_list)
		g_slist_free_full(current_content_list, (GDestroyNotify)g_free);
}
