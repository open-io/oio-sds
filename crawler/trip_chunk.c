#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_chunk"
#endif //G_LOG_DOMAIN

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>

#include <glib.h>

#include "lib/lib_trip.h"
#include "lib/crawler_tools.h"
#include "lib/dir_explorer.h"

static gchar* trip_name = "trip_chunk";
static gchar* source_cmd_opt_name = "s";
static gchar* infinite_cmd_opt_name = "infinite";
static gchar* trip_occur_format_string = "(ss)";

static gchar* source_directory_path_ref = NULL;

static gboolean infinite = FALSE;

static dir_explorer_t dir_explorer_handle;

int
trip_progress(void)
{
	return dir_progress(&dir_explorer_handle);
}

int
trip_start(int argc, char** argv)
{
	GError *err = NULL;

	/* Infinite parameter extraction */
	gchar* temp_infinite = NULL;
	if (NULL != (temp_infinite = get_argv_value(argc, argv, trip_name, infinite_cmd_opt_name))) {
		infinite = metautils_cfg_get_bool(temp_infinite, FALSE);
		g_free(temp_infinite);
	}
	/* ------- */

	/* Source directory path extraction */
    if (NULL == (source_directory_path_ref = get_argv_value(argc, argv, trip_name, source_cmd_opt_name))) {
        GRID_ERROR("Bad or missing -%s.%s argument", trip_name, source_cmd_opt_name);
        return EXIT_FAILURE;
    }
	/* ------- */

	memset(&dir_explorer_handle, 0, sizeof(dir_explorer_t));
	err = dir_explore(source_directory_path_ref, &dir_explorer_handle);

    if (err) {
        GRID_ERROR("Failed during exploring repository [%s]: %s", source_directory_path_ref, err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

	return EXIT_SUCCESS;
}

// FIXME: similar to trip_container
static gboolean
_reset_infinite(void)
{
	GError *err = NULL;
	sleep(1);

	dir_explorer_clean(&dir_explorer_handle);
	err = dir_explore(source_directory_path_ref, &dir_explorer_handle);

	if (err != NULL) {
		TRIP_ERROR("Failed to reset dir_explorer: %s", err->message);
		g_clear_error(&err);
		return FALSE;
	}

	return TRUE;
}

static GVariant*
_sub_trip_next()
{
	gchar* file_path = NULL;

	do {
		file_path = dir_next_file(&dir_explorer_handle, REDC_LOSTFOUND_FOLDER);
		while (file_path != NULL) {
			if (chunk_path_is_valid(file_path)) {
				TRIP_INFO("Pass chunk [%s] to actions", file_path);
				GVariant* ret = g_variant_new(trip_occur_format_string, file_path, "");
				g_free(file_path);
				return ret;
			}
			g_free(file_path);
			file_path = dir_next_file(&dir_explorer_handle, REDC_LOSTFOUND_FOLDER);
		}
		// file_path is NULL, we can restart at the beginning
		if (!infinite || !_reset_infinite()) {
			return NULL;
		}

	} while (infinite);

	return NULL;
}

GVariant*
trip_next(void)
{
	return _sub_trip_next();
}

void
trip_end(void)
{
	dir_explorer_clean(&dir_explorer_handle);
	if (source_directory_path_ref != NULL)
        g_free(source_directory_path_ref);
}
