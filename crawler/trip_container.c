#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_container"
#endif //G_LOG_DOMAIN


#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <attr/xattr.h>

#include <metautils/lib/metautils.h>

#include <glib.h>

#include "lib/crawler_constants.h"
#include "lib/lib_trip.h"
#include "lib/crawler_tools.h"
#include "lib/dir_explorer.h"



static gchar* trip_name = "trip_container";
static gchar* source_cmd_opt_name = "s";
static gchar* infinite_cmd_opt_name = "infinite";
static gchar* trip_occur_format_string = "(ss)";

static gchar meta2_url[LIMIT_LENGTH_URL] = "";
static gchar* source_directory_path_ref = NULL;

static dir_explorer_t dir_explorer_handle;

static gboolean infinite = FALSE;


// FIX TODO: trip_sqlx and trip_container: the SAME code except trip_name, "xattr url", verif function on trip_next()...

int
trip_progress(void)
{
	return dir_progress(&dir_explorer_handle);
}

int
trip_start(int argc, char** argv)
{
	GError *err = NULL;
	memset(meta2_url, 0, sizeof(meta2_url));
	memset(&dir_explorer_handle, 0, sizeof(dir_explorer_t));

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

	/* Meta2 URL extraction */
	if (getxattr(source_directory_path_ref, "user.meta2_server.address", meta2_url, sizeof(meta2_url)) <= 0) {
        GRID_ERROR("Cannot get xattr parameters of repository [%s]: (errno %d) %s",
				source_directory_path_ref, errno, g_strerror(errno));
        return EXIT_FAILURE;
	}
	
	if (!g_strcmp0("", meta2_url)) {
		GRID_ERROR("Bad xattr azttribute (bad repository?) about repository [%s]", source_directory_path_ref);
		return EXIT_FAILURE;
	}
	/* ------- */

	err = dir_explore(source_directory_path_ref, &dir_explorer_handle);
	if (err) {
		GRID_ERROR("Failed during exploring repository [%s]: %s", source_directory_path_ref, err->message);
        g_clear_error(&err);
        return EXIT_FAILURE;
    }

	return EXIT_SUCCESS;
}

static gboolean
_reset_infinite(void)
{
	GError *err = NULL;
	sleep(1);

	dir_explorer_clean(&dir_explorer_handle);
	err = dir_explore(source_directory_path_ref, &dir_explorer_handle);
	if (err) {
        TRIP_ERROR("Failed to reset dir_explorer [%s]: %s",
				source_directory_path_ref, err->message);
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
		file_path = dir_next_file(&dir_explorer_handle, NULL);
		while (file_path != NULL) {
			if (container_path_is_valid(file_path)) {
				TRIP_INFO("Pass container [%s] to actions", file_path);
				GVariant* ret = g_variant_new(trip_occur_format_string, file_path, meta2_url);
				g_free(file_path);
				return ret;
			}
			g_free(file_path);
			file_path = dir_next_file(&dir_explorer_handle, NULL);
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
	if (NULL!= source_directory_path_ref)
        g_free(source_directory_path_ref);
}
