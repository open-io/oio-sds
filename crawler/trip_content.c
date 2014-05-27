#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "grid.crawler.trip_content"
#endif //G_LOG_DOMAIN

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <attr/xattr.h>

#include <metautils/lib/metacomm.h>
#include <metautils/lib/metautils.h>
#include <meta2/remote/meta2_remote.h>

#include <glib.h>

#include "lib/crawler_constants.h"
#include "lib/crawler_tools.h"
#include "lib/lib_trip.h"
#include "lib/dir_explorer.h"


static gchar* trip_name = "trip_content";
static gchar* source_cmd_opt_name = "s";
static gchar* infinite_cmd_opt_name = "infinite";
static gchar* trip_occur_format_string = "(ss)";

static gchar meta2_url[LIMIT_LENGTH_URL] = "";
static GSList* current_content_list = NULL;
static const gchar* current_container_id_str = NULL;
static gchar* source_directory_path_ref = NULL;

static dir_explorer_t dir_explorer_handle;

static gboolean infinite = FALSE;

static void refresh_current_content_list(const gchar* container_path)
{
	GError* error = NULL;
	addr_info_t meta2_addr;
	gchar* container_id_str = NULL;
	container_id_t container_id;

	if (NULL == container_path || NULL != current_content_list)
		return;

	GRID_DEBUG("Looking for contents in container at %s", container_path);

	memset(&meta2_addr, 0x00, sizeof(addr_info_t));
	l4_address_init_with_url(&meta2_addr, meta2_url, &error);
	if (NULL != error) {
		GRID_ERROR("Failed to load meta2 address: %s", error->message);
		g_clear_error(&error);
		current_content_list = NULL; /* Just to make sure */
	} else {
		container_id_str = g_path_get_basename(container_path);
		container_id_hex2bin(container_id_str, strlen(container_id_str),
				&container_id, &error);
		if (NULL != error) {
			GRID_ERROR("Failed to read container id: %s", error->message);
			g_clear_error(&error);
			current_content_list = NULL; /* Just to make sure */
			g_free(container_id_str);
		} else {
			current_content_list = meta2_remote_container_list(&meta2_addr,
					META2_CONNECTION_TIMEOUT * 1000, &error, container_id);
			if (NULL != error) {
				GRID_ERROR("Failed to list contents of container %s: %s",
						container_id_str, error->message);
				g_clear_error(&error);
				current_content_list = NULL; /* Just to make sure */
				g_free(container_id_str);
			} else {
				g_free((gpointer)current_container_id_str);
				current_container_id_str = container_id_str;
				GRID_DEBUG("Found %d contents",
						g_slist_length(current_content_list));
			}
		}
	}
}

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

	if (!g_strcmp0("", meta2_url)){
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

// FIXME: similar to trip_container
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
        return EXIT_FAILURE;
    }

	return TRUE;
}

static GVariant*
_trip_next_content(void)
{
	if (NULL == current_content_list)
		return NULL;

	gchar* temp_cur_cont = ((path_info_t*)(current_content_list->data))->path;
	gchar* temp_val = g_strconcat(current_container_id_str, G_DIR_SEPARATOR_S,
			temp_cur_cont, NULL);
	GVariant* ret = g_variant_new(trip_occur_format_string, temp_val, meta2_url);
	path_info_clean(current_content_list->data);
	current_content_list = g_slist_delete_link(current_content_list,
			current_content_list);
	GRID_INFO("Pass content [%s] to actions", temp_val);
	if (temp_val)
		g_free(temp_val);

	return ret;
}

static GVariant*
_sub_trip_next(void)
{
	gchar* file_path = NULL;
	while (current_content_list == NULL) {
		// Look for a valid container
		do {
			g_free((gpointer)file_path);
			file_path = dir_next_file(&dir_explorer_handle, NULL);
		} while (file_path != NULL && !container_path_is_valid(file_path));
		if (file_path != NULL) {
			// Valid container found, listing contents
			refresh_current_content_list(file_path);
		} else if (!infinite || !_reset_infinite()) {
			// No valid container found, and loop forbidden or reset failed
			return NULL;
		}
	}
	g_free((gpointer)file_path);
	return _trip_next_content();
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

	if (NULL != current_content_list)
		g_slist_free_full(current_content_list, (GDestroyNotify)path_info_clean);

	if (NULL != source_directory_path_ref)
		g_free(source_directory_path_ref);
}
