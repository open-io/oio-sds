#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.chunk_checker"
#endif

#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <rawx.h>

#include "../lib/chunk_check.h"
#include "../lib/broken_event.h"

#include "check.h"
#include "chunk_checker.h"
#include "event_filter.h"

struct chunk_checker_data_s {
	gchar *volume_path;
	struct service_info_s *si;
	long sleep_time;
};

static enum scanner_traversal_e
sleep_after_directory(const gchar *path, guint depth, void *data)
{
	struct chunk_checker_data_s *cc_data;

	(void) depth;
	(void) path;

	cc_data = data;
	sleep(cc_data->sleep_time);
	return SCAN_CONTINUE;
}

static enum scanner_traversal_e
check_chunk_and_sleep(const char *chunk_path, void *data)
{
	GError *local_error = NULL;
	struct chunk_checker_data_s *cc_data;

	cc_data = data;

	if (!check_chunk(chunk_path, cc_data->volume_path, &local_error)) {
		ERROR("check_chunk(%s) : %s", chunk_path, gerror_get_message(local_error));
		g_clear_error(&local_error);
	}

	sleep(cc_data->sleep_time);

	return SCAN_CONTINUE;
}

gboolean
fill_scanning_info_for_chunk_checker(struct volume_scanning_info_s *scanning_info, service_info_t * service_info,
    struct integrity_loop_config_s *config, GError ** error)
{
	gchar volume_path[LIMIT_LENGTH_VOLUMENAME];
	struct chunk_checker_data_s cc_data;
        struct service_tag_s *tag = NULL;

        CHECK_ARG_POINTER(scanning_info, error);
        CHECK_ARG_POINTER(service_info, error);
        CHECK_ARG_POINTER(config, error);

	bzero(volume_path, sizeof(volume_path));
	bzero(scanning_info, sizeof(*scanning_info));
	bzero(&cc_data, sizeof(cc_data));

        tag = service_info_get_tag(service_info->tags, NAME_TAGNAME_RAWX_VOL);
        if (tag == NULL) {
                GSETERROR(error, "Failed to retrieve tag [%s]", NAME_TAGNAME_RAWX_VOL);
                return FALSE;
        }

        /* Fill volume_path */
        if (!service_tag_get_value_string(tag, volume_path, sizeof(volume_path), error)) {
                GSETERROR(error, "Failed to extract string value from tag [%s]", NAME_TAGNAME_RAWX_VOL);
                return FALSE;
        }

        /* Fill callback and callback data */
	scanning_info->volume_path = g_strdup(volume_path);
        scanning_info->file_action = check_chunk_and_sleep;
	scanning_info->dir_exit = sleep_after_directory;

	cc_data.volume_path = g_strdup(volume_path);
        cc_data.sleep_time = config->chunk_checker_sleep_time;
	cc_data.si = service_info_dup(service_info);
	scanning_info->callback_data = g_memdup(&cc_data, sizeof(cc_data));

        return TRUE;
}

gboolean
check_chunk(const char *chunk_path, void *data, GError ** error)
{
	struct chunk_textinfo_s text_chunk;
	GSList *list_mismatch = NULL;

	CHECK_ARG_POINTER(chunk_path, error);
	CHECK_ARG_VALID_FILE(chunk_path, error);

	/* Get content from chunk file attr */
	if (!get_chunk_info_in_attr(chunk_path, error, &text_chunk)) {
		GSETERROR(error, "Failed to read chunk infos from chunk file attributes");
		return FALSE;
	}

	/* Check chunk integrity */
	if (!check_chunk_integrity(chunk_path, &text_chunk, &list_mismatch, error)) {
		GSETERROR(error, "Chunk integrity check failed");
		return FALSE;
	}

	/* if list_mismatch == NULL => chunk integrity ok, we can test chunk referencing  */
	if (list_mismatch==NULL){
	}
	
	/* Send broken events if any */
	if (list_mismatch != NULL) {
		struct broken_event_s * broken_event = NULL;

		broken_event = g_new0(struct broken_event_s, 1);
		memcpy(&(broken_event->service_info), data, sizeof(service_info_t));
		broken_event->broken_elements = list_mismatch;

		if (!record_broken_event(broken_event, error)) {
			GSETERROR(error, "Failed to record a broken event");
			g_free(broken_event);
			g_slist_foreach(list_mismatch, broken_element_gfree, NULL);
			g_slist_free(list_mismatch);
			return FALSE;
		}
	}
	return TRUE;
}
