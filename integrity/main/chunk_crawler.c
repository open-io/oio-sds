#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.chunk_crawler"
#endif

#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <rawx.h>
#include <cluster/lib/gridcluster.h>

#include "check.h"

#include "chunk_crawler.h"
#include "config.h"

#include "../lib/chunk_check.h"
#include "../lib/chunk_db.h"
#include "../lib/volume_scanner.h"
#include "../lib/service_cache.h"

struct chunk_crawler_data_s {
	gchar *volume_path;
	long sleep_time;
};

static enum scanner_traversal_e
save_chunk_and_sleep(const gchar *chunk_path, void *data)
{
	GError *local_error = NULL;
	struct chunk_crawler_data_s *cc_data = data;
	
	if (!save_chunk_to_db(chunk_path, cc_data->volume_path, &local_error)) {
		ERROR("save_chunk_to_db(%s) error : %s", chunk_path,
			gerror_get_message(local_error));
		g_clear_error(&local_error);
	}

	sleep(cc_data->sleep_time);

	return SCAN_CONTINUE;
}

static enum scanner_traversal_e
sleep_after_directory(const gchar *path, guint depth, void *data)
{
	struct chunk_crawler_data_s *cc_data;

	(void) depth;
	(void) path;

	cc_data = data;
	sleep(cc_data->sleep_time);
	return SCAN_CONTINUE;
}

gboolean
fill_scanning_info_for_chunk_crawler(struct volume_scanning_info_s *scanning_info, service_info_t * service_info,
    struct integrity_loop_config_s *config, GError ** error)
{
	gchar volume_path[LIMIT_LENGTH_VOLUMENAME];
	struct chunk_crawler_data_s cc_data;
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
	scanning_info->file_action = save_chunk_and_sleep;
	scanning_info->dir_exit = sleep_after_directory;

	cc_data.volume_path = g_strdup(scanning_info->volume_path);
	cc_data.sleep_time = config->chunk_crawler_sleep_time;
	scanning_info->callback_data = g_memdup(&cc_data, sizeof(cc_data));

	return TRUE;
}

gboolean
save_chunk_to_db(const gchar * chunk_path, void *data, GError ** error)
{
	gchar *volume_root = NULL;
	struct content_textinfo_s content_info;

	CHECK_ARG_POINTER(chunk_path, error);
	CHECK_ARG_POINTER(data, error);

	volume_root = (gchar *) data;

	CHECK_ARG_VALID_FILE(chunk_path, error);
	CHECK_ARG_VALID_DIR(volume_root, error);

	/* Read content info from chunk attributes */
	if (!get_content_info_in_attr(chunk_path, error, &content_info)) {
		GSETERROR(error, "Failed to read rawx info from chunk [%s]", chunk_path);
		return FALSE;
	}

	/* Save chunk_path in content ans container db */
	if (!add_chunk_to_db(volume_root, chunk_path, content_info.path, content_info.container_id, error)) {
		GSETERROR(error, "Failed to add chunk in integrity db [%s]", chunk_path);
		content_textinfo_free_content(&content_info);
		return FALSE;
	}

	content_textinfo_free_content(&content_info);

	return TRUE;
}

