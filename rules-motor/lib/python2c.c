#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rules-motor"
#endif

#include <grid_client.h>
#include <meta2-mover/lib/meta2_mover.h>
#include <integrity/lib/content_check.h>

#include "motor.h"

/****************************************************************
 * chunks compression/decompression functions
 ****************************************************************/
void
motor_compress_chunk(const char *chunk_path, const char *algo, const int bsize, gboolean preserve)
{
	GError *error = NULL;
	int rc;
	rc = compress_chunk(chunk_path, algo, bsize, preserve, &error);
	if(rc != 1)
		ERROR("Chunk [%s] compression failed : %s", chunk_path, error ? error->message : "unknown error");
	else
		INFO("Chunk [%s] compressed", chunk_path);

	if(error)
		g_clear_error(&error);
}

void
motor_decompress_chunk(const char *chunk_path, gboolean preserve)
{
	GError *error = NULL;
	int rc;
	rc = uncompress_chunk(chunk_path, preserve, &error);
	if(rc != 1)
		ERROR("Chunk [%s] decompression failed : %s", chunk_path, error ? error->message : "unknown error");
	else
		INFO("Chunk [%s] decompressed", chunk_path);

	if(error)
		g_clear_error(&error);
}

/**
 * delete content function
 */
void
motor_delete_content(const gchar * ns_name, const gchar * container_id, const gchar * content_name)
{
	gs_error_t *error = NULL;
	gs_container_t *container = NULL;
	gs_grid_storage_t *gs = NULL;

	gs = gs_grid_storage_init(ns_name, &error);
	if (gs == NULL) {
		ERROR("Failed to get grid connection to ns [%s] : %s", ns_name, gs_error_get_message(error));
		gs_error_free(error);
		return;
	}

	container = gs_get_container_by_hexid(gs, container_id, 0, &error);
	if (container == NULL) {
		ERROR("Failed to get container [%s/%s] : %s", ns_name, container_id, gs_error_get_message(error));
		gs_error_free(error);
		gs_grid_storage_free(gs);
		return;
	}

	if (!gs_delete_content_by_name(container, content_name, &error)) {
		ERROR("Failed to delete content [%s/%s/%s] : %s",ns_name, container_id, content_name, gs_error_get_message(error));
		gs_error_free(error);
		gs_container_free(container);
		gs_grid_storage_free(gs);
		return;
	}

	gs_container_free(container);
	gs_grid_storage_free(gs);
}

/**
 * generic log function
 */
void
motor_log(const char *domain, int lvl, const char *msg)
{
	(void) lvl;
	g_log(domain, GRID_LOGLVL_INFO, msg);
}

int
motor_move_container(const gchar * ns_name, const gchar * xcid)
{
	gs_error_t *gserr = NULL;
	gs_grid_storage_t *cli;
	GError *err = NULL;

	cli = gs_grid_storage_init2(ns_name, 90000, 90000, &gserr);
	if (!cli) {
		ERROR("Grid init error : %s", gs_error_get_message(gserr));
		gs_error_free(gserr);
		return 0;
	}

	g_assert(gserr == NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_RAWX_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_RAWX_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M0_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M0_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M1_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M1_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M2_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_M2_OP, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_MCD_CNX, 90000, NULL);
	gs_grid_storage_set_timeout(cli, GS_TO_MCD_OP, 90000, NULL);

	err = meta2_mover_migrate(cli, xcid, NULL);
	if (err) {
		ERROR("Container migration error : %s", err->message);
		g_clear_error(&err);
		return 0;
	}

	gs_grid_storage_free(cli);
	return 1;
}

/**
 * Storage policy check method
 */
void
motor_check_storage_policy(const gchar * ns_name, const gchar * container_id, const gchar * content_name)
{
	GError *error = NULL;

	if (!check_content_storage_policy(ns_name, container_id, content_name, FALSE, &error)) {
		ERROR("Failed to check content [%s/%s/%s] storage policy : %s", ns_name, container_id, content_name, error->message);
		g_clear_error(&error);
	}
	else
		INFO("Storage policy for content [%s/%s/%s] was checked and valid",  ns_name, container_id, content_name);
}
