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

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "rules-motor"
#endif

#include <grid_client.h>
#include <meta2_mover.h>
#include <content_check.h>
#include "./motor.h"

/****************************************************************
 * test functions 
 ****************************************************************/
/*
void
content_info_test(struct crawler_chunk_data_pack_s *c_struct){
	printf("it works!\n");	
	printf("%s\n", c_struct->content_info->path);
	printf("%s\n", c_struct->content_info->container_id);
	printf("%ld\n", c_struct->atime);
	printf("%s\n", c_struct->chunk_path);
}
*/


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
	container_id_t cid;

	container_id_hex2bin(container_id, STRLEN_CONTAINERID, &cid, NULL);

	if (!check_content_storage_policy(ns_name, cid, content_name, FALSE, &error)) {
		ERROR("Failed to check content [%s/%s/%s] storage policy : %s", ns_name, container_id, content_name, error->message);
		g_clear_error(&error);
	}
	else
		INFO("Storage policy for content [%s/%s/%s] was checked and valid",  ns_name, container_id, content_name);
}
