#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.main.meta2_checker"
#endif

#include <string.h>
#include <netdb.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <grid_client.h>
#include <meta2/remote/meta2_remote.h>

#include "check.h"
#include "meta2_checker.h"
#include "../lib/meta2_check.h"


extern GSList *gs_resolve_meta2(gs_grid_storage_t * gs, const container_id_t cID, GError ** err);


/**
 * Find the META2 which is local in the given list of META2 addr
 *
 * @param list_addr_meta2 a list of META2 addr to search in
 * @param addr_local_meta2 a META2 addr which will be filled with the found local META2 addr
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
static gboolean
_find_local_meta2(GSList * list_addr_meta2, addr_info_t * addr_local_meta2, GError ** error)
{
	if (g_slist_length(list_addr_meta2) < 1) {
		GSETERROR(error, "META2 addr list is empty");
		return FALSE;
	}

	memcpy(g_slist_nth_data(list_addr_meta2, 0), addr_local_meta2, sizeof(addr_info_t));

	return TRUE;
}

/**
 * Resolv the local META2 addr for the given container_id
 *
 * @param ns_name the namespace name we are working on
 * @param container_id the container id
 * @param addr_meta2 a pre-allocated add_info_t which will be filled with the resolved META2 addr
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
static gboolean
_resolv_meta2(const gchar * ns_name, const container_id_t container_id, addr_info_t * addr_meta2, GError ** error)
{
	gs_error_t *client_error = NULL;
	gs_grid_storage_t *grid = NULL;
	GSList *list_addr_meta2 = NULL;

	/* Init grid client */
	grid = gs_grid_storage_init(ns_name, &client_error);
	if (grid == NULL) {
		GSETERROR(error, "%s", gs_error_get_message(client_error));
		GSETERROR(error, "Failed to init grid client to retreive META2 addr");
		gs_error_free(client_error);
		goto error_init_grid;
	}

	/* Get META2 addr which manage this db */
	list_addr_meta2 = gs_resolve_meta2(grid, container_id, error);
	if (list_addr_meta2 == NULL) {
		GSETERROR(error, "Failed to resolv META2");
		goto error_resolv;
	}

	if (!_find_local_meta2(list_addr_meta2, addr_meta2, error)) {
		GSETERROR(error, "Failed to find local META2 in META2 addr list");
		goto error_find_local;
	}

	g_slist_foreach(list_addr_meta2, addr_info_gclean, NULL);
	g_slist_free(list_addr_meta2);

	gs_grid_storage_free(grid);

	return TRUE;

      error_find_local:
	g_slist_foreach(list_addr_meta2, addr_info_gclean, NULL);
	g_slist_free(list_addr_meta2);
      error_resolv:
	gs_grid_storage_free(grid);
      error_init_grid:

	return FALSE;
}


/**
 * Check all chunks from the list of contents names given in args
 *
 * @param ctx the META2 connection context
 * @param container_id the container id we are checking
 * @param list_raw_content the list of all contents names of the container
 * @param broken a list of broken_element_s filled with check problems
 */
static void
_check_chunk_from_list(struct metacnx_ctx_s *ctx, const container_id_t container_id, GSList * list_raw_content,
    GSList ** broken)
{
	GError *local_error = NULL;
	GSList *list = NULL;

	for (list = list_raw_content; list && list->data; list = list->next) {
		GSList *local_broken = NULL;
		gchar *str_content_name = list->data;
		struct meta2_raw_content_s *raw_content = NULL;

		raw_content =
		    meta2raw_remote_get_content_from_name(ctx, &local_error, container_id, str_content_name,
		    strlen(str_content_name));
		if (raw_content == NULL) {
			WARN("Failed to get raw_content from META2 : %s", local_error->message);
			g_clear_error(&local_error);
			local_error = NULL;
			continue;
		}

		if (!check_meta2_chunk(raw_content, &local_broken, &local_error)) {
			WARN("Failed to check chunk from RAWX : %s", local_error->message);
			g_clear_error(&local_error);
			local_error = NULL;
			continue;
		}

		*broken = g_slist_concat(*broken, local_broken);
	}
}


gboolean
check_meta2(const gchar * meta2_db_path, void *data, GError ** error)
{
	struct meta2_checker_data_s *checker_data = NULL;
	GSList *list_content_names = NULL;
	gchar *str_container_id = NULL;
	addr_info_t addr_meta2;
	container_id_t container_id;
	GSList *list_broken = NULL;
	struct metacnx_ctx_s *ctx_meta2 = NULL;

	CHECK_ARG_POINTER(meta2_db_path, error);
	CHECK_ARG_POINTER(data, error);
	CHECK_ARG_VALID_FILE(meta2_db_path, error);

	checker_data = data;

	/* Maintenance sqlite db */
	if (!meta2_sqlite_maintenance(meta2_db_path, error)) {
		GSETERROR(error, "Failed to maintenance sqlite database");
		return FALSE;
	}

	/* Extract container_id from meta2_db_path */
	str_container_id = g_path_get_basename(meta2_db_path);
	memset(container_id, 0, sizeof(container_id_t));
	if (!hex2bin(str_container_id, container_id, sizeof(container_id_t), error)) {
		GSETERROR(error, "Failed to convert container_id from hex [%s] to bin", str_container_id);
		goto error_convert;
	}

	/* Resolv META2 */
	memset(&addr_meta2, 0, sizeof(addr_info_t));
	if (!_resolv_meta2(checker_data->ns_name, str_container_id, &addr_meta2, error)) {
		GSETERROR(error, "Failed to resolv local META2 for container [%s]", str_container_id);
		goto error_resolv;
	}

	/* init META2 connection context */
	ctx_meta2 = metacnx_create(error);
	if (ctx_meta2 == NULL) {
		GSETERROR(error, "Failed to create metacnx_ctx_s");
		goto error_alloc_ctx;
	}

	if (!metacnx_init_with_addr(ctx_meta2, &addr_meta2, error)) {
		GSETERROR(error, "Failed to init metacnx_ctx_s");
		goto error_init;
	}

	/* List contents from this db */
	list_content_names = meta2raw_remote_get_contents_names(ctx_meta2, error, container_id);
	if (list_content_names == NULL) {
		GSETERROR(error, "Failed to request get_contents_names on META2");
		goto error_get;
	}

	/* Check all chunks */
	_check_chunk_from_list(ctx_meta2, container_id, list_content_names, &list_broken);

	g_free(str_container_id);

	g_slist_foreach(list_content_names, g_free1, NULL);
	g_slist_free(list_content_names);

	metacnx_close(ctx_meta2);
	metacnx_destroy(ctx_meta2);

	return TRUE;

      error_get:
	if (metacnx_is_open(ctx_meta2))
		metacnx_close(ctx_meta2);
      error_init:
	metacnx_destroy(ctx_meta2);
      error_alloc_ctx:
      error_resolv:
      error_convert:
	g_free(str_container_id);

	return FALSE;
}
