#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "gs-rebuild"
#endif

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <attr/xattr.h>
#include <math.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <cluster/lib/gridcluster.h>
#include <rawx-lib/src/rawx.h>
#include <meta2/remote/meta2_remote.h>

#include "./repair.h"
#include "../lib/chunk_db.h"

# define RAW_CONTENT_GET_CID(R) (R)->container_id

static int
get_timeout(struct metacnx_ctx_s *ctx)
{
	return MAX(ctx->timeout.cnx, ctx->timeout.req);
}

static const char *
check_attributes(struct chunk_textinfo_s *chunk, struct content_textinfo_s *content)
{
	if (!chunk)
		return "NULL chunk";
	if (!chunk->path)
		return "Missing mandatory content path";
	if (!chunk->id)
		return "Missing mandatory chunk ID";
	if (!chunk->size)
		return "Missing mandatory chunk size";
	if (!chunk->hash)
		return "Missing mandatory chunk hash";
	if (!chunk->position)
		return "Missing mandatory chunk position";

	if (!content)
		return "NULL content";
	if (!content->path)
		return "Missing mandatory content path";
	if (!content->size)
		return "Missing mandatory content size";
	if (!content->chunk_nb)
		return "Missing mandatory chunk number";
	if (!content->container_id)
		return "Missing mandatory container identifier";

	if (64 != strlen(chunk->id))
		return "Chunk ID has a bad size";
	if (64 != strlen(content->container_id))
		return "Chunk ID has a bad size";
		
	return NULL;
}

/* ------------------------------------------------------------------------- */

static gchar*
meta2_locate_recursive(guint attempts,
		struct metacnx_ctx_s *ctx, const gchar *str_cid,
		gs_grid_storage_t *gs_client, GError **error)
{
	gchar *result = NULL;
	gs_error_t *gserr = NULL;
	struct gs_container_location_s *location;

	if (!attempts) {
		GSETERROR(error, "Too many attempts, container not found");
		return NULL;
	}

	/* We don't know the container's name, try the ID */
	gserr = NULL;
	location = gs_locate_container_by_hexid(gs_client, str_cid, &gserr);
	if (!location) {
		GSETCODE(error, gs_error_get_code(gserr), "Memory error : %s", gs_error_get_message(gserr)); 
		gs_error_free(gserr);
		return NULL;
	}
	
	if (!location->m2_url || !location->m2_url[0]) {
		gs_container_location_free(location);
		GSETCODE(error, gs_error_get_code(gserr), "Container not found", gs_error_get_message(gserr)); 
		gs_error_free(gserr);
		return NULL;
	}

	/* Location found, ok ...  */
	metacnx_clear(ctx);
	if (!metacnx_init_with_url(ctx, location->m2_url[0], error))
		GSETERROR(error, "Invalid META2 address [%s]", location->m2_url[0]);
	else
		result = g_strdup(location->container_name);

	gs_container_location_free(location);
	ctx->timeout.req = ctx->timeout.cnx = 60000;
	return result;
}

static gchar*
meta2_locate(struct metacnx_ctx_s *ctx, struct meta2_raw_content_s *raw,
		gs_grid_storage_t *gs_client, GError **error)
{
	gchar str_cid[STRLEN_CONTAINERID+1];

	bzero(str_cid, sizeof(str_cid));
	container_id_to_string(raw->container_id, str_cid, sizeof(str_cid));

	return meta2_locate_recursive(2, ctx, str_cid, gs_client, error);
}

static gboolean
meta2_repair_from_raw_content(struct meta2_raw_content_s *raw,
		gs_grid_storage_t *gs_client, GError **error)
{
	gboolean rc = FALSE;
	struct metacnx_ctx_s ctx;
	gchar *container_name = NULL;

	bzero(&ctx, sizeof(ctx));

	/* Locate the container */
	container_name = meta2_locate(&ctx, raw, gs_client, error);
	if (!container_name) {
		GSETERROR(error, "META2 not resolved");
		goto label_error_close_cnx;
	}

	/* Open the container */
	guint attempts = 2;
	for (attempts=2 ; attempts ; attempts--) {
		if (meta2_remote_container_open(&(ctx.addr), get_timeout(&ctx), error, RAW_CONTENT_GET_CID(raw)))
			break;
		if (CODE_CONTAINER_NOTFOUND == gerror_get_code(*error)) {
			if (!metacnx_open(&ctx, error))
				GSETERROR(error, "Cannot connect to the META2");
			else if (meta2_remote_container_create_in_fd(&(ctx.fd), ctx.timeout.req, error,
					raw->container_id, container_name))
				GSETERROR(error, "CONTAINER recreated [%s]", container_name);
			else {
				GSETERROR(error, "Container cannot be recreated [%s]", container_name);
				goto label_error_close_cnx;
			}
		}
		else {
			GSETERROR(error, "Cannot open container");
			goto label_error_close_cnx;
		}
	}
	if (!attempts) {
		GSETERROR(error, "Container could not be recreated then located");
		goto label_error_close_cnx;
	}

	/* Insertion without update */
	/* Update content only if we have the chunk with position 0 */
	gboolean local_rc = FALSE;
	GError *local_error = NULL;
	/* Get chunk */
	if (raw->raw_chunks != NULL && raw->raw_chunks->data != NULL && ((struct meta2_raw_chunk_s*)raw->raw_chunks->data)->position == 0)
		local_rc = meta2raw_remote_update_content(&ctx, &local_error, raw, FALSE);
	else
		local_rc = meta2raw_remote_update_chunks(&ctx, &local_error, raw, FALSE, NULL);
	if (local_rc == FALSE) {
		switch (gerror_get_code(local_error)) {
			case CODE_CONTENT_EXISTS:
			case CODE_CONTENT_ONLINE:
				break;
			default: 
				if (error)
					GSETCODE(error, gerror_get_code(local_error),
						"Reference insertion failed : %s", gerror_get_message(local_error));
				else
					g_clear_error(&local_error);
				goto label_error_close_container;
		}
	}

	rc = TRUE;

label_error_close_container:
	meta2_remote_container_close(&(ctx.addr), get_timeout(&ctx), NULL, RAW_CONTENT_GET_CID(raw));

label_error_close_cnx:
	metacnx_close(&ctx);
	if (container_name)
		g_free(container_name);

	return rc;
}

gboolean
meta2_repair_from_rawx(const gchar *path,
		const gchar *rawx_vol, const addr_info_t *rawx_addr,
		gs_grid_storage_t *gs_client, GError **error)
{
	gboolean rc;
	struct meta2_raw_content_s *raw;

	raw = rawx_load_raw_content(path, rawx_vol, rawx_addr, error);
	if (!raw) {
		GSETERROR(error, "Chunk format error");
		return FALSE;
	}

	rc = meta2_repair_from_raw_content(raw, gs_client, error);
	if (!rc)
		GSETERROR(error, "Rebuild error");
	meta2_maintenance_destroy_content(raw);
	return rc;
}

struct meta2_raw_content_s*
rawx_load_raw_content(const gchar *path, const gchar *rawx_vol,
		const addr_info_t *rawx_addr, GError **error)
{
	const char *str_err;
	struct chunk_textinfo_s txt_chunk;
	struct content_textinfo_s txt_content;
	struct meta2_raw_chunk_s *raw_chunk;
	struct meta2_raw_content_s *raw_content;

	bzero(&txt_content, sizeof(txt_content));
	bzero(&txt_chunk, sizeof(txt_chunk));
	raw_chunk = g_malloc0(sizeof(*raw_chunk));
	raw_content = g_malloc0(sizeof(*raw_content));

	if (!get_rawx_info_in_attr(path, error, &txt_content, &txt_chunk)) {
		GSETERROR(error, "Cannot get attributes");
		goto label_error_free_raw;
	}
	if (NULL != (str_err = check_attributes(&txt_chunk, &txt_content))) {
		GSETERROR(error, "Invalid attributes");
		goto label_error_free_attr;
	}
	
	if (!convert_content_text_to_raw(&txt_content, raw_content, error)) {
		GSETERROR(error, "Invalid content fields");
		goto label_error_free_attr;
	}
	if (!convert_chunk_text_to_raw(&txt_chunk, raw_chunk, error)) {
		GSETERROR(error, "Invalid chunk fields");
		goto label_error_free_attr;
	}

	g_strlcpy(raw_chunk->id.vol, rawx_vol, sizeof(raw_chunk->id.vol)-1);
	g_memmove(&(raw_chunk->id.addr), rawx_addr, sizeof(addr_info_t));
	
	meta2_maintenance_add_chunk(raw_content, raw_chunk);
	meta2_maintenance_destroy_chunk(raw_chunk);
	content_textinfo_free_content(&txt_content);
	chunk_textinfo_free_content(&txt_chunk);
	return raw_content;

label_error_free_attr:
	content_textinfo_free_content(&txt_content);
	chunk_textinfo_free_content(&txt_chunk);
label_error_free_raw:
	meta2_maintenance_destroy_chunk(raw_chunk);
	meta2_maintenance_destroy_content(raw_content);
	return NULL;
}

