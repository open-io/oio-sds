#ifndef GS_INTEGRITY_REBUILD__H
# define GS_INTEGRITY_REBUILD__H 1

#include <metautils/lib/metatypes.h>
#include <glib.h>
#include <grid_client.h>

/**
 *
 * @param path_chunk
 * @param rawx_vol
 * @param rawx_addr
 * @param gs_client
 * @param error
 * @return
 */
gboolean meta2_repair_from_rawx(const gchar *path_chunk,
		const gchar *rawx_vol, const addr_info_t *rawx_addr,
		gs_grid_storage_t *gs_client, GError **error);

/** 
 *
 * @param path
 * @param rawx_vol
 * @param rawx_addr
 * @param error
 * @return
 */
struct meta2_raw_content_s* rawx_load_raw_content(const gchar *path,
		const gchar *rawx_vol, const addr_info_t *rawx_addr,
		GError **error);

#endif /*GS_INTEGRITY_REBUILD__H*/
