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

#ifndef GS_INTEGRITY_REBUILD__H
# define GS_INTEGRITY_REBUILD__H 1

#include <metatypes.h>
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
