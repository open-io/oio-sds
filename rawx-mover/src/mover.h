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

#ifndef GRIDSTORAGE__CHUNK_MOVER_API__H
# define GRIDSTORAGE__CHUNK_MOVER_API__H 1

/* YAFDAAUI (yet another forward declaration avoiding an ugly include) */
struct gs_grid_storage_s;

/* YAFDAAUI */
struct service_info_s;

#define GS_MOVER_UNLINK      0x0001
#define GS_MOVER_DEREFERENCE 0x0002
#define GS_MOVER_DOWNLOAD    0x0004
#define GS_MOVER_DRYRUN      0x0008

GError* move_chunk(struct gs_grid_storage_s *gs_client,
		const gchar *path,
		struct service_info_s *rawx_src,
		struct service_info_s *rawx_dst,
		guint32 options);

gboolean chunk_path_is_valid(const gchar *path);

#endif
