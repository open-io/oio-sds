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

#ifndef __GSCLIENT_SHORTCUTS_H__
# define __GSCLIENT_SHORTCUTS_H__ 1

# include <grid_client.h>
# include <metatypes.h>

gs_content_t*
gs_container_get_content_from_raw(gs_grid_storage_t *client,
                struct meta2_raw_content_s *raw, gs_error_t **gserr);

#endif
