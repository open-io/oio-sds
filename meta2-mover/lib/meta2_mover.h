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

#ifndef GS_META2_MOVER_PUBLIC__H
# define GS_META2_MOVER_PUBLIC__H 1

#include <glib.h>
#include <grid_client.h>
#include <metautils.h>

/*!
 *  * Locate the source META2 and the META1, poll a destination META2,
 *   * then advance to the next step
 *    */
GError* meta2_mover_migrate(gs_grid_storage_t * ns_client, const gchar * xcid, const gchar *meta2_addr);

#endif /* GS_META2_MOVER_PUBLIC__H */
