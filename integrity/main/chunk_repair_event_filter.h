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

#ifndef CHUNK_REPAIR_H
#define CHUNK_REPAIR_H

/**
 * @defgroup integrity_loop_lib_chunk_repair Chunk Repair
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>
#include "../lib/broken_event.h"

/**
 * Repair broken attributes of a chunk
 *
 * @param broken_event the broken_event describing what is broken in attributes
 * @data unused
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean repair_chunk_attr(const struct broken_event_s *broken_event, void *data, GError **error);

/**
 * init the chunk_repair_event filter
 *
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean init_chunk_repair_event_filter(GError **error);

/** @} */

#endif	/** CHUNK_REPAIR_H */
