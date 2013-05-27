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

#ifndef META2_REPAIR_H
#define META2_REPAIR_H

/**
 * @defgroup integrity_loop_lib_meta2_repair Meta2 Repair
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>
#include "../lib/broken_event.h"

gboolean repair_meta2(const struct broken_event_s *broken_event, void *data, GError **error);

/**
 * init the meta2_repair_event filter
 *
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean init_meta2_repair_event_filter(GError **error);

/** @} */

#endif	/** META2_REPAIR_H */
