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

/**
 * @file event_puller.h The broken events puller engine
 */

#ifndef EVENT_PULLER_H
#define EVENT_PULLER_H

/**
 * @defgroup integrity_loop_main_event_puller Broken Events Puller
 * @ingroup integrity_loop_main
 * @{
 */

#include <glib.h>
#include "../lib/broken_event.h"

/**
 * @param event
 * @param error
 * @return
 */
gboolean notify_broken_events_processing(const struct broken_event_s* event, GError **error);

/**
 * @param error
 * @return
 */
gboolean start_event_puller_thread(GError** error);

/** @} */

#endif	/* EVENT_PULLER_H */
