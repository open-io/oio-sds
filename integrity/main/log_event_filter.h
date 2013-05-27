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
 * @file log_event_filter.h
 */

#ifndef LOG_EVENT_FILTER_H
#define LOG_EVENT_FILTER_H

/**
 * @defgroup integrity_loop_main_log_event_filter Log Event Filter
 * @ingroup integrity_loop_main
 * @{
 */

#include "../lib/broken_event.h"

/**
 * Log broken event to log4c
 *
 * @param broken_event the event to log
 * @param log4c_domain the log4c domain used for logging
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean log_broken_event(const struct broken_event_s *broken_event, void * log4c_domain, GError **error);

/**
 * Initialize the log_event filter
 *
 * @param domain the log domain to log to
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean init_log_event_filter(const gchar * domain, GError ** error);

/** @} */
#endif	/* LOG_EVENT_FILTER_H */
