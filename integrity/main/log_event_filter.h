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

#include <integrity/lib/broken_event.h>

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
