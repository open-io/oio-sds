/**
 * @file event_filter.h The broken events filter engine
 */

#ifndef EVENT_FILTER_H
#define EVENT_FILTER_H

/**
 * @defgroup integrity_loop_main_event_filter Broken Events Filter
 * @ingroup integrity_loop_main
 * @{
 */

#include <metautils/lib/metautils.h>
#include <integrity/main/config.h>
#include <integrity/lib/broken_event.h>

extern GAsyncQueue * broken_events_queue;

/**
 * struct to store a broken event filter
 */
struct broken_event_filter_s {
	int location;	/*!< The location of the broken element */
	int property;	/*!< The property broken in this element */
	int reason;	/*!< The reason this property is broken */
};

/**
 * Start the event filter thread
 *
 * @param config the integrity loop config
 * @param error
 *
 * @return TRUE or FALSE if an error occured
 */
gboolean start_event_filter(const struct integrity_loop_config_s * config, GError ** error);


/**
 * Record a new broken event in the filter.
 * The event will be filtered and eventually lauch actions
 *
 * @param broken_event the event to record
 * @param error
 * 
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean record_broken_event(struct broken_event_s * broken_event, GError ** error);


/**
 * The filter action ptototype
 *
 * @param broken_event the filtered event
 * @param data some implementation specific data
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
typedef gboolean (* broken_event_filter_f) (const struct broken_event_s * broken_event, void * data, GError ** error);


/**
 * Register a new action on broken_events with given filter
 *
 * @param filter the filter definition
 * @param filter_func the action to execute on matching events
 * @param data some action specific data
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
*/
gboolean register_event_filter(const struct broken_event_filter_s * filter, broken_event_filter_f filter_func, void * data, GError ** error);

/** @} */

#endif	/* EVENT_FILTER_H */
