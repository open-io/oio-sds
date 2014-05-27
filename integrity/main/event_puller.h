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

#include <metautils/lib/metautils.h>
#include <integrity/lib/broken_event.h>

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
