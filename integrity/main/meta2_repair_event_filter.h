#ifndef META2_REPAIR_H
#define META2_REPAIR_H

/**
 * @defgroup integrity_loop_lib_meta2_repair Meta2 Repair
 * @ingroup integrity_loop_lib
 * @{
 */

#include <metautils/lib/metautils.h>
#include <integrity/lib/broken_event.h>

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
