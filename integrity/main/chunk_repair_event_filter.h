#ifndef CHUNK_REPAIR_H
#define CHUNK_REPAIR_H

/**
 * @defgroup integrity_loop_lib_chunk_repair Chunk Repair
 * @ingroup integrity_loop_lib
 * @{
 */

#include <metautils/lib/metautils.h>
#include <integrity/lib/broken_event.h>

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
