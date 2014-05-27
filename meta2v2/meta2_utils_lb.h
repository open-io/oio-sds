#ifndef META2_UTILS_LB_H
# define META2_UTILS_LB_H

#include <metautils/lib/metautils.h>
#include <glib.h>

/**
 * Signature of functions converting (struct service_info_s *)
 * to chunk information.
 */
typedef gpointer (*srvinfo_to_chunk_f)(struct service_info_s *si);

/**
 * Get as many spare chunks as required to upload one metachunk with the
 * specified storage policy.
 *
 * @param lbp Pointer to a rawx load balancing pool
 * @param stgpol Pointer to the wanted storage policy
 * @param result Pointer to a list where spare chunks will be inserted
 * @param answer_beans If TRUE, the spare chunks will be (struct bean_CHUNKS_s*)
 *   instead of (chunk_info_t *)
 * @return A GError in case of error
 */
GError* get_spare_chunks(struct grid_lbpool_s *lbp,
		struct storage_policy_s *stgpol, GSList **result, gboolean use_beans);

/**
 * Get spare chunks according to some criteria.
 *
 * @param lbp Pointer to a rawx load balancing pool
 * @param count The number of wanted spare chunks
 * @param dist The wanted distance between chunks
 * @param stgclass The wanted storage class for spare chunks
 * @param notin_loc The list of locations (char*) that are already know and
 *   that should count when computing distance between chunks
 * @param broken_loc The list of locations (char*) that are known to be broken
 *   and that should be avoided, but do not count when computing distance
 * @param result Pointer to a list where spare chunks will be inserted
 * @param answer_beans If TRUE, the spare chunks will be (struct bean_CHUNKS_s*)
 *   instead of (chunk_info_t*)
 * @return A GError in case of error
 */
GError* get_conditioned_spare_chunks(struct grid_lbpool_s *lbp,
		gint64 count, gint64 dist, const struct storage_class_s *stgclass,
		GSList *notin_loc, GSList *broken_loc, GSList **result,
		gboolean answer_beans);

/**
 * Get spare chunks according to a storage policy and lists of already
 * known chunks. Will return enough spare chunks to complete a metachunk,
 * or just one if the metachunk seems already complete.
 *
 * @param lbp Pointer to a rawx load balancing pool
 * @param stgpol Pointer to the wanted storage policy
 * @param notin The list of chunks that are already known and that are taken
 *   into account when computing distance
 * @param broken The list of chunks that are known to be broken and whose
 *   location should be avoided (do not count when computing distance)
 * @param result Pointer to a list where spare chunks will be inserted
 * @param answer_beans If TRUE, the spare chunks will be (struct bean_CHUNKS_s*)
 *   instead of (chunk_info_t*)
 * @return A GError in case of error
 */
GError* get_conditioned_spare_chunks2(struct grid_lbpool_s *lbp,
		struct storage_policy_s *stgpol, GSList *notin, GSList *broken,
		GSList **result, gboolean answer_beans);

/**
 * Get the service information of the rawx hosting a chunk.
 *
 * @param lbp Pointer to a rawx load balancing pool
 * @param chunk_id The complete chunk id (with URL)
 * @param srvinfo Place where to store the service info (use
 *   service_info_clean to free)
 * @return A GError in case of error
 */
GError* service_info_from_chunk_id(struct grid_lbpool_s *glp,
		const gchar *chunk_id, service_info_t **srvinfo);

#endif
