#ifndef GS_META2_MOVER_PUBLIC__H
# define GS_META2_MOVER_PUBLIC__H 1

#include <metautils/lib/metautils.h>

/*!
 *  * Locate the source META2 and the META1, poll a destination META2,
 *   * then advance to the next step
 *    */
GError* meta2_mover_migrate(struct gs_grid_storage_s * ns_client,
		const gchar * xcid, const gchar *meta2_addr);

#endif /* GS_META2_MOVER_PUBLIC__H */
