/**
 * @file meta2_check.h
 * META2 checking library
 */

#ifndef META2_CHECK_H
#define META2_CHECK_H

/**
 * @defgroup integrity_loop_lib_meta2_check META2 related checks
 * @ingroup integrity_loop_lib
 * @{
 */

#include <metautils/lib/metautils.h>
 
/**
 * Execute maintenance (mainly vacuum) on SQLITE database
 *
 * @param meta2_db_path the fullp ath to the META2 database
 * @param error
 *
 * @return TRUE or FALSE if an error occured
 *
 * - Execute VACUUM command on sqlite database
 */
gboolean meta2_sqlite_maintenance(const gchar* meta2_db_path, GError **error);

/**
 * Check chunk properties consistancy between chunk from META2 and chunk from RAWX
 *
 * @param raw_content a meta2_raw_content struct containing only the chunk to check
 * @param broken a list of broken_element struct
 * @param error
 *
 * @return TRUE or FALSE if an error occured
 *
 * - Use rawx_client_get_direcoty_data() to retreive the content/chunk infos from the RAWX
 * - Use the check_chunk_referencing() function to find diffs
 */
gboolean check_meta2_chunk(const struct meta2_raw_content_s* raw_content, GSList** broken, GError** error);

/** @} */

#endif /* META2_CHECK_H */
