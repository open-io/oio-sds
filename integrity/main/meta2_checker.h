/**
 * @file meta2_checker.h
 * META2 database integrity checker module
 */

#ifndef META2_CHECKER_H
#define META2_CHECKER_H

/**
 * @defgroup integrity_loop_main_meta2_checker META2 Checker
 * @ingroup integrity_loop_main
 * @{
 */

#include <metautils/lib/metautils.h>

/**
 * Internal data passed to the meta2_check callback
 */
struct meta2_checker_data_s {
	gchar ns_name[LIMIT_LENGTH_NSNAME];	/*!< A namespace name */
	addr_info_t cs_addr;			/*!< A conscience addr */
};
 
/**
 * Check META2 database integrity
 * Check META2 data are correctly backed up in chunks attributes
 *
 * @param meta2_db_path the full path to the file
 * @param data some anonymous user data
 * @param error the error struct
 *
 * @return TRUE if success, FALSE otherwise (info about error is available in error struct)
 *
 * - Vacuum the sqlite database with sqlite library
 * - Resolv the META2 addr hosting the container stored in the sqlite file (gs_grid_storage_init(), gs_resolve_meta2())
 * - Connect to the META2 and launch a full integrity check for this container
 * - Get all contents in the container (meta2raw_remote_get_contents_names())
 * - For each content, get its chunks and check data is backed-up on RAWX
 *
 * @test Test arguments
 *	- Execute function with file_path that doesn't exists
 * @test Test execution
	- Create a fake META2 SQLite database
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Execute callback and check it returns TRUE
	- Change content flag to DELETE
	- Execute callback and check it returns FALSE
	- Check that all content and chunks were removed from db
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Change content flag to ADD
	- Execute callback and check it returns FALSE
	- Check that all content and chunks were removed from db
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Add a fake chunk related to the content but with a bad chunk_position (higher than the last chunk)
	- Execute callback and check it returns FALSE
	- Check that fake chunk was removed from db
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Add a fake chunk related to the content but with a bad flag (different from AVAILABLE)
	- Execute callback and check it returns FALSE
	- Check that fake chunk was removed from db
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Add a fake chunk related to the content but with the same chunk_position as one of the existing chunk
	- Execute callback and check it returns FALSE
	- Check that the duplicate chunk_position was logged
	- Add a content with chunks, all with their pending flag set to AVAILABLE
	- Remove one of the chunks
	- Execute callback and check it returns FALSE
	- Check that the missing chunk was logged
 */
gboolean check_meta2(const gchar* meta2_db_path, void* data, GError** error);

/** @} */

#endif /* META2_CHECKER_H */
