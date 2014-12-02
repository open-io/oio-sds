/**
 @file chunk_check.h
 Chunk integrity check lib
 */

#ifndef CHUNK_CHECK_H
#define CHUNK_CHECK_H

/**
 * @defgroup integrity_loop_lib_chunk_check Chunk related checks
 * @ingroup integrity_loop_lib
 * @{
 */

#include <metautils/lib/metautils.h>

#include "check.h"

/**
 * Check that values of size and hash in the chunk attributes matches the chunk size and hash
 * 
 * @param chunk_path the full path to the chunk file
 * @param chunk a chunk_textinfo struct containing values read from chunk attributes
 * @param broken a list of struct chunk_element_s listing mismatch revealed by this check (or NULL if no diffs were found)
 * @param error the error struct
 *  
 * @return TRUE or FALSE if an error occured (info about error is available in error struct)
 * 
 * - Check size in attr is set
 * - Compare size in attributes and chunk size
 * - Check hash in attr is set
 * - Compare hash in attributes and chunk hash
 * - Add a broken_element in broken list for each pb found
 * 
 * @test Test arguments
 *   	- Execute with an unexisting chunk_path
 * @test Test execution
 * 	- Create a fake chunk
 * 	- Execute the callback and check it returns TRUE
 * 	- Corrupt the chunk to change its size or hash
 * 	- Execute the callback and check it returns FALSE
 */
gboolean check_chunk_integrity(const char *chunk_path, const struct chunk_textinfo_s *chunk, GSList ** broken,
    GError ** error);

/**
 * Check that this chunk is well referenced in the grif directory (META0/1/2)
 * 
 * @param content_from_chunk a content_textinfo struct containing values read from chunk attributes
 * @param chunk_from_chunk a chunk_textinfo struct containing values read from chunk attributes
 * @param content_from_meta2 a raw_content struct containing values read from META2 concerning the content/chunk we check
 * @param broken a list of struct chunk_element_s listing mismatch revealed by this check (or NULL if no diffs were found)
 * @param error the error struct
 * 
 * @return TRUE if success, FALSE otherwise (info about error is available in error struct)
 * 
 * - Compare data from attributes and data from META2 :
 *    - chunk.hash
 *    - chunk.id
 *    - chunk.position
 *    - chunk.size
 *    - content.nbchunk
 *    - content.path
 *    - content.size 
 *    - content.sysmetadata
 * - Create a broken content event
 * 
 * @test Test arguments
 *	- Test NULL args
 * @test Test execution
 * 	- Allocate a fake content_from_chunk
 * 	- Allocate a fake content_from_meta2 with same data
 * 	- Execute the function and check it returns TRUE
 * 	- Change chunk.hash value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change chunk.id value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change chunk.position value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change chunk.size value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change content.container value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change content.nbchunk value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change content.path value in content_from_chunk, execute the function and check it returns FALSE
 * 	- Change content.size value in content_from_chunk, execute the function and check it returns FALSE
 */
gboolean check_chunk_referencing(const struct content_textinfo_s *content_from_chunk,
    const struct chunk_textinfo_s *chunk_from_chunk, const struct meta2_raw_content_s *content_from_meta2,
    GSList ** broken, GError ** error);


/**
 * Check struct chunk_textinfo_s given as argument is filled
 *
 * @param chunk the struct chunk_textinfo_s to check
 * @param error
 *
 * @return TRUE or FALSE if a field is not set
 */
gboolean check_chunk_info(struct chunk_textinfo_s *chunk, GError **p_error);

/**
 * Check if a chunk is orphaned, ie if it belongs to the container/content
 * specified in its extended attributes.
 * If no container/content can be found, create them and add the chunk to the
 * content. If no container can be created, trash the chunk.
 *
 * @param check_info info about the chunk path and its extended attributes
 * @param cres result of testing: cres->check_ok is TRUE if the chunk is not
 * 		orphaned, FALSE if it orphaned (in which case it was added to a new
 * 		content or trashed).
 * @param p_err error
 * @return TRUE if the check could be fully executed,
 * 		FALSE if an error occurred.
 */
gboolean check_chunk_orphan(check_info_t *check_info, check_result_t *cres, GError **p_err);

/**
 * Check whether the chunk.id xattr is parsable, and replace it with the file
 * name if needed.
 * @param ci info about the chunk path and its extended attributes
 * @param cres
 * @param p_err error
 * @return TRUE if the check could be fully executed,
 * 		FALSE if an error occurred.
 */
gboolean check_chunk_id_parsable(check_info_t *ci, check_result_t *cres, GError **p_err);

/**
 * Computes the md5 sum of the file given as argument.
 * @param filepath path to the file
 * @return the md5 sum (string), to be freed with g_free, or NULL
 * 		if an error occurred.
 */
gchar* compute_file_md5(const gchar *filepath);

/**
 * Replaces a chunk in the content specified in ctx by the one specified by
 * check_info. The comparison is based on chunk position, ie if the position
 * found in extended attributes is N, the chunk at position N in the content
 * will be deleted and replaced by a new chunk created from all extended
 * attributes.
 *
 * @param ctx context containing info about container/content,
 * 		usually returned by get_meta2_ctx (see check.h).
 * @param rc the raw_chunk to be replaced
 * @param check_info info about the chunk path and its extended attributes
 * @param p_err error
 * @return TRUE if the chunk was actually fixed, FALSE otherwise.
 */
gboolean replace_chunk(struct meta2_ctx_s *ctx, struct meta2_raw_chunk_s *rc,
		check_info_t *check_info, GError **p_err);

/**
 * Rename the file by removing all characters after the last '.' in the file
 * name.
 * @param path the path of the file to rename
 * @return TRUE if renaming was successful, FALSE otherwise
 */
gboolean remove_file_extension(const gchar *path);

/**
 * Trashes a chunk by moving it into a dedicated directory located at the root
 * of rawx volume. Checks whether the dryrun mode was asked, in which case the
 * chunk is not moved but a log message is filled.
 * @param check_info info about the chunk path and its extended attributes
 * @param cres the check result: a message is appended on dryrun mode
 * @return TRUE if the chunk was moved successfully, FALSE otherwise
 */
gboolean trash_chunk(check_info_t *check_info, check_result_t *cres);

/** @} */

#endif /* CHUNK_CHECK_H */
