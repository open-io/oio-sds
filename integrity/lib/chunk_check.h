/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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

#include <metautils.h>

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

/** @} */

#endif /* CHUNK_CHECK_H */
