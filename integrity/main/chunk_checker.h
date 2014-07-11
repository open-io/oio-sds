/**
 * @file chunk_checker.h
 * Check chunk integrity
 */

#ifndef CHUNK_CHECKER_H
#define CHUNK_CHECKER_H

/**
 * @defgroup integrity_loop_main_chunk_checker Chunk Checker
 * @ingroup integrity_loop_main
 * @{
 */

#include <metautils/lib/metautils.h>
#include <integrity/lib/volume_scanner.h>
#include <integrity/main/config.h>

/**
 * Extract the volume path from service tags to fill the volume_scanning_info callback user data
 *
 * @param scanning_info a preallocated (including the field volume_path) volume_scanning_info_s
 * @param service_info a service_info to extract volume_path from
 * @param config the integrity_loop config
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
gboolean fill_scanning_info_for_chunk_checker(struct volume_scanning_info_s *scanning_info, service_info_t * service_info, struct integrity_loop_config_s *config, GError ** error);

/**
 * Check integrity and directory referencing for a chunk \n
 * Implements scanner_exec_f() to be used as a callback by volume_scanner.h
 * 
 * @param chunk_path the full path to the chunk file
 * @param data unused
 * @param error
 * 
 * @return TRUE if success, FALSE otherwise (info about error is available in error struct)
 * 
 * - Read attributes from chunk (Rawx Api:get_rawx_info_in_attr())
 * - Check chunk integrity (check_chunk_integrity())
 * - Get data from META2 regarding this chunk (Meta2 Remote Api:meta2raw_remote_stat_content) 
 * - Check directory referencing (check_chunk_referencing())
 * 
 * @test Test arguments
 * 	- Execute with an unexisting chunk_path
 */
gboolean check_chunk(const char* chunk_path, void* data, GError **error);

/** @} */

#endif /* CHUNK_CHECKER_H */
