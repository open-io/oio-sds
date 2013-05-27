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

#include <metautils.h>

#include "../lib/volume_scanner.h"
#include "config.h"

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
