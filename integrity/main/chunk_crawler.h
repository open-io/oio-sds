/**
 * @file chunk_crawler.h
 * Chunk crawler module
 */

#ifndef CHUNK_CRAWLER_H
#define CHUNK_CRAWLER_H

#include <metautils/lib/metautils.h>
#include <integrity/lib/volume_scanner.h>
#include <integrity/main/config.h>

/**
 * @defgroup integrity_loop_main_chunk_crawler Chunk Crawler
 * @ingroup integrity_loop_main
 * @{
 */

/**
 Save chunk's container and content to Berkeley DB in volume root path

 @param chunk_path the full path to the chunk file
 @param data some anonymous user data
 @param error the error struct

 @return TRUE if success, FALSE otherwise (info about error is available in error struct)

 - Read the RAWX volume root path from the data arg
 - Read attributes from chunk (Metautils Api:content_from_chunk_attributes)
 - Store chunk to Berkeley dbs content-to-chunk.db and container-to-chunk.db (add_chunk_to_db())

 @test Test arguments
	- Execute with an unexisting chunk_path
	- Execute with an unexisting volume_root (passed as data)
 @test Test execution
	- Create a fake chunk
	- Execute the callback with the RAWX volume root path in data
	- Check that chunk has been added to volume_root_path/container-to-chunk.db
	- Check that chunk has been added to volume_root_path/content-to-chunk.db
 */
gboolean save_chunk_to_db(const gchar * chunk_path, void *data, GError ** error);

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
gboolean fill_scanning_info_for_chunk_crawler(struct volume_scanning_info_s *scanning_info, service_info_t * service_info,
    struct integrity_loop_config_s *config, GError ** error);

/** @} */

#endif /* CHUNK_CRAWLER_H */
