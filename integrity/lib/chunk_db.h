/**
 @file
 Chunk database management system.
 */

#ifndef CHUNK_DB_H
#define CHUNK_DB_H

/**
 * @defgroup integrity_loop_lib_chunk_db Chunks database management
 * @ingroup integrity_loop_lib
 * @{
 */

#include <glib.h>

#define CONTENT_DB_NAME "content-to-chunk.db"		/*!< The name of the content Berkley db */
#define CONTAINER_DB_NAME "container-to-chunk.db"	/*!< The name of the container Berkley db */

/**
 Add a chunk to both content-to-chunk and container-to-chunk db

 @param volume_root the volume root path (where db resides)
 @param chunk_path the full path to the chunk file
 @param content_name the content name the chunk belongs to
 @param container_id the container id (in hex format) the content belongs to
 @param error

 @return TRUE or FALSE if an error occured (error is set)

 - 0pen Berkeley db volume_root/content-to-chunk.db
 - Check if we already have an entry for that chunk
 - Add a new entry for that chunk if it was not present
 - Open Berkeley db volume_root/container-to-chunk.db
 - Check if we already have an entry for that chunk
 - Add a new entry for that chunk if it was not present

 @test Test arguments
	- Execute with NULL pointer args
 @test Test execution
	- Execute and check the work was done using native Berkley db API
 */
gboolean add_chunk_to_db(const gchar* volume_root, const gchar* chunk_path,
		const gchar* content_name, const gchar* container_id,
		GError **error);

/**
 Fill the list_chunk given in args with all chunks belonging to the given content

 @param volume_root the volume root path (where db resides)
 @param container_id
 @param content_name the content name which we're looking chunks for
 @param list_chunk list filled with chunk paths (gchar*) belonging to the content. List is set to NULL if no chunks were found
 @param error

 @return TRUE or FALSE if an error occured (error is set)

 - Open Berkeley db volume_root/content-to-chunk.db
 - List all chunks belonging to the content
 - Fill the chunk list

 @test Test arguments
	- Execute with NULL pointer args
 @test Test execution
	- Create fake db using native Berkley db API
	- Add an entry for a fixed content_name and chunk_path
	- Execute with the same content_name and check the list is filled with the correct chunk_path
	- Execute with a different content_name and check the list returned is NULL

 */
gboolean get_content_chunks(const gchar* volume_root, const gchar *container_id, const gchar* content_name,
		GSList **list_chunk, GError **error);


/**
 Fill the list_chunk given in args with all chunks belonging to the given container

 @param volume_root the volume root path (where db resides)
 @param container_id the container id (in hex format) which we're looking chunks for
 @param list_chunk list filled with chunk paths (gchar*) belonging to the container. List is set to NULL if no chunks were found
 @param error

 @return TRUE or FALSE if an error occured (error is set)

 - Open Berkeley db volume_root/container-to-chunk.db
 - List all chunks belonging to the container
 - Fill the chunk list

 @test Test arguments
	- Execute with NULL pointer args
 @test Test execution
	- Create fake db using native Berkley db API
	- Add an entry for a fixed container_id and chunk_path
	- Execute with the same container_id and check the list is filled with the correct chunk_path
	- Execute with a different container_id and check the list returned is NULL
 */
gboolean get_container_chunks(const gchar* volume_root, const gchar* container_id, GSList **list_chunk, GError **error);

gboolean list_container_chunks(const gchar* volume_root, GError **error,
		gboolean (*cb)(GByteArray *gba_k, GByteArray *gba_v));

gboolean list_content_chunks(const gchar* volume_root, GError **error,
		gboolean (*cb)(GByteArray *gba_k, GByteArray *gba_v));

void prepare_chunks_db(const gchar* volume_root);
void commit_chunks_db(const gchar* volume_root);
void rollback_chunks_db(const gchar* volume_root);

/** @} */

#endif /* CHUNK_DB_H */
