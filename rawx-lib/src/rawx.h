/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__rawx_lib__src__rawx_h
# define OIO_SDS__rawx_lib__src__rawx_h 1

# include <metautils/lib/metatypes.h>

# define ATTR_NAME_MAX_LENGTH 64

# define ATTR_DOMAIN "user.grid"

# define ATTR_NAME_CHUNK_ID                "chunk.id"
# define ATTR_NAME_CHUNK_SIZE              "chunk.size"
# define ATTR_NAME_CHUNK_HASH              "chunk.hash"
# define ATTR_NAME_CHUNK_POS               "chunk.position"
# define ATTR_NAME_CHUNK_METADATA          "chunk.metadata"
# define ATTR_NAME_CHUNK_METADATA_COMPRESS "chunk.metadatacompress"
# define ATTR_NAME_CHUNK_COMPRESSED_SIZE   "chunk.compressedsize"

# define ATTR_NAME_CONTENT_PATH      "content.path"
# define ATTR_NAME_CONTENT_ID        "content.id"
# define ATTR_NAME_CONTENT_VERSION   "content.version"
# define ATTR_NAME_CONTENT_SIZE      "content.size"
# define ATTR_NAME_CONTENT_NBCHUNK   "content.nbchunk"
# define ATTR_NAME_CONTENT_STGPOL    "content.storage_policy"
# define ATTR_NAME_CONTENT_CONTAINER "content.container"

#define NS_RAWX_BUFSIZE_OPTION "rawx_bufsize"

#define NS_COMPRESSION_OPTION "compression"
#define NS_COMPRESS_ALGO_OPTION "compression_algorithm"
#define NS_COMPRESS_BLOCKSIZE_OPTION "compression_blocksize"

#define DEFAULT_STREAM_BUFF_SIZE 512000
#define RAWX_CONF_TIMEOUT 10LLU
#define NS_COMPRESSION_ON "on"

typedef struct rawx_conf_s rawx_conf_t;

struct rawx_conf_s
{
	/* gboolean compression;
	gchar* compression_algorithm;
	gint64 blocksize; */
	namespace_info_t *ni;
	struct storage_policy_s *sp;
	GSList* acl;
	gint64 last_update;
};

typedef struct chunk_textinfo_s
{
	gchar *id;           /**< The chunk id */
	gchar *size;         /**< The chunk size */
	gchar *position;     /**< The chunk position */
	gchar *hash;         /**< The chunk hash */
	gchar *metadata;     /**< The chunk metadata */
} chunk_textinfo_t;

typedef struct content_textinfo_s
{
	gchar *container_id;    /**< The container id */

	gchar *content_id;      /**< The content id */
	gchar *path;            /**< The alias path */
	gchar *version;         /**< The content version */
	gchar *size;            /**< The content size */
	gchar *chunk_nb;        /**< The number of chunks */
	gchar *storage_policy;  /**< The storage policy */

	gchar *rawx_list; /**< The rawx list (introduced by the rainx service) */
	gchar *spare_rawx_list; /**< The rawx list for reconstruction (introduced by the rainx service) */
} content_textinfo_t;


#define chunk_info_clean  g_free0
#define chunk_info_gclean g_free1

void chunk_textinfo_free_content(struct chunk_textinfo_s *cti);

void content_textinfo_free_content(struct content_textinfo_s *cti);

/**
 * Write the attributes in the structure in the extended attributes of
 * the file pointed by the given path.
 *
 * If the structure has fields with a NULL value, it is not an error and
 * the associated attribute won't be set.
 *
 * @param pathname the path of the chunk whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param cti the attributes of the chunk
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_chunk_info_in_attr( const char *pathname, GError **error,
	struct chunk_textinfo_s *cti);

/**
 * Write the attributes in the structure in the extended attributes of
 * the file pointed by the given path.
 *
 * If the structure has fields with a NULL value, it is not an error and
 * the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param cti the attributes of the chunk
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_content_info_in_attr(const char *pathname, GError **error,
	struct content_textinfo_s *cti);

/**
 * Set both the content and the chunk attributes in the extended attributes
 * of the file pointed by the given path.
 *
 * If one of the structure has fields with a NULL value, it is not an error
 * and the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param content the content attributes
 * @param chunk the chunk attributes
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_rawx_info_in_attr(const char *pathname, GError **error,
	struct content_textinfo_s *content, struct chunk_textinfo_s *chunk);

/**
 * Set both the content and the chunk attributes in the extended attributes
 * of the file pointed by the given path.
 *
 * If one of the structure has fields with a NULL value, it is not an error
 * and the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param filedes the already opened filedes of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param content the content attributes
 * @param chunk the chunk attribute
 * @param compression_info the chunk compression informations (algo, bs)
 * @param compressed_size the chunk compressed size
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_rawx_full_info_in_attr(const char *pathname, int filedes, 
	GError **error,
	struct content_textinfo_s *content, struct chunk_textinfo_s *chunk,
	const char *compression_info, const char *compressed_size);

/**
 * Set the compression attributes in the extended attributes
 * of the file pointed by the given path.
 *
 * If one of the structure has fields with a NULL value, it is not an error
 * and the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param ns_name the name of the namespace
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_compression_info_in_attr(const char *pathname, GError **error,
	const char *ns_name);

/**
 * Set the compression attributes in the extended attributes
 * of the file pointed by the given path.
 *
 * If one of the structure has fields with a NULL value, it is not an error
 * and the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param the size of the compressed chunk
 * @return 1 in case of success, 0 in case of error
 */
gboolean set_chunk_compressed_size_in_attr(const char *pathname, GError **error,
        guint32 compressed_size);

/**
 * Get the compression attributes in the extended attributes
 * of the file pointed by the given path.
 *
 * If one of the structure has fields with a NULL value, it is not an error
 * and the associated attribute won't be set.
 *
 * @param pathname the path of the content whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param the size of the compressed chunk
 * @return 1 in case of success, 0 in case of error
 */
gboolean get_chunk_compressed_size_in_attr(const char *pathname, GError **error,
        guint32* compressed_size);

/**
 * Load the given attribute structure with the content extended attributes
 * of the chunk pointed by the given path.
 *
 * The structure fields (the pointers) are overwriten. If an
 * attribute is not found, the associated attribute is set to NULL in the
 * structure.
 *
 * @param pathname the path of the chunk whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param cti the content attributes structure
 * @return 1 in case of success, 0 in case of error
 */
gboolean get_content_info_in_attr( const char *pathname, GError **error,
	struct content_textinfo_s *cti);

/**
 * Load the given attribute structure with the chunk extended attributes
 * of the chunk pointed by the given path.
 *
 * The structure fields (the pointers) are overwriten. If an
 * attribute is not found, the associated attribute is set to NULL in the
 * structure.
 *
 * @param pathname the path of the chunk whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param cti the chunk attributes structure
 * @return 1 in case of success, 0 in case of error
 */
gboolean get_chunk_info_in_attr(const char *pathname, GError **error,
	struct chunk_textinfo_s *cti);

/**
 * Load both attribute structures with the chunk attributes and the
 * content attributes of the chunk pointed by the given path.
 *
 * The structure fields (the pointers) are overwriten. If an
 * attribute is not found, the associated attribute is set to NULL in the
 * structure.
 *
 * @param pathname the path of the chunk whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param cti the chunk attributes structure
 * @return 1 in case of success, 0 in case of error
 */
gboolean get_rawx_info_in_attr(const char *pathname, GError **error,
	struct content_textinfo_s *content, struct chunk_textinfo_s *chunk);

/**
 * Load the given attribute structure with the chunk extended attributes
 * of the chunk pointed by the given path.
 *
 * The structure fields (the pointers) are overwriten. If an
 * attribute is not found, the associated attribute is set to NULL in the
 * structure.
 *
 * @param pathname the path of the chunk whose attributes should be set
 * @param error a pointer to a GError structure filled in case of error
 * @param table the compression attributes table
 * @return 1 in case of success, 0 in case of error
 */
gboolean get_compression_info_in_attr(const char *pathname, GError **error,
	GHashTable **table);

#ifndef RAWXLOCK_ATTRNAME_URL
# define RAWXLOCK_ATTRNAME_URL "user.rawx_server.address"
#endif

#ifndef RAWXLOCK_ATTRNAME_NS
# define RAWXLOCK_ATTRNAME_NS "user.rawx_server.namespace"
#endif

#ifndef RAWXLOCK_FLAG_OVERWRITE
# define RAWXLOCK_FLAG_OVERWRITE 0x00010000
#endif

/* Clean a rawx config, but do not free the structure.  */
void rawx_conf_clean(rawx_conf_t *c);

/* Clean a rawx config, and free the structure.  */
void rawx_conf_gclean(rawx_conf_t *c);

#endif /*OIO_SDS__rawx_lib__src__rawx_h*/
