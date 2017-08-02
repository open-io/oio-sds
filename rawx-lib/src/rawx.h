/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
# define ATTR_DOMAIN_OIO "user.oio"

# define ATTR_NAME_CONTENT_CONTAINER "content.container"

# define ATTR_NAME_CONTENT_ID      "content.id"
# define ATTR_NAME_CONTENT_PATH    "content.path"
# define ATTR_NAME_CONTENT_VERSION "content.version"
# define ATTR_NAME_CONTENT_SIZE    "content.size"
# define ATTR_NAME_CONTENT_NBCHUNK "content.nbchunk"

# define ATTR_NAME_CONTENT_STGPOL      "content.storage_policy"
# define ATTR_NAME_CONTENT_CHUNKMETHOD "content.chunk_method"
# define ATTR_NAME_CONTENT_MIMETYPE    "content.mime_type"

# define ATTR_NAME_METACHUNK_SIZE "metachunk.size"
# define ATTR_NAME_METACHUNK_HASH "metachunk.hash"

# define ATTR_NAME_CHUNK_ID   "chunk.id"
# define ATTR_NAME_CHUNK_SIZE "chunk.size"
# define ATTR_NAME_CHUNK_POS  "chunk.position"
# define ATTR_NAME_CHUNK_HASH "chunk.hash"

# define ATTR_NAME_CHUNK_METADATA_COMPRESS "compression.metadata"
# define ATTR_NAME_CHUNK_COMPRESSED_SIZE   "compression.size"

# define ATTR_NAME_OIO_VERSION "oio.version"

# define ATTR_NAME_OIO_USER_PATH "oio.user"


#define NS_RAWX_BUFSIZE_OPTION "rawx_bufsize"

#define NS_COMPRESSION_OPTION "compression"
#define NS_COMPRESS_ALGO_OPTION "compression_algorithm"
#define NS_COMPRESS_BLOCKSIZE_OPTION "compression_blocksize"

#define DEFAULT_STREAM_BUFF_SIZE 512000
#define RAWX_CONF_TIMEOUT 10LLU
#define NS_COMPRESSION_ON "on"

typedef struct chunk_textinfo_s
{
	gchar *container_id;

	gchar *content_id;
	gchar *content_path;
	gchar *content_version;
	gchar *content_size;
	gchar *content_chunk_nb;

	gchar *content_storage_policy;
	gchar *content_chunk_method;
	gchar *content_mime_type;

	gchar *metachunk_size;
	gchar *metachunk_hash;

	gchar *chunk_id;
	gchar *chunk_size;
	gchar *chunk_position;
	gchar *chunk_hash;

	gchar *compression_metadata;
	gchar *compression_size;

	gchar *oio_version;

	gchar *oio_full_path;

} chunk_textinfo_t;

void chunk_textinfo_free_content(struct chunk_textinfo_s *cti);

gboolean set_rawx_info_to_file (const char *p, GError **error, struct chunk_textinfo_s *chunk);
gboolean set_rawx_info_to_fd (int fd, GError **err, struct chunk_textinfo_s *chunk);

gboolean set_compression_info_in_attr(const char *p, GError **error, const char *v);
gboolean set_chunk_compressed_size_in_attr(const char *p, GError **error, guint32 v);

gboolean get_rawx_info_from_file (const char *p, GError **error, struct chunk_textinfo_s *chunk);
gboolean get_rawx_info_from_fd (int fd, GError **error, struct chunk_textinfo_s *chunk);

gboolean get_compression_info_in_attr(const char *p, GError **error, GHashTable *table);

#endif /*OIO_SDS__rawx_lib__src__rawx_h*/
