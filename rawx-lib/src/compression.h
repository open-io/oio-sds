/*
OpenIO SDS rawx-lib
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#ifndef OIO_SDS__rawx_lib__src__compression_h
# define OIO_SDS__rawx_lib__src__compression_h 1

/****************************************************/
/*          COMPRESSION FUNCTIONS DECLARATION       */
/****************************************************/

#include <stdio.h>
#include <glib.h>

#include <zlib.h>
#include <zconf.h>

#define SUCCESS_CODE 0

struct compressed_chunk_s {
	FILE *fd;
	gchar* uncompressed_size;
	guint8* buf;
	guint data_len;
	guint buf_len;
	guint buf_offset; /* offset in the current block */
	guint read; /* offset in the whole chunk */
	guint block_size;
	gulong checksum;
	guint32 flags;
	int method;
	int level;
};

/* Compression context definition */

typedef int (*write_header_f)(FILE *fd, guint32 blocksize, gulong *checksum, guint32 *compressed_size);
typedef int (*compress_data_f)(const void *buf, gsize bufsize, GByteArray *result, gulong *checksum);
typedef int (*write_eof_f)(FILE *fd, gulong checksum, guint32 *compressed_size);
typedef int (*compressed_chunk_get_data_f)(struct compressed_chunk_s *chunk, gsize offset, guint8 *buf, gsize buf_len, GError **error);
typedef int (*compressed_chunk_init_f)(struct compressed_chunk_s *chunk, const gchar *path);
typedef int (*compressed_chunk_check_integrity_f)(struct compressed_chunk_s *chunk);
typedef int (*init_compress_checksum_f)(gulong* checksum);

struct compression_ctx_s {
	compressed_chunk_init_f chunk_initiator;
	init_compress_checksum_f checksum_initiator;
	write_header_f header_writer;
	compress_data_f data_compressor;
	compressed_chunk_get_data_f data_uncompressor;
	write_eof_f eof_writer;
	compressed_chunk_check_integrity_f integrity_checker;
};

gboolean init_compression_ctx(struct compression_ctx_s* comp_ctx, const gchar* algo_name);

// ZLIB FUNCTIONS //

int zlib_write_compress_header(FILE *fd, guint32 blocksize, gulong *checksum, guint32 *compressed_size);

int zlib_write_compress_eof(FILE *fd, gulong checksum, guint32 *compressed_size);

int zlib_compress_chunk_part(const void *buf, gsize bufsize, GByteArray *result, gulong *checksum);

int zlib_compressed_chunk_get_data(struct compressed_chunk_s *chunk, gsize offset, guint8 *buf, gsize buf_len, GError **error);

int zlib_compressed_chunk_init(struct compressed_chunk_s *chunk, const gchar *path);

gboolean zlib_compressed_chunk_check_integrity(struct compressed_chunk_s *chunk);

gboolean zlib_init_compress_checksum(gulong *checksum);

/***********************************************************************/

/*
 * Compress a chunk file
 *
 * @param path the chunk file path to compress
 * @param algorithm the compression algorithm to use (LZO / ZLIB)
 * @param blocksize the compression blocksize
 * @param error a glib GError pointer
 *
 * @return 1 if succeeded, 0 otherwise
 *
 */
int compress_chunk(const gchar* path, const gchar* algorithm, const gint64 blocksize, gboolean preserve, GError ** error);

gboolean compress_file(FILE *src, FILE *dst, struct compression_ctx_s * comp_ctx,
		gint64 blocksize, gulong *checksum, guint32 *compressed_size);

/*
 * Uncompressing a chunk file
 *
 * @param path the chunk file path to compress
 * @param error a glib GError pointer
 *
 * @return 1 if succeeded, 0 otherwise
 */
int
uncompress_chunk(const gchar* path, gboolean preserve, GError ** error);

/*
 * Uncompressing a chunk file
 *
 * @param path the chunk file path to compress
 * @param keep_pending keep .pending file in case of error
 * @param error a glib GError pointer
 *
 * @return 1 if succeeded, 0 otherwise
 */
int
uncompress_chunk2(const gchar* path, gboolean preserve, gboolean keep_pending, GError ** error);

#endif /*OIO_SDS__rawx_lib__src__compression_h*/
