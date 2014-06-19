#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.compress"
#endif

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#ifdef APR_HAVE_STDIO_H
#include <stdio.h>              /* for sprintf() */
#endif

#include <unistd.h>
#include <string.h>

#include <zlib.h>
#include <zconf.h>

#include <metautils/lib/metautils.h>

#include "rawx.h"
#include "compression.h"

#include <errno.h>

/* magic file header for zlib block compressed files */
static const unsigned char magic[8] =
    { 0x00, 0xe9, 0x5a, 0x4c, 0x49, 0x42, 0xff, 0x1a };

#define HEADER_SIZE (sizeof(magic) + sizeof(guint32))

static uLong
get_working_buffer_size(uLong uncompressed_size)
{
	return compressBound(uncompressed_size);
}

int
zlib_write_compress_header(FILE *fd, guint32 blocksize, gulong *checksum, guint32 *compressed_size)
{
	gsize written = 0;
	
	GByteArray *headers = NULL;
	int status = 1;
	headers = g_byte_array_new();	

#define HEADER_APPEND(V, S) g_byte_array_append(headers,(guint8*)V, S);

	headers = HEADER_APPEND(&magic, sizeof(magic)); /* char[8] */
	headers = HEADER_APPEND(&blocksize, sizeof(blocksize)); /* guint32 */

	written = fwrite(headers->data, headers->len, 1, fd);

	if (written != 1) {
		DEBUG("Failed to write compression headers");
		goto end;
	}

	*compressed_size = *compressed_size + headers->len;
	
	*checksum = adler32(0, NULL, 0);

	status = 0;

end:

	if(headers)
		g_byte_array_free(headers, TRUE);

	return status;
}

int
zlib_write_compress_eof(FILE *fd, gulong checksum, guint32 *compressed_size)
{
	guint32 eof_marker = 0;
	gsize written = 0;
	int result = 1;

	GByteArray *eof = NULL;
	eof = g_byte_array_new();
	eof = g_byte_array_append(eof, (guint8*)&eof_marker, sizeof(guint32));
	eof = g_byte_array_append(eof, (guint8*)&checksum, sizeof(gulong));
	
	written = fwrite(eof->data, eof->len, 1, fd);

	if (written != 1) {
		WARN("Failed to write checksum and EOF marker");
		goto end;
	}

	*compressed_size = *compressed_size + eof->len;
	
	result = 0;

end:

	if(eof)
		g_byte_array_free(eof, TRUE);

	return result;
}

int
zlib_compress_chunk_part(const void *buf, gsize bufsize, GByteArray *result, gulong* checksum)
{
	guint8* out = NULL;
	gulong bufsize_ulong = bufsize;
	gulong out_max;
	int r = 0;

	/* Sanity check */
	if(!result) {
		ERROR("Invalid parameter : %p", result);
		return 1;
	}

	out_max = get_working_buffer_size(bufsize);
	out = g_malloc0(out_max);
	*checksum = adler32(*checksum, buf, bufsize_ulong);
		
	if (buf == NULL || out == NULL){
		r = 1;
		goto err;
	}

	/* compress block */
	r = compress(out, &out_max, buf, bufsize_ulong);
	if (r != Z_OK){
		/* this should NEVER happen */
		ERROR("internal error - compression failed");
		r = 2;
		goto err;
	}

#define DATA_APPEND(D, S) g_byte_array_append(result, (guint8*)D, S);

	/* write uncompressed block size */
	result = DATA_APPEND(&bufsize_ulong, sizeof(gulong));

	if (out_max < bufsize_ulong) {
		/* write compressed block */
		result = DATA_APPEND(&out_max, sizeof(gulong));
		result = DATA_APPEND(out, out_max);
	}
	else {
		/* not compressible - write uncompressed block */
		result = DATA_APPEND(&bufsize, sizeof(gulong));
		result = DATA_APPEND(buf, bufsize);
	}

	r = 0;

err:
	if (out)
		g_free(out);
	return r; 
}

static int
_zlib_fill_decompressed_buffer(struct compressed_chunk_s * chunk, gsize to_skip)
{
	gsize nb_read = 0;
	gsize total_skipped = 0;
	gulong in_len;
	gulong out_len;
	int r;

	if(chunk->buf)
		g_free(chunk->buf);

	chunk->buf = NULL;
	chunk->buf_len = 0;
	chunk->buf_offset = 0;
	chunk->data_len = 0;

	while(1) {
		/* read uncompressed size */
		nb_read = 0;
		errno = 0;
		// FIXME: dangerous (sizeof(gulong) may vary)
		nb_read = fread(&out_len, sizeof(out_len), 1, chunk->fd);

		if (nb_read != 1) {
			DEBUG("Failed to read block uncompressed size: %s",
					feof(chunk->fd)? "EOF" : strerror(errno));
			return feof(chunk->fd)? 0 : -1;
		}
		/* exit if last block (EOF marker) */
		if(out_len == 0) {
			return 0;
		}

		/* read compressed size */
		in_len = 0;
		nb_read = 0;
		errno = 0;
		// FIXME: dangerous (sizeof(gulong) may vary)
		nb_read = fread(&in_len, sizeof(in_len), 1, chunk->fd);

		if (nb_read != 1) {
			DEBUG("Failed to read block compressed size: %s",
					feof(chunk->fd)? "EOF" : strerror(errno));
			return feof(chunk->fd)? 0 : -1;
		}
		/* check if we are in good block */
		if(to_skip < total_skipped + out_len) {
			/* data in this block */
			chunk->data_len = out_len;
			chunk->buf_offset = to_skip - total_skipped;
			break;
		} else {
			/* don't need to uncompress this block, go to the next */
			total_skipped += out_len;
			if(fseek(chunk->fd, in_len, SEEK_CUR)) {
				/* fseek issue */
				DEBUG("Failed to skip block: %s", strerror(errno));
				return feof(chunk->fd)? 0 : -1;
			}
		}
	}

	/* Consider the "to_skip" bytes already read */
	chunk->read += to_skip;

	DEBUG("_fill_decompressed_buffer: current block compressed size (read from file): %"G_GSIZE_FORMAT, in_len);
	DEBUG("_fill_decompressed_buffer: block_size = %u", (uint)chunk->block_size);

	/* sanity check of the size values */
	if (in_len > chunk->block_size || chunk->data_len > chunk->block_size ||
			in_len == 0 || in_len > chunk->data_len){
		DEBUG("_fill_decompressed_buffer: block size error - data corrupted\n");
		r = -1;
		goto err;
	}

	/* Manage the case of uncompressed data */
	if (in_len == chunk->data_len) {
		chunk->buf_len = chunk->data_len;
		chunk->buf = g_malloc0(chunk->buf_len);
		nb_read = 0;

		nb_read = fread(chunk->buf, chunk->buf_len, 1, chunk->fd);

		if (nb_read != 1) {
			DEBUG("Could not read block: %s", strerror(errno));
			r = -1;
			goto err;
		}
	}
	else { /* in_len < chunk->data_len */
		guint8* in;
		gulong new_len;

		/* place compressed block at the end of the buffer */
		chunk->buf_len = chunk->data_len;
		chunk->buf = g_malloc0(chunk->buf_len);

		TRACE("_fill_uncompressed_buffer: before decompress"
				" (input=%u max_out=%u expected=%u)",
				(uint)in_len, (uint)chunk->buf_len, (uint)chunk->data_len);

		in = g_malloc0(in_len);
		nb_read = 0;

		nb_read = fread(in, in_len, 1, chunk->fd);
		if (nb_read != 1) {
			g_free(in);
			DEBUG("Failed to read compressed block");
			r = -1;
			goto err;
		}

		/* uncompress */
		new_len = chunk->buf_len;
		r = uncompress(chunk->buf, &new_len, in, in_len);
		g_free(in);

		if (r != Z_OK) {
			DEBUG("zlib uncompress returned %d", r);
			r = -1;
			goto err;
		}
	}

	/* update checksum */
	chunk->checksum = adler32(chunk->checksum, chunk->buf, chunk->data_len);
	r = 1;
err:
	return r;
}

gboolean
zlib_compressed_chunk_check_integrity(struct compressed_chunk_s *chunk)
{
	gchar *eof_info = NULL;
	gulong c;	
	gsize len;
	gsize nb_read;
	gboolean status = FALSE;

 	/* len = sizeof(guint32) + sizeof(gulong); */
 	len = sizeof(guint32) + sizeof(guint32);

	eof_info = g_malloc0(len);

	nb_read = 0;
	nb_read  = fread(eof_info, len, 1, chunk->fd);
	
	if (nb_read != 1) {
		ERROR("Failed to read %"G_GSIZE_FORMAT" bytes from chunk", len);
		goto end;
	}

	DEBUG("chunk->checksum : %lu\n", chunk->checksum);
	
	c = *((gulong*)(eof_info + sizeof(guint32)));	

	DEBUG("c (get from file): %lu\n", c);
	/* eof_info + sizeof(guint32) */
	if(memcmp(&c, &(chunk->checksum), sizeof(gulong)) != 0)
		goto end;
	
	status = TRUE;

end:

	if(eof_info)
		g_free(eof_info);	
	
	return status;	
}

int 
zlib_compressed_chunk_get_data(struct compressed_chunk_s *chunk, gsize offset, guint8 *buf, gsize buf_len, GError **error)
{
	gsize max_to_read;
	gsize to_skip = 0;

	(void) error;

	if(offset > 0) {
		to_skip = offset - (chunk->data_len - chunk->buf_offset);
		chunk->buf_offset = MIN(chunk->data_len, chunk->buf_offset + offset);
	}

	if (!chunk->buf || !chunk->data_len || chunk->buf_offset >= chunk->data_len) {
		int rf;

		rf = _zlib_fill_decompressed_buffer(chunk, to_skip);	
		if (rf < 0) {
			TRACE("An error occured while filling buffer");
			return -1;
		}

		DEBUG("Entering compressed_chunk_get_data, buffer refilled, max=%u buf_offset=%u data_len=%u",
				(uint)buf_len, (uint)chunk->buf_offset, (uint)chunk->data_len);
	}
	else {
		DEBUG("Entering compressed_chunk_get_data, reusing data, max=%u buf_offset=%u data_len=%u",
				(uint)buf_len, (uint)chunk->buf_offset, (uint)chunk->data_len);
	}


	if (!chunk->data_len) {
		WARN("Premature end of archive");
		return 0;
	} else if (!chunk->buf) {
		DEBUG("Buffer is null, this must never happen");
		return -1;
	}

	max_to_read = chunk->data_len - chunk->buf_offset;
	max_to_read = MIN(max_to_read, buf_len);
	if (max_to_read > 0) {
		memcpy(buf, chunk->buf + chunk->buf_offset, max_to_read);
		chunk->read += max_to_read;
		chunk->buf_offset += max_to_read;
	}

	DEBUG("Exiting compressed_chunk_get_data, max=%u read=%u buf_offset=%u data_len=%u",
			(uint)buf_len, (uint)max_to_read, (uint)chunk->buf_offset, (uint)chunk->data_len);
	return max_to_read;
}

int
zlib_compressed_chunk_init(struct compressed_chunk_s *chunk, const gchar *path)
{
	int r = 0;	
	gsize nb_read;
	guint8 headers[HEADER_SIZE];
	GError * error = NULL;
	struct chunk_textinfo_s cti;
	struct compressed_chunk_s ck;

	bzero(headers, sizeof(headers));
	bzero(&cti, sizeof(cti));
	bzero(&ck, sizeof(ck));
	
	/* Get chunk uncompressed size in his attr */
	if (!get_chunk_info_in_attr(path, &error, &cti)){
		DEBUG("Failed to get chunk info in attr : %s", error->message);
		g_clear_error(&error);
		return 1;
	}

	ck.uncompressed_size = g_strdup(cti.size);
	DEBUG("size get in attr = %s", ck.uncompressed_size); 

	/* Read magic header & flags */
	/* place block at top of buffer */
	/*
 	 * Step 1: check magic header, read flags & block size, init checksum
 	*/

	ck.fd = fopen(path, "r");

	if (!ck.fd) {
		DEBUG("Failed to open chunk file");
		r = 1;
		goto err;
	}
	
	TRACE("compressed_chunk_init: compressed chunk open");

	/* compile for read all header info in one call */
	nb_read = 0;

	nb_read = fread(headers, sizeof(headers), 1, ck.fd);
	if (nb_read != 1) {
		DEBUG("Failed to read compressed chunk headers");
		r = 2;
		goto err;
	}

	do { /* extract all headers */
		#define GETNEXTPTR(Res,Ptr,Type) do { Res = *((Type *)Ptr); Ptr = ((char*)Ptr) + sizeof(Type); } while (0)
		char *ptr = ((char*)headers + sizeof(magic));
		GETNEXTPTR(ck.block_size, ptr, guint32);
	} while (0);

	if (memcmp(headers, magic, sizeof(magic)) != 0) {
		r = 4;
		goto err;
	}
    	if (ck.block_size < 1024 || ck.block_size > 8*1024*1024L){
        	r = 6;
        	goto err;
    	}

	TRACE("ck.block_size : %d", ck.block_size);

	ck.checksum = adler32(0,NULL,0);
	memcpy(chunk, &ck, sizeof(ck));
	TRACE("chunk->uncompressed_size = %s", chunk->uncompressed_size);

	r=0;

err:
	if (error)
		g_clear_error(&error);
	chunk_textinfo_free_content(&cti);
	return r;
}

gboolean
zlib_init_compress_checksum(gulong* checksum)
{
	TRACE("Init checksum in zlib context");
	*checksum = adler32(0,NULL,0);
	return TRUE;
}

