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

#include <metautils/lib/metautils.h>

#include "rawx.h"
#include "compression.h"

/* magic file header for lzopack-compressed files */
static const unsigned char lzo_magic[7] =
    { 0x00, 0xe9, 0x4c, 0x5a, 0x4f, 0xff, 0x1a };

#define LZO_METHOD         0x01
#define LZO_LEVEL          0x01
#define LZO_FLAG_CHECKSUM  0x00000001

#define HEADER_SIZE (sizeof(lzo_magic) + sizeof(lzo_uint32) + sizeof(char) + sizeof(char) + sizeof(lzo_uint32))


static gsize
get_working_buffer_size(gsize uncompressed_size)
{
	return uncompressed_size + uncompressed_size / 16 + 64 + 3;
}

int
lzo_write_compress_header(FILE *file, guint32 blocksize, gulong *checksum, guint32 *compressed_size)
{
	lzo_uint32 flags = LZO_FLAG_CHECKSUM;       /* do compute a checksum */
	char method = LZO_METHOD;
	char level = LZO_LEVEL;
	gsize written = 0;

	GByteArray *headers = NULL;
	headers = g_byte_array_new();	

#define HEADER_APPEND(V, S) g_byte_array_append(headers,(guint8*)V, S);

	headers = HEADER_APPEND(&lzo_magic, sizeof(lzo_magic)); /* char[7] */
	headers = HEADER_APPEND(&flags, sizeof(flags)); /* guint32 */
	headers = HEADER_APPEND(&method, sizeof(method)); /* char */
	headers = HEADER_APPEND(&level, sizeof(level)); /* char */
	headers = HEADER_APPEND(&blocksize, sizeof(blocksize)); /* guint32 */

	written = fwrite(headers->data, headers->len, 1, file);

	if (written != 1) {
		ERROR("Failed to write headers\n");
		if(headers)
			g_byte_array_free(headers, TRUE);
		return 1;
	}

	*compressed_size = *compressed_size + headers->len;
	lzo_uint32 cheksum32 = 0;
	cheksum32 = lzo_adler32(0, NULL, 0);
	*checksum = cheksum32;
	if(headers)
		g_byte_array_free(headers, TRUE);
	return 0;
}

int
lzo_write_compress_eof(FILE *file, gulong checksum, guint32 *compressed_size)
{
	lzo_uint32 eof_marker = 0;
	gsize written = 0;

	GByteArray *eof = NULL;
	eof = g_byte_array_new();
	eof = g_byte_array_append(eof, (guint8*)&eof_marker, sizeof(guint32));
	lzo_uint32 checksum32 = 0;
	checksum32 = checksum;
	eof = g_byte_array_append(eof, (guint8*)&checksum32, sizeof(guint32));
	
	written = fwrite(eof->data, eof->len, 1, file);
	if (written != 1) {
		DEBUG("Failed to write eof\n");
		if(eof)
			g_byte_array_free(eof, TRUE);
		return 1;
	}

	*compressed_size = *compressed_size + eof->len;
	if(eof)
		g_byte_array_free(eof, TRUE);
	return 0;
}

int
lzo_compress_chunk_part(const void *buf, gsize bufsize, GByteArray *result, gulong* checksum)
{
	lzo_bytep out = NULL;
	lzo_uint out_len = 0;
	gsize out_max;
	lzo_bytep wrkmem = NULL;
	lzo_uint wrk_len = 0;
	int r = 0;
	
	/* Sanity check */
	if(!result) {
		ERROR("Invalid parameter : %p", result);
		return 1;
	}

	out_max = get_working_buffer_size(bufsize);
	out = g_malloc0(out_max);
	lzo_uint tmp = bufsize;
	lzo_uint32 checksum32 = 0;
	checksum32 = *checksum;
	checksum32 = lzo_adler32(checksum32, buf, tmp);
	*checksum = checksum32;

	wrk_len = LZO1X_1_MEM_COMPRESS;
	wrkmem = (lzo_bytep) g_malloc0(wrk_len);
	if (buf == NULL || out == NULL || wrkmem == NULL){
		DEBUG("out of memory\n");
		r = 1;
		goto err;
	}

	/* compress block */
	r = lzo1x_1_compress(buf, bufsize, out, &out_len, wrkmem);
	if (r != LZO_E_OK || out_len > out_max){
		/* this should NEVER happen */
		DEBUG("internal error - compression failed\n");
		r = 2;
		goto err;
	}

#define DATA_APPEND(D, S) g_byte_array_append(result, (guint8*)D, S);

	/* write uncompressed block size */
	result = DATA_APPEND(&bufsize, sizeof(lzo_uint));

	if (out_len < bufsize) {
		/* write compressed block */
		result = DATA_APPEND(&out_len, sizeof(lzo_uint));
		result = DATA_APPEND(out, out_len);
		out = NULL;
	}
	else {
		/* not compressible - write uncompressed block */
		result = DATA_APPEND(&bufsize, sizeof(lzo_uint));
		result = DATA_APPEND(buf, bufsize);
	}

	r = 0;

err:
	g_free(wrkmem);
	if (out)
		g_free(out);
	return r; 
}

static int
_fill_decompressed_buffer(struct compressed_chunk_s * chunk, gsize to_skip)
{
	DEBUG("_fill_decompressed_buffer: START\n");
	gsize nb_read;
	gsize in_len;
	gulong out_len;
	gsize total_skipped = 0;
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
		nb_read = fread(&out_len, sizeof(out_len), 1, chunk->fd);
		if (nb_read != 1) {
			DEBUG("Failed to read compressed chunk size");
			return -1;
		}
		/* exit if last block (EOF marker) */
		if(out_len == 0) {
			return 0;
		}

		/* read compressed size */
		in_len = 0;
		nb_read = 0;
		nb_read = fread(&in_len, sizeof(in_len), 1, chunk->fd);

		if (nb_read != 1) {
			return -1;
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
				return -1;
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
		DEBUG("_fill_decompressed_buffer: block size error - data corrupted");
		r = -1;
		goto err;
	}
	DEBUG("_fill_decompressed_buffer: ok, data not corrupted, it's time to work");

	/* Manage the case of uncompressed data */
	if (in_len == chunk->data_len) {
		chunk->buf_len = chunk->data_len;
		chunk->buf = g_malloc0(chunk->buf_len);
		nb_read = 0;
		nb_read = fread(chunk->buf, chunk->buf_len, 1, chunk->fd);
		if (nb_read != 1) {
			DEBUG("Failed to read uncompressed block");
			r = -1;
			goto err;
		}
	}
	else { /* in_len < chunk->data_len */
		lzo_bytep in;
		lzo_uint new_len;

		chunk->buf_len = chunk->data_len;
		chunk->buf = g_malloc0(chunk->buf_len);

		DEBUG("_fill_uncompressed_buffer: before lzo1x_decompress_safe"
				" (input=%u max_out=%u expected=%u)\n",
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

		/* decompress - use safe decompressor as data might be corrupted
		 * during a file transfer */
		new_len = chunk->buf_len;
		r = lzo1x_decompress_safe(in, in_len, chunk->buf, &new_len, NULL);
		g_free(in);

		if (r != LZO_E_OK || new_len != chunk->data_len) {
			DEBUG("_fill_uncompressed_buffer: compressed data violation"
					" (input=%u max_out=%u expected=%u got=%u)\n",
					(uint)in_len, (uint)chunk->buf_len, (uint)chunk->data_len, (uint)new_len);
			r = -1;
			goto err;
		}

		DEBUG("_fill_uncompressed_buffer: afetr lzo1x_decompress_safe"
				" (input=%u max_out=%u expected=%u got=%u)\n",
				(uint)in_len, (uint)chunk->buf_len, (uint)chunk->data_len, (uint)new_len);
	}

	/* update checksum */
	if (chunk->flags & LZO_FLAG_CHECKSUM) {
		DEBUG("data used for checksum : %u\n", (uint)chunk->data_len);
		lzo_uint32 checksum32 = 0;
		checksum32 = chunk->checksum;
		checksum32 = lzo_adler32(checksum32, chunk->buf, chunk->data_len);
		chunk->checksum = checksum32;
		DEBUG("_fill_decompressed_buffer: checksum updated\n");
	}

	r = 1;
err:
	return r;
}

gboolean
lzo_compressed_chunk_check_integrity(struct compressed_chunk_s *chunk)
{
	/* read and verify checksum */
	gchar *eof_info = NULL;
	guint32 c;	
	gsize len;
	gsize nb_read;
	gboolean status = FALSE;

	len = 2 * sizeof(guint32);
	eof_info = g_malloc0(len);

	nb_read = 0;
	nb_read = fread(eof_info, len, 1, chunk->fd);
	
	if (nb_read != 1) {
		DEBUG("Failed to read file checksum and EOF marker");
		goto end;
	}
	
	lzo_uint32 checksum32 = 0;
	checksum32 = chunk->checksum;
	DEBUG("chunk->checksum : %d\n", checksum32);
	c = *((guint32*)(eof_info + sizeof(guint32)));	

	DEBUG("c (get from file): %d\n", c);

	if(memcmp(eof_info + sizeof(guint32), &checksum32, sizeof(guint32)) != 0)
		goto end;
	
	status = TRUE;

end: 

	if(eof_info){
		g_free(eof_info);	
		eof_info = NULL;
	}
	
	return status;	

}

int 
lzo_compressed_chunk_get_data(struct compressed_chunk_s *chunk, gsize offset, guint8 *buf, gsize buf_len, GError **error)
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

		rf = _fill_decompressed_buffer(chunk, to_skip);	
		if (rf < 0) {
			DEBUG("An error occured while filling buffer\n");
			return -1;
		}
		DEBUG("Entering compressed_chunk_get_data, buffer refilled, max=%u buf_offset=%u data_len=%u\n",
				(uint)buf_len, (uint)chunk->buf_offset, (uint)chunk->data_len);
	}
	else 
		DEBUG("Entering compressed_chunk_get_data, reusing data, max=%u buf_offset=%u data_len=%u\n",
				(uint)buf_len, (uint)chunk->buf_offset, (uint)chunk->data_len);


	if (!chunk->buf || !chunk->data_len) {
		DEBUG("This must never happened\n");	
		return -1;
	}

	max_to_read = chunk->data_len - chunk->buf_offset;
	max_to_read = MIN(max_to_read, buf_len);
	if (max_to_read > 0) {
		memcpy(buf, chunk->buf + chunk->buf_offset, max_to_read);
		chunk->read += max_to_read;
		chunk->buf_offset += max_to_read;
	}

	DEBUG("Exiting compressed_chunk_get_data, max=%u read=%u buf_offset=%u data_len=%u\n",
			(uint)buf_len, (uint)max_to_read, (uint)chunk->buf_offset, (uint)chunk->data_len);
	return max_to_read;
}

int
lzo_compressed_chunk_init(struct compressed_chunk_s *chunk, const gchar *path)
{
	int r = 0;	
	gsize nb_read;
	guint8 headers[HEADER_SIZE];
	GError * error = NULL;
	struct chunk_textinfo_s cti;
	DEBUG("compressed_chunk_init: START\n");

	if(!chunk)
		ERROR("Invalid parameter : %p\n", chunk);

	bzero(headers, sizeof(headers));
	bzero(&cti, sizeof(cti));
	
	/* Get chunk uncompressed size in his attr */
	if (!get_chunk_info_in_attr(path, &error, &cti)){
		DEBUG("Failed to get chunk info in attr : %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}

	chunk->uncompressed_size = g_strdup(cti.size);
	DEBUG("size get in attr = %s", chunk->uncompressed_size);

	/* Read magic header & flags */
	/* place block at top of buffer */
	/*
 	 * Step 1: check magic header, read flags & block size, init checksum
 	*/

	chunk->fd = fopen(path, "r");

	if (!chunk->fd) {
		r = 1;
		goto err;
	}
	
	DEBUG("compressed_chunk_init: compressed chunk open");

	/* compile for read all header info in one call */
	nb_read = 0;
	nb_read = fread(headers, sizeof(headers), 1, chunk->fd);
	if (nb_read != 1) {
		DEBUG("Failed to read headers from chunk file");
		r = 2;
		goto err;
	}


	do { /* extract all headers */
#define GETNEXTPTR(Res,Ptr,Type) do { Res = *((Type *)Ptr); Ptr = Ptr + sizeof(Type); } while (0)
		guint32 bsize32 = 0;

		char *ptr = (char*)headers + sizeof(lzo_magic);
		GETNEXTPTR(chunk->flags, ptr, lzo_uint32);
		GETNEXTPTR(chunk->method, ptr, char);
		GETNEXTPTR(chunk->level, ptr, char);
		GETNEXTPTR(bsize32, ptr, lzo_uint32);
		chunk->block_size = bsize32;
	} while (0);

	if (memcmp(headers, lzo_magic, sizeof(lzo_magic)) != 0) {
		r = 4;
		goto err;
	}
    	if (chunk->method != 1) {
        	r = 5;
        	goto err;
    	}
    	if (chunk->block_size < 1024 || chunk->block_size > 8*1024*1024L){
        	r = 6;
        	goto err;
    	}

	DEBUG("ck.block_size : %"G_GUINT32_FORMAT"\n", chunk->block_size);

	chunk->checksum = lzo_adler32(0, NULL, 0);

	DEBUG("chunk->uncompressed_size = %s\n", chunk->uncompressed_size);

	r=0;

err:
	if(error)
		g_clear_error(&error);
	chunk_textinfo_free_content(&cti);
	
	return r;
}

gboolean
lzo_init_compress_checksum(gulong* checksum)
{
	lzo_uint32 checksum32 = 0;
	checksum32 = lzo_adler32(0, NULL, 0);
	*checksum = checksum32;
	return TRUE;
}

