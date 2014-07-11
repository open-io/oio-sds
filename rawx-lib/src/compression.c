#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "rawx.compress"
#endif

#undef PACKAGE_BUGREPORT
#undef PACKAGE_NAME
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
#undef PACKAGE_VERSION

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <utime.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <metautils/lib/metautils.h>
#include "compression.h"
#include "rawx.h"

#define DECOMPRESSION_MAX_BUFSIZE 512000

static gulong
get_adler_ulong(struct compressed_chunk_s* chunk)
{
	gulong result = 0;
	result = chunk->checksum;
	return result;
}

static guint32
get_adler_uint32(struct compressed_chunk_s* chunk)
{
	guint32 result = 0;
	result = chunk->checksum;
	return result;
}

gboolean
init_compression_ctx(struct compression_ctx_s* comp_ctx, const gchar* algo_name)
{
	gboolean status = FALSE;
	// Define compression algorithm functions in comp_ctx
	if(g_ascii_strcasecmp(algo_name,"LZO") == 0) {
		DEBUG("Algo LZO used");
		comp_ctx->chunk_initiator = lzo_compressed_chunk_init;
		comp_ctx->checksum_initiator = lzo_init_compress_checksum;
		comp_ctx->header_writer = lzo_write_compress_header;
		comp_ctx->data_compressor = lzo_compress_chunk_part;
		comp_ctx->data_uncompressor = lzo_compressed_chunk_get_data;
		comp_ctx->eof_writer = lzo_write_compress_eof;
		comp_ctx->integrity_checker = lzo_compressed_chunk_check_integrity;
		status = TRUE;
		goto end;
	}
	if(g_ascii_strcasecmp(algo_name,"ZLIB") == 0) {
		DEBUG("Algo ZLIB used");
		comp_ctx->chunk_initiator = zlib_compressed_chunk_init;
		comp_ctx->checksum_initiator = zlib_init_compress_checksum;
		comp_ctx->header_writer = zlib_write_compress_header;
		comp_ctx->data_compressor = zlib_compress_chunk_part;
		comp_ctx->data_uncompressor = zlib_compressed_chunk_get_data;
		comp_ctx->eof_writer = zlib_write_compress_eof;
		comp_ctx->integrity_checker = zlib_compressed_chunk_check_integrity;
		status = TRUE;
		goto end;
	}

end:
	return status;
}

static gboolean
check_uncompressed_chunk(const gchar* path, GError** error)
{
	/* Check chunk exists */
	gboolean status = FALSE;
	struct stat *buf = NULL;
	buf = g_malloc0(sizeof(struct stat));	
	if(stat(path, buf) == -1) {
		GSETERROR (error, "stat() failed\n");
		goto end;
	}
	
	GHashTable *compress_opt = NULL;
	compress_opt = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);
	
	/* Check chunk not already compresssed */
	if (get_compression_info_in_attr(path, error, &compress_opt)) {
		DEBUG("Compression info found");
		gchar *compression = NULL;
		compression = g_hash_table_lookup(compress_opt, NS_COMPRESSION_OPTION);
		if (compression && g_ascii_strcasecmp(compression, NS_COMPRESSION_ON) == 0) {
			/* read headers for ensure ? */
			GSETERROR (error, "Chunk already compressed\n");
			goto end;
		}
	} else {
			GSETERROR (error, "Failed to get compression info from extended attributes\n");
			goto end;
	}

	status = TRUE;

end:
	if(buf)
		g_free(buf);
	if (compress_opt)
		g_hash_table_destroy(compress_opt);

	return status;
}

static gboolean
copy_fattr(const gchar *src, gchar* dst, GError **error)
{
	gboolean status = FALSE;
	struct content_textinfo_s *content = NULL;
	struct chunk_textinfo_s *chunk = NULL;

	content = g_malloc0(sizeof(struct content_textinfo_s));
	chunk = g_malloc0(sizeof(struct chunk_textinfo_s));

	if(!get_rawx_info_in_attr(src, error, content, chunk)) {
		GSETERROR(error, "Failed to load extended attributes from source file\n");
		goto err;
	}
	
	/*Check we are working with a gs chunk */
	if(!chunk->id) {
		GSETERROR(error, "No chunk_id found in source file extended attributes, may be this file is not a chunk\n");
		goto err;
	}
		
	if(!set_rawx_info_in_attr(dst, error, content, chunk)) {
		GSETERROR(error, "Failed to set extended attributes to destination file\n");
		goto err;
	}
	
	status = TRUE;

err:
	if(chunk) {
		chunk_textinfo_free_content(chunk);
		g_free(chunk);
	}
	if(content) {
		content_textinfo_free_content(content);
		g_free(content);
	}
	return status;
}

static gboolean
compress_file(FILE *src, FILE *dst, struct compression_ctx_s * comp_ctx, gint64 blocksize, gulong *checksum, guint32 *compressed_size)
{
	gboolean status = FALSE;
	guint8* buf = NULL;
	gsize nb_read;
	gsize nb_write;
	buf = g_malloc0(blocksize);
	gsize bsize = blocksize;
	GByteArray *gba = NULL;
	int src_fd = fileno(src);
	while(1) {
		nb_read = 0;
		nb_read = read(src_fd, buf, bsize);
		if(nb_read != bsize) {
			/* check if we hit eof */
			if(!feof(src) && ferror(src)) {
				goto end;	
			} else {
				if(nb_read > 0) {
					gba = g_byte_array_new();
					/* process data */
					if(0 != comp_ctx->data_compressor(buf, nb_read, gba, checksum))
						goto end;
					
					/* write compressed data */
					nb_write = 0;
					if ((nb_write = fwrite(gba->data, gba->len, 1, dst)) != 1) {
						goto end;
					}

					compressed_size+=gba->len;
					if(gba) {
						g_byte_array_free(gba, TRUE);
						gba = NULL;
					}
				}
				break; 
			}
		} else {
			gba = g_byte_array_new();
			/* process data */
			if(!comp_ctx->data_compressor(buf, blocksize, gba, checksum))
				goto end;

			/* write compressed data */
			nb_write = 0;
			if ((nb_write = fwrite(gba->data, gba->len, 1, dst)) != 1)
				goto end;
			
			compressed_size+=gba->len;
			if(gba)
				g_byte_array_free(gba, TRUE);
		}
		
	}	
	status = TRUE;

end:
	if(buf)	
		g_free(buf);
	if(gba)
		g_byte_array_free(gba, TRUE);
	
	return status;
}

static gboolean
set_compress_attr(gchar* tmp_path, const gchar* algo, gint64 blocksize, GError ** error)
{
	DEBUG("Going to add compression attributes\n");
	gboolean status = FALSE;
	gchar* metadata_compress = NULL;
	gchar bs_str[sizeof(gint64)+1];
	
	bzero(bs_str, sizeof(bs_str));
	g_snprintf(bs_str, sizeof(bs_str), "%"G_GINT64_FORMAT, blocksize);
	
	metadata_compress = g_strconcat(NS_COMPRESSION_OPTION, "=", NS_COMPRESSION_ON, ";",
			NS_COMPRESS_ALGO_OPTION,"=", algo, ";",
			NS_COMPRESS_BLOCKSIZE_OPTION, "=", bs_str, NULL);

	DEBUG("Compression metadata to add : [%s]\n",metadata_compress);

	if (!set_compression_info_in_attr(tmp_path, error, metadata_compress)) {
		goto err;
	}
	
	
	status = TRUE;
err:
	if(metadata_compress)
		g_free(metadata_compress);
	
	return status;
			

}

int
compress_chunk(const gchar* path, const gchar* algo, const gint64 blocksize, gboolean preserve, GError ** error)
{

	GError *local_error = NULL;
	int status = 0;
	gchar *tmp_path = NULL;
	gulong tmp_len;
	guint32 compressed_size = 0;
	struct compression_ctx_s* comp_ctx = NULL;
 	struct stat *stat_buf = NULL;

	guint8* buf = NULL;
	gsize nb_read;
	gsize nb_write;
	GByteArray *gba = NULL;

	gulong checksum = 0;

	FILE *src = NULL;
	FILE *dst = NULL;

	/* Sanity check */	
	if(!path || ! algo) {
		GSETERROR(error, "Invalid parameter %p\n", path);
		return status;
	}
	
	if(!check_uncompressed_chunk(path, &local_error)) {
		if(local_error) {
			GSETERROR(error, "Chunk check failed :\n%s", local_error->message);
			g_clear_error(&local_error);
		} else
			GSETERROR(error, "Chunk check failed : no error\n");
		return status;
	}

	tmp_len = strlen(path) +sizeof(".pending");	
	tmp_path = g_malloc0(tmp_len);
	g_snprintf(tmp_path, tmp_len, "%s.pending", path);

	comp_ctx = g_malloc0(sizeof(struct compression_ctx_s));

	if(!init_compression_ctx(comp_ctx, algo)) {
		GSETERROR(error, "Failed to init compression context\n");
		goto end;
	}

	if(!comp_ctx->checksum_initiator(&checksum)) {
		GSETERROR(error, "Failed to init compression checksum\n");
		goto end;
        }
	
        stat_buf = g_malloc0(sizeof(struct stat));
        if(stat(tmp_path, stat_buf) != -1) {
                GSETERROR (error, "stat() success on pending file, cannot process : chunk busy\n");
                goto end;
        }

	
	do {
	int fd;

	if((fd = open(tmp_path, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1) {
		GSETERROR(error, "Failed to create pending chunk file (%s)\n", strerror(errno));	
		goto end;
	}
	
	metautils_pclose(&fd);
	} while (0);

	if(!copy_fattr(path, tmp_path, &local_error)) {
		if(local_error) {
			GSETERROR(error, "Failed to copy extended attributes to destination file:\n%s",local_error->message);
			g_clear_error(&local_error);
		}
		else
			GSETERROR(error, "Failed to copy extended attributes to destination file\n");
		goto end;
	}
	DEBUG("Extended attributes copied from src to dst\n");
	
	if(!set_compress_attr(tmp_path, algo, blocksize, &local_error)) {
		if(local_error) {
			GSETERROR(error, "Error while adding compression attibutes :\n %s", local_error->message);
			g_clear_error(&local_error);
		}
		goto end;
	}
	
	DEBUG("Compression extended attributes successfully added\n");

	src = fopen(path, "r");
	dst = fopen(tmp_path, "w");

	guint32 bsize32 = blocksize;
	if(comp_ctx->header_writer(dst, bsize32, &checksum, &compressed_size) != 0) {
		GSETERROR(error, "Failed to compress source file\n");
		goto end;
	}
	
	int src_fd = fileno(src);

	gsize bsize = blocksize;
	buf = g_malloc0(blocksize);

	while(1) {
		nb_read = 0;
		nb_read = read(src_fd, buf, bsize);
		if(nb_read != bsize) {
			/* check if we hit eof */
			if(!feof(src) && ferror(src)) {
				GSETERROR(error, "An error occured while reading data from source file\n");
				goto end;	
			} else {
				if(nb_read > 0) {
					gba = g_byte_array_new();
					/* process data */
					if(0 != comp_ctx->data_compressor(buf, nb_read, gba, &checksum)) {
						GSETERROR(error, "Error while compressing data\n");
						goto end;
					}
					/* write compressed data */
					nb_write = 0;
					if ((nb_write = fwrite(gba->data, gba->len, 1, dst)) != 1) {
						GSETERROR(error, "An error occured while writing data in destination file\n");
						goto end;
					}

					compressed_size+=gba->len;
					if(gba) {
						g_byte_array_free(gba, TRUE);
						gba = NULL;
					}
				}
				break; 
			}
		} else {
			gba = g_byte_array_new();
			/* process data */
			if(0 != comp_ctx->data_compressor(buf, nb_read, gba, &checksum)) {
				GSETERROR(error, "Error while compressing data\n");
				goto end;
			}

			/* write compressed data */
			nb_write = 0;
			if ((nb_write = fwrite(gba->data, gba->len, 1, dst)) != 1) {
				GSETERROR(error, "An error occured while writing data in destination file\n");
				goto end;
			}
			
			compressed_size+=gba->len;
			if(gba) {
				g_byte_array_free(gba, TRUE);
				gba = NULL;
			}
		}
		
	}	
	
	DEBUG("Chunk compressed");

	if(comp_ctx->eof_writer(dst, checksum, &compressed_size) != 0) {
		GSETERROR(error, "Failed to write compressed file EOF marker and checksum\n");
		goto end;
	}

	if(!set_chunk_compressed_size_in_attr(tmp_path, error, compressed_size)) {
		GSETERROR(error, "Failed to set compression information in extended attributes\n");
		goto end;
	}

	DEBUG("Compression footers successfully wrote");
	
	status = 1;

end:
	if(src) {
		if(fclose(src) != 0)
			WARN("Failed to fclose source file");
		src = NULL;
	}
	if(dst) {
		if(fclose(dst) != 0)
			WARN("Failed to fclose destination file");
		dst = NULL;
	}
	
	if(status == 1) {
		/* TODO: stat old file, rename, paste stat*/
		if(preserve) {
			/* Need to set old file info in new file */
			TRACE("Renaming and setting good informations to new file...");	
			if(stat_buf)
				g_free(stat_buf);
			stat_buf = g_malloc0(sizeof(struct stat));
			if(stat(path, stat_buf) == -1) {
				GSETERROR (error, "Failed to stat old file, cannot keep old file information, abort\n");
				/* remove tmp file */	
				DEBUG("Removing failed file");
				if(remove(tmp_path) != 0)
					WARN("Failed to remove tmp file [%s]", tmp_path);
				status = 0;
			} else {
				TRACE("Updating Access / Modify / Change informations");
				struct utimbuf* ut = NULL;
				ut = g_malloc0(sizeof(struct utimbuf));
				ut->actime = stat_buf->st_atime;
				ut->modtime = stat_buf->st_mtime;
				chown(tmp_path, stat_buf->st_uid, stat_buf->st_gid);
				if(utime(tmp_path, ut) != 0) {
					GSETERROR(error, "Failed to set correct access time to new file");
					status = 0;
				}
				if(ut)
					g_free(ut);
				if(status == 1) {
					if(rename(tmp_path, path) != 0) {
						GSETERROR(error, "Failed to rename tmp file");
						status = 0;
					}
				} else {
					/* remove tmp file */	
					DEBUG("Removing failed file");
					if(remove(tmp_path) != 0)
						WARN("Failed to remove tmp file [%s]", tmp_path);
				}
			}
		} else {
			TRACE("Renaming pending file...");
			if(rename(tmp_path, path) != 0) {
				GSETERROR(error, "Failed to rename tmp file");
				status = 0;
			}
			TRACE("Renaming done");
		}
	} else {
		/* remove tmp file */	
		DEBUG("Removing failed file");
		if(remove(tmp_path) != 0)
			WARN("Failed to remove tmp file [%s]", tmp_path);
	}

	if(stat_buf)	
		g_free(stat_buf);

	if(buf)	
		g_free(buf);
	if(gba)
		g_byte_array_free(gba, TRUE);

	if(tmp_path)
		g_free(tmp_path);
	
	return status;

}

int
uncompress_chunk2(const gchar* path, gboolean preserve, gboolean keep_pending,
		GError ** error)
{
	GError *local_error = NULL;
	int status = 0;
	TRACE("Uncompressing [%s]", path);
	gchar *tmp_path = NULL;
	gulong tmp_len;
	gint64 total_read;
	guint8* data = NULL;
	gint64 bufsize, nb_read;
	gint64 current_read;
	struct stat *buf = NULL;
	struct compressed_chunk_s *cp_chunk = NULL;
	struct compression_ctx_s *comp_ctx = NULL;
	

	FILE *dst = NULL;

	/* Check chunk exists */
	buf = g_malloc0(sizeof(struct stat));	

	DEBUG("Checking chunk exists");

	if(stat(path, buf) == -1) {
		GSETERROR (error, "stat() failed, chunk not found\n");
		goto end;
	}
	DEBUG("File [%s] found", path);
	
	GHashTable *compress_opt = NULL;
	compress_opt = g_hash_table_new_full( g_str_hash, g_str_equal, g_free, g_free);

	if(!get_compression_info_in_attr(path, error, &compress_opt)) {
		GSETERROR(error, "Failed to get compression info in attr, chunk may be not compressed");
		goto end;
	}
	
	gchar * compression = NULL;
	compression = (gchar*) g_hash_table_lookup(compress_opt, NS_COMPRESSION_OPTION);
	
	if (compression != NULL && g_ascii_strncasecmp(compression, NS_COMPRESSION_ON, strlen(compression)) != 0) {
		GSETERROR(error, "Chunk not compressed, cannot nothing to do");
		goto end;
	}

	/* init compression method according to algo choice */
	comp_ctx = g_malloc0(sizeof(struct compression_ctx_s));
	init_compression_ctx(comp_ctx, g_hash_table_lookup(compress_opt, NS_COMPRESS_ALGO_OPTION));
	cp_chunk = g_malloc0(sizeof(struct compressed_chunk_s));

	if (comp_ctx->chunk_initiator(cp_chunk, path) != 0) {
		GSETERROR(error, "Failed to init compressed chunk context");
		goto end;
	}
	

	DEBUG("Chunk check done");

	tmp_len = strlen(path) +sizeof(".pending");	
	tmp_path = g_malloc0(tmp_len);
	g_snprintf(tmp_path, tmp_len, "%s.pending", path);

	DEBUG("Checking chunk not busy");

	if(stat(tmp_path, buf) != -1) {
		DEBUG("Stats failed");
		GSETERROR (error, "stat() success on pending file, cannot process : busy chunk\n");
		goto end;
	}
	
	do {
	int fd;

	if((fd = open(tmp_path, O_WRONLY|O_CREAT|O_EXCL, 0644)) == -1) {
		GSETERROR(error, "Failed to create pending chunk file (%s)\n", strerror(errno));	
		goto end;
	}
	
	metautils_pclose(&fd);
	} while (0);

	if(!copy_fattr(path, tmp_path, error)) {
		GSETERROR(error, "Failed to copy extended attributes to destination file\n");
		goto end;
	}

	TRACE("xattr copied from src to dst");

	dst = fopen(tmp_path, "w");

	TRACE("Destination file opened");

	gint64 chunk_size;
	chunk_size = g_ascii_strtoll(cp_chunk->uncompressed_size, NULL, 10);

	total_read = 0;	

	DEBUG("Starting, total_read = %"G_GINT64_FORMAT", chunk_size = %"G_GINT64_FORMAT, total_read, chunk_size);

	while(total_read < chunk_size) {
		bufsize = MIN(DECOMPRESSION_MAX_BUFSIZE, (chunk_size - total_read));
		data = g_malloc0(bufsize);
		DEBUG("New buffer allocated sized %"G_GINT64_FORMAT" bytes", bufsize);
		nb_read = 0;
		current_read = 0;
		while(nb_read < bufsize) {
			current_read = comp_ctx->data_uncompressor(cp_chunk, 0, data + nb_read, bufsize - nb_read, &local_error);
			DEBUG("Currently read %"G_GINT64_FORMAT" bytes", current_read);
			if(current_read < 0) {
				if(local_error) {
					GSETERROR(error, "An error occured while decompressing chunk : %s", local_error->message);	
					g_clear_error(&local_error);
				} else
					GSETERROR(error, "An error occured while decompressing chunk\n"); 
				goto end;
			} else if (current_read == 0) {
				/* Premature end of file, will still write to pending */
				WARN("Read 0 bytes, original chunk may have been truncated");
				break;
			}
			nb_read += current_read;
		}
		TRACE("buffer filled");
		errno = 0;
		/* write buf to dst file */
		if(nb_read > 0 && fwrite(data, nb_read, 1, dst) != 1) {
			GSETERROR(error, "An error occured while writing data in destination file: %s",
					strerror(errno));
			goto end;
		}
		if (data) {
			g_free(data);
			data = NULL;
		}
		if (nb_read > 0)
			total_read += nb_read;
		else
			break;
	}

	if(!comp_ctx->integrity_checker(cp_chunk)) {
		GSETERROR(error, "Seems there is an error in decompression, invalid checksum\n");
		goto end;
	}

	status = 1;

end:
	if(dst) {
		if(fclose(dst) != 0)
			WARN("Failed to fclose destination file");
		dst = NULL;
	}
	
	if(status == 1) {
		if(preserve) {
			/* Need to set old file info in new file */
			TRACE("Updating Access / Modify / Change informations");
			struct utimbuf* ut = NULL;
			ut = g_malloc0(sizeof(struct utimbuf));
			ut->actime = buf->st_atime;
			ut->modtime = buf->st_mtime;
			chown(tmp_path, buf->st_uid, buf->st_gid);
			if(utime(tmp_path, ut) != 0) {
				GSETERROR(error, "Failed to set correct access time to new file");
				status = 0;
			}
			if(ut)
				g_free(ut);
			if(status == 1) {
				if(rename(tmp_path, path) != 0) {
					GSETERROR(error, "Failed to rename tmp file");
					status = 0;
				}
			} else if (keep_pending) {
				INFO("Temporary file kept: %s", tmp_path);
			} else {
				/* remove tmp file */
				DEBUG("Removing failed file");
				if(remove(tmp_path) != 0)
					WARN("Failed to remove tmp file [%s]", tmp_path);
			}
		} else {
			DEBUG("Renaming pending file\n");
			if(rename(tmp_path, path) != 0) {
				GSETERROR(error, "Failed to rename tmp file");
				status = 0;
			} 
		}
	} else if (keep_pending) {
		INFO("Temporary file kept: %s", tmp_path);
	} else {
		/* remove tmp file */
		DEBUG("Removing pending file\n");
		if(remove(tmp_path) != 0)
			WARN("Failed to remove tmp file [%s]", tmp_path);
	}

	if(compress_opt)
		g_hash_table_destroy(compress_opt);

	if(buf)
		g_free(buf);

	if(data)
		g_free(data);

	if(tmp_path)
		g_free(tmp_path);
	
	return status;
}

int
uncompress_chunk(const gchar* path, gboolean preserve, GError ** error)
{
	return uncompress_chunk2(path, preserve, FALSE, error);
}
