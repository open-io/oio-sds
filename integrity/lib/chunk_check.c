#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "integrity.lib.chunk_check"
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include <metautils/lib/metautils.h>
#include <meta1v2/meta1_remote.h>
#include <meta2/remote/meta2_remote.h>
#include <meta2/remote/meta2_services_remote.h>
#include <meta2v2/meta2v2_remote.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <client/c/lib/gs_internals.h>

#include "check.h"
#include "content_check.h"
#include "chunk_check.h"
#include "broken_event.h"

#define META1_TIMEOUT 6000
#define META2_TIMEOUT 6000

/**
 * Compute the MD5 hash of a chunk file
 *
 * @param chunk_path the full path to the chunk file
 * @param chunk_hash the chunk_hash_t to fill with the computed hash
 * @param error
 *
 * @return TRUE or FALSE if an error occured (error is set)
 */
static gboolean
_compute_chunk_md5_hash(const gchar * chunk_path, chunk_hash_t chunk_hash, GError ** error)
{
	int fd;
	size_t len;
	ssize_t size_read;
	guint8 buffer[4096];
	GChecksum *md5_sum = NULL;

	memset(buffer, 0, sizeof(buffer));

	fd = open(chunk_path, O_RDONLY);
	if (fd == -1) {
		GSETERROR(error, "Failed to open chunk file [%s] for reading : %s", chunk_path, strerror(errno));
		return FALSE;
	}

	md5_sum = g_checksum_new(G_CHECKSUM_MD5);
	if (md5_sum == NULL) {
		GSETERROR(error, "GChecksum allocation failure");
		metautils_pclose(&fd);
		return FALSE;
	}

	while (0 < (size_read = read(fd, buffer, sizeof(buffer)))) {
		g_checksum_update(md5_sum, buffer, size_read);
		memset(buffer, 0, sizeof(buffer));
	}

	metautils_pclose(&fd);
	len = sizeof(chunk_hash_t);
	g_checksum_get_digest(md5_sum, chunk_hash, &len);
	g_checksum_free(md5_sum);

	if (size_read == -1) {
		GSETERROR(error, "Failed while reading chunk file [%s] : %s", chunk_path, strerror(errno));
		memset(chunk_hash, 0, sizeof(chunk_hash_t));
		return FALSE;
	}

	if (len != sizeof(chunk_hash_t)) {
		GSETERROR(error, "Chunk file content computed hash hash wrong size : %d instead of %d", len,
		    sizeof(chunk_hash_t));
		memset(chunk_hash, 0, sizeof(chunk_hash_t));
		return FALSE;
	}

	return TRUE;
}


gboolean
check_chunk_integrity(const char *chunk_path, const struct chunk_textinfo_s * text_chunk, GSList ** mismatch,
    GError ** error)
{
	GError *local_error = NULL;
	chunk_hash_t chunk_file_hash, chunk_attr_hash;
	gint64 chunk_attr_size;

	CHECK_ARG_POINTER(chunk_path, error);
	CHECK_ARG_POINTER(text_chunk, error);
	CHECK_ARG_VALID_FILE(chunk_path, error);


#define ADD_BRK_EL_TXT(L, P, R, V) \
do {\
	struct broken_element_s* brk_el; \
	brk_el = broken_element_alloc2(text_chunk->container_id, text_chunk->path, text_chunk->id, L, P, R, V); \
	if (brk_el != NULL) \
		*mismatch = g_slist_prepend(*mismatch, brk_el); \
	else { \
		GSETERROR(error, "Memory allocation failure"); \
		goto error; \
	} \
} while(0)

	/* See if we have a chunk_hash in attr */
	if (text_chunk->hash != NULL) {

		/* Compute chunk hash from file */
		if (!_compute_chunk_md5_hash(chunk_path, chunk_file_hash, error)) {
			GSETERROR(error, "Failed to compute MD5 hash of chunk file [%s]", chunk_path);
			goto error;
		}

		/* Convert attr chunk hash to bin */
		if (!hex2bin(text_chunk->hash, chunk_attr_hash, sizeof(chunk_hash_t), &local_error)) {
			WARN("Failed to convert chunk hash from hex [%s] to bin format : %s", text_chunk->hash,
			    local_error->message);
			g_clear_error(&local_error);
		}
		else if (0 != memcmp(chunk_file_hash, chunk_attr_hash, sizeof(chunk_hash_t)))
			ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_HASH, R_MISMATCH, g_memdup(chunk_attr_hash,
				sizeof(chunk_hash_t)));
	}

	/* See if we have a chunk size in attr */
	if (text_chunk->size != NULL) {
		struct stat file_stat;

		chunk_attr_size = g_ascii_strtoll(text_chunk->size, NULL, 10);

		/* Read chunk file size */
		memset(&file_stat, 0, sizeof(struct stat));
		if (-1 == stat(chunk_path, &file_stat)) {
			GSETERROR(error, "Failed to stat chunk file [%s] : %s", chunk_path, strerror(errno));
			goto error;
		}

		/* Compare chunk size */
		if (file_stat.st_size != chunk_attr_size){
			NOTICE("Chunk size mismatch, starting new broken event");
			ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&chunk_attr_size,
				sizeof(chunk_attr_size)));
		}
	}
	else {
		NOTICE("text_chunk size =NULL!...\n");
		ADD_BRK_EL_TXT(L_CHUNK, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&chunk_attr_size, sizeof(chunk_attr_size)));
	
	}
	return TRUE;

      error:
	if (*mismatch != NULL) {
		g_slist_foreach(*mismatch, broken_element_gfree, NULL);
		g_slist_free(*mismatch);
		*mismatch = NULL;
	}

	return FALSE;
}

gint _chunk_position_comparator(gconstpointer _chunk, gconstpointer _str_position) {
	guint32 position = g_ascii_strtoull((const gchar*)_str_position, NULL, 10);
	const struct meta2_raw_chunk_s *chunk = _chunk;
	return chunk->position - position;
}

gint _chunk_hash_comparator(gconstpointer _chunk, gconstpointer _str_hash) {
	const gchar *str_hash = _str_hash;
	const struct meta2_raw_chunk_s *chunk = _chunk;
	gchar hash_from_chunk[STRLEN_CHUNKHASH];
	buffer2str(chunk->hash, sizeof(chunk->hash), hash_from_chunk, STRLEN_CHUNKHASH);
	return g_strcmp0(hash_from_chunk, str_hash);
}

static struct meta2_raw_chunk_s *
_get_chunk(GSList *raw_chunks, const gchar *position)
{
	GSList *found_element = g_slist_find_custom(raw_chunks,
			position, _chunk_position_comparator);
	return found_element ? found_element->data : NULL;
}

static gboolean
check_chunk_referencing_full(const struct content_textinfo_s * content_from_chunk,
    const struct chunk_textinfo_s * chunk_from_chunk, const struct meta2_raw_content_s * content_from_meta2,
    struct meta2_raw_chunk_s *raw_chunk, GSList ** broken, GError ** error)
{
	struct meta2_raw_chunk_s *chunk_from_meta2 = NULL;
	GError *local_error = NULL;

	CHECK_ARG_POINTER(content_from_chunk, error);
	CHECK_ARG_POINTER(chunk_from_chunk, error);
	CHECK_ARG_POINTER(content_from_meta2, error);
	CHECK_ARG_POINTER(content_from_meta2->raw_chunks, error);

#define ADD_BRK_EL_BIN(L, P, R, V) \
do {\
	struct broken_element_s* brk_el; \
	brk_el = broken_element_alloc(content_from_meta2->container_id, content_from_meta2->path, chunk_from_meta2->id.id, L, P, R, V); \
	if (brk_el != NULL) \
		*broken = g_slist_prepend(*broken, brk_el); \
	else { \
		GSETERROR(error, "Memory allocation failure"); \
		goto error; \
	} \
} while(0)

	if (g_slist_length(content_from_meta2->raw_chunks) == 0) {
		GSETERROR(error, "List of raw_chunk in content from META2 is emty");
		return FALSE;
	}

	if (raw_chunk) {
		chunk_from_meta2 = raw_chunk;
	} else {
		chunk_from_meta2 = _get_chunk(content_from_meta2->raw_chunks,
				chunk_from_chunk->position);
		if (chunk_from_meta2 ==NULL)
			return FALSE;
	}


	gboolean check_chunk_hash_same  = FALSE;
	gboolean check_chunk_id_notsame = FALSE;
	gboolean is_referenced = TRUE;


	/* Check chunk hash */
	if (chunk_from_chunk->hash == NULL && !data_is_zeroed(chunk_from_meta2->hash, sizeof(chunk_hash_t))) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_HASH, R_MISSING, g_memdup(chunk_from_meta2->hash,
			sizeof(chunk_hash_t)));
	}
	else if (data_is_zeroed(chunk_from_meta2->hash, sizeof(chunk_hash_t)) && chunk_from_chunk->hash != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CHUNK_HASH, R_MISSING, NULL);
	}
	else {
		chunk_hash_t hash;

		if (!hex2bin(chunk_from_chunk->hash, hash, sizeof(chunk_hash_t), &local_error)) {
			WARN("Failed to convert chunk_hash from hex [%s] to bin : %s", chunk_from_chunk->hash,
			    local_error->message);
			g_clear_error(&local_error);
			ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_HASH, R_FORMAT, g_memdup(chunk_from_meta2->hash,
				sizeof(chunk_hash_t)));
		}
		else if (0 != memcmp(chunk_from_meta2->hash, hash, sizeof(chunk_hash_t)))
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_HASH, R_MISMATCH, g_memdup(chunk_from_meta2->hash,
				sizeof(chunk_hash_t)));
		else check_chunk_hash_same = TRUE;
		
	}

	/* Check chunk id */
	if (chunk_from_chunk->id == NULL && !data_is_zeroed(chunk_from_meta2->id.id, sizeof(hash_sha256_t))) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_ID, R_MISSING, g_memdup(chunk_from_meta2->id.id,
			sizeof(hash_sha256_t)));
	}
	else if (data_is_zeroed(chunk_from_meta2->id.id, sizeof(hash_sha256_t)) && chunk_from_chunk->id != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CHUNK_ID, R_MISSING, NULL);
	}
	else {
		hash_sha256_t id;

		if (!hex2bin(chunk_from_chunk->id, id, sizeof(hash_sha256_t), &local_error)) {
			WARN("Failed to convert chunk_id from hex [%s] to bin : %s", chunk_from_chunk->id,
			    local_error->message);
			g_clear_error(&local_error);
			ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_ID, R_FORMAT, g_memdup(chunk_from_meta2->id.id,
				sizeof(hash_sha256_t)));
		}
		else if (0 != memcmp(chunk_from_meta2->id.id, id, sizeof(hash_sha256_t))) {			
			check_chunk_id_notsame = TRUE;
			// ADD_BRK_EL_BIN(L_ALL, P_CHUNK_ID, R_MISMATCH, g_memdup(chunk_from_meta2->id.id,
            //         sizeof(hash_sha256_t)));
			
		}
	}

	/* Check chunk size */
	if (chunk_from_chunk->size == NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_SIZE, R_MISSING, g_memdup(&(chunk_from_meta2->size),
			sizeof(chunk_from_meta2->size)));
	}
	else {
		gint64 size = g_ascii_strtoll(chunk_from_chunk->size, NULL, 10);

		if (size != chunk_from_meta2->size)
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_SIZE, R_MISMATCH, g_memdup(&(chunk_from_meta2->size),
				sizeof(chunk_from_meta2->size)));
	}

	/* Check chunk position */
	if (chunk_from_chunk->position == NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CHUNK_POS, R_MISSING, g_memdup(&(chunk_from_meta2->position),
			sizeof(chunk_from_meta2->position)));
	}
	else {
		guint32 position = atoi(chunk_from_chunk->position);

		if (position != chunk_from_meta2->position)
			ADD_BRK_EL_BIN(L_ALL, P_CHUNK_POS, R_MISMATCH, g_memdup(&(chunk_from_meta2->position),
				sizeof(chunk_from_meta2->position)));
	}

	/* Check content name */
	if (content_from_chunk->path == NULL
	    && !data_is_zeroed(content_from_meta2->path, sizeof(content_from_meta2->path))) {
		NOTICE("chunk_check: path null..\n");
		ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_NAME, R_MISSING, g_strdup(content_from_meta2->path));
	}
	else if (data_is_zeroed(content_from_meta2->path, sizeof(content_from_meta2->path))
	    && content_from_chunk->path != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CONTENT_NAME, R_MISSING, g_strdup(content_from_chunk->path));
	}
	else if (strncmp(content_from_chunk->path, content_from_meta2->path, LIMIT_LENGTH_CONTENTPATH)) {
		ADD_BRK_EL_BIN(L_ALL, P_CONTENT_NAME, R_MISMATCH, g_strdup(content_from_meta2->path));
	}

	/* Check content system metadata */
	if (content_from_chunk->system_metadata == NULL && content_from_meta2->system_metadata != NULL) {
		ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_SYSMETADATA, R_MISSING,
		    g_memdup(content_from_meta2->system_metadata->data, content_from_meta2->system_metadata->len));
	}
	else if ((content_from_meta2->system_metadata == NULL || content_from_meta2->system_metadata->len == 0)
	    && content_from_chunk->system_metadata != NULL) {
		ADD_BRK_EL_BIN(L_META2, P_CONTENT_SYSMETADATA, R_MISSING, g_strdup(content_from_chunk->system_metadata));
	}
	else {
		gchar metadata[content_from_meta2->system_metadata->len + 1];

		memset(metadata, '\0', sizeof(metadata));
		memcpy(metadata, content_from_meta2->system_metadata->data, sizeof(metadata) - 1);

		if (!metadata_equal(content_from_chunk->system_metadata, metadata, NULL))
			ADD_BRK_EL_BIN(L_ALL, P_CONTENT_SYSMETADATA, R_MISMATCH,
			    g_memdup(content_from_meta2->system_metadata->data,
				content_from_meta2->system_metadata->len));
	}

	/* Check properties on chunk with position 0 */
	if (chunk_from_chunk->position != NULL && 0 == atoi(chunk_from_chunk->position)) {
		/* Check content nb chunk */
		if (content_from_chunk->chunk_nb == NULL) {
			ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_CHUNK_NB, R_MISSING,
			    g_memdup(&(content_from_meta2->nb_chunks), sizeof(content_from_meta2->nb_chunks)));
		}
		else {
			guint32 nb_chunk = atoi(content_from_chunk->chunk_nb);

			if (nb_chunk != content_from_meta2->nb_chunks)
				ADD_BRK_EL_BIN(L_ALL, P_CONTENT_CHUNK_NB, R_MISMATCH,
				    g_memdup(&(content_from_meta2->nb_chunks), sizeof(content_from_meta2->nb_chunks)));
		}

		/* Check content size */
		if (content_from_chunk->size == NULL) {
			ADD_BRK_EL_BIN(L_CHUNK, P_CONTENT_SIZE, R_MISSING, g_memdup(&(content_from_meta2->size),
				sizeof(content_from_meta2->size)));
		}
		else {
			gint64 size = g_ascii_strtoll(content_from_chunk->size, NULL, 10);

			if (size != content_from_meta2->size)
				ADD_BRK_EL_BIN(L_ALL, P_CONTENT_SIZE, R_MISMATCH, g_memdup(&(content_from_meta2->size),
					sizeof(content_from_meta2->size)));
		}
	}

	//--------------------
	// for differenciation between dupplicated chunk / other content chunk / broken chunk
	if ((*broken != NULL)&&(g_slist_length(*broken)> 0)) {
		// error --> add the chunk_id error if there is
		if (check_chunk_id_notsame == TRUE)
			 ADD_BRK_EL_BIN(L_ALL, P_CHUNK_ID, R_MISMATCH, g_memdup(chunk_from_meta2->id.id,
                     sizeof(hash_sha256_t)));

	} else if (check_chunk_hash_same == FALSE) {
		// no error / same id / NOT smae hash --> chunk not for this content
        if (check_chunk_id_notsame == TRUE)
             ADD_BRK_EL_BIN(L_ALL, P_CHUNK_ID, R_MISMATCH, g_memdup(chunk_from_meta2->id.id,
                      sizeof(hash_sha256_t)));		
				
	} else if (check_chunk_id_notsame == TRUE) {
		// no error / not same id / same hash  --> chunk not referenced / no other error
		is_referenced = FALSE;
	}

	return is_referenced;

error:
	if (*broken != NULL) {
		g_slist_foreach(*broken, broken_element_gfree, NULL);
		g_slist_free(*broken);
		*broken = NULL;
	}

	return FALSE;
}

gboolean
check_chunk_referencing(const struct content_textinfo_s * content_from_chunk,
    const struct chunk_textinfo_s * chunk_from_chunk, const struct meta2_raw_content_s * content_from_meta2,
    GSList ** broken, GError ** error)
{
	return check_chunk_referencing_full(content_from_chunk, chunk_from_chunk,
			content_from_meta2, NULL, broken, error);
}

gboolean
check_chunk_info(struct chunk_textinfo_s *chunk, GError **p_error)
{
	CHECK_INFO(chunk->path,		p_error, "Missing mandatory content path");
	CHECK_INFO(chunk->id,		p_error, "Missing mandatory chunk ID");
	CHECK_INFO(chunk->size,		p_error, "Missing mandatory chunk size");
	CHECK_INFO(chunk->hash,		p_error, "Missing mandatory chunk hash");
	CHECK_INFO(chunk->position,	p_error, "Missing mandatory chunk position");
	return TRUE;
}

static gboolean
_create_container(struct meta2_ctx_s *ctx, container_id_t *p_cid, GError **p_err)
{
	addr_info_t *p_m1_addr = NULL;
	gboolean ret = FALSE;

	p_m1_addr = gs_resolve_meta1v2 (ctx->hc /*container->info.gs*/,
			*p_cid,  ctx->loc->container_name, 0, NULL, p_err);
	if (!p_m1_addr) {
		GSETERROR(p_err, "META1 resolution error for [%s]", ctx->loc->container_name);
		goto clean_up;
	}

	gboolean rc = meta1_remote_create_container_v2(p_m1_addr, META1_TIMEOUT,
			p_err, ctx->loc->container_name, ctx->ns, *p_cid, 0, 0, NULL);
	if (!rc && p_err && *p_err)
		goto clean_up;

	ret = TRUE;

clean_up:
	if (p_m1_addr)
		addr_info_clean(p_m1_addr);

	return ret;
}


static gint64
_extract_date_from_sysmd(const guint8 *mdsys, gsize mdsys_len)
{
	GError *err = NULL;
	GHashTable *unpacked = metadata_unpack_buffer(mdsys, mdsys_len, &err);
	GHashTableIter iter;
	gpointer k, v;
	gint64 md_date = -1;

	if (!err) {
		g_hash_table_iter_init(&iter, unpacked);
		while (g_hash_table_iter_next(&iter, &k, &v)) {
			if (g_str_equal(k, "creation-date")) {
				md_date = g_ascii_strtoll(v, NULL, 10);
				break;
			}
		}
	} else {
		GRID_DEBUG("Cannot extract date from system metadata: %s",
				err->message ? err->message : "<no details>");
		g_error_free(err);
	}

	g_hash_table_destroy(unpacked);
	return md_date;
}

static void
_replace_sysmd_date(struct meta2_ctx_s *ctx, gint64 newdate)
{
	GError *err = NULL;
	struct meta2_raw_content_s *rc = ctx->content;
	GHashTable *unpacked = metadata_unpack_gba(rc->system_metadata, &err);
	if (!err) {
		metadata_add_printf(unpacked, "creation-date", "%"G_GINT64_FORMAT, newdate);
	} else {
		GRID_DEBUG("Cannot replace system metadata creation-date: %s",
				err->message ? err->message : "<no details>");
		g_clear_error(&err);
	}
	g_byte_array_free(rc->system_metadata, TRUE);
	rc->system_metadata = metadata_pack(unpacked, &err);
	if (err) {
		GRID_DEBUG("Cannot repack system metadata: %s",
				err->message ? err->message : "<no details>");
		g_clear_error(&err);
	}

	gchar *sysmd = g_strndup((gchar*)rc->system_metadata->data,
			rc->system_metadata->len);
	if (!meta2_remote_modify_metadatasys(ctx->m2_cnx, rc->container_id,
			rc->path, sysmd, &err)) {
		GRID_DEBUG("Error modifying system metadata for content [%s] (%s)",
				rc->path, err && err->message ? err->message : "no details");
		g_clear_error(&err);
	}
	g_free(sysmd);
	g_hash_table_destroy(unpacked);
}

static gboolean
_ensure_container_created_in_m2(struct meta2_ctx_s *ctx, container_id_t *p_cid,
		gchar *stgpol, check_result_t *cres)
{
	addr_info_t m2;
	gboolean ret = FALSE;
	GError *local_error = NULL;

	GRID_DEBUG("m2addr_str=%s", ctx->loc->m2_url[0]);

	// suppose container does not exist: create it
	grid_string_to_addrinfo(ctx->loc->m2_url[0], NULL, &m2);
	ret = meta2_remote_container_create_v3 (&m2, META2_TIMEOUT,
			ctx->ns, ctx->loc->container_name,
			*p_cid, stgpol, &local_error);
	// if return "already created": it's not an error!
	if (!ret && local_error)  {
		if (local_error->code == CODE_CONTAINER_EXISTS) {
			g_clear_error(&local_error);
			GRID_DEBUG("Container [%s/%s] already exist on meta2 [%s]",
					ctx->ns, ctx->loc->container_name,
					ctx->loc->m2_url[0]);
			ret = TRUE;
		}
	}

	if (!local_error) {
		check_result_append_msg(cres, "Created container [%s]",
				ctx->loc->container_hexid);
		ret = TRUE;
	} else {
		GRID_DEBUG("Failed to create container [%s/%s] (%s).",
				ctx->ns, ctx->loc->container_name, local_error->message);
		g_error_free(local_error);
	}

	return ret;
}

static gboolean
_ensure_container_created(struct meta2_ctx_s *ctx, check_info_t *check_info,
		check_result_t *cres, GError **p_err)
{
	gboolean ret = FALSE;
	GError *local_error = NULL;
	struct content_textinfo_s *ct_info = check_info->ct_info;
	gchar *hexid = ct_info->container_id;
	container_id_t cid;
	gint64 date_in_attr = 0;

	GRID_DEBUG("Check/Create container with...storage_policy=%s, version=%s, container_id=%s, container_name=%s/%s,",
			ct_info->storage_policy, ct_info->version,
			hexid, ctx->ns, ctx->loc->container_name);

	if (!container_id_hex2bin(hexid, strlen(hexid), &cid, &local_error))
		goto clean_up;

	if (ctx->loc->m2_url == NULL) {
		if (!_create_container(ctx, &cid, p_err))
			goto clean_up;

		// replace date of new container by the one from extended attributes
		if (ct_info->system_metadata)
			date_in_attr = _extract_date_from_sysmd(
					(guint8*)ct_info->system_metadata,
					strlen(ct_info->system_metadata));
		_replace_sysmd_date(ctx, date_in_attr);

		// log message
		check_result_append_msg(cres, "Created container [%s] "
				"with date [%"G_GINT64_FORMAT"]",
				ct_info->container_id, date_in_attr);
	} else {
		if (!_ensure_container_created_in_m2(ctx, &cid,
				ct_info->storage_policy, cres))
			goto clean_up;
	}

	ret = TRUE;

clean_up:
	return ret;
}

gchar *
compute_file_md5(const gchar *filepath)
{
	FILE *fp;
	guint8 buf[8096];
	gint read_bytes;
	gchar *strmd5 = NULL;
	GChecksum *checksum = NULL;

	errno = 0;
	if (NULL != (fp = fopen(filepath, "rb"))) {
		checksum = g_checksum_new(G_CHECKSUM_MD5);
		while ((read_bytes = fread(buf, 1, sizeof(buf), fp)) > 0)
			g_checksum_update(checksum, buf, read_bytes);
		strmd5 = g_strdup(g_checksum_get_string(checksum));
		fclose(fp);
		g_checksum_free(checksum);
	} else {
		GRID_DEBUG("Could not open file [%s] (%s)",
				filepath, strerror(errno));
	}
	return strmd5;
}

static gboolean
_check_chunk_md5(check_info_t *check_info)
{
	gboolean ret;
	gchar *filemd5 = compute_file_md5(check_info->source_path);
	ret = (0 == g_ascii_strncasecmp(filemd5, check_info->ck_info->hash, STRLEN_CHUNKHASH));
	g_free(filemd5);
	return ret;
}

static gboolean
_fill_raw_content_with_info(struct meta2_raw_content_s *rc,
		check_info_t *check_info, GError **p_err)
{
	struct content_textinfo_s *ci = check_info->ct_info;

	if (!rc)
		return FALSE;

	// CONTAINER ID
	if (ci->container_id)
		hex2bin(ci->container_id, rc->container_id,
				sizeof(rc->container_id), p_err);

	// NB CHUNKS
	if (ci->chunk_nb)
		rc->nb_chunks = g_ascii_strtoull(ci->chunk_nb, NULL, 10);

	// CONTENT PATH
	if (ci->path)
		g_strlcpy(rc->path, ci->path, sizeof(rc->path));

	// SIZE
	if (ci->size)
		rc->size = g_ascii_strtoll(ci->size, NULL, 10);

	// STORAGE POLICY
	rc->storage_policy = g_strdup(ci->storage_policy);

	// SYSTEM METADATA
	if (ci->system_metadata) {
		if (rc->metadata)
			g_byte_array_free(rc->metadata, TRUE);
		rc->system_metadata = g_byte_array_append(g_byte_array_new(),
				(guint8*)ci->system_metadata, strlen(ci->system_metadata));
	}

	// VERSION
	if (ci->version)
		rc->version = g_ascii_strtoll(ci->version, NULL, 10);

	return TRUE;
}
static gboolean
_fill_raw_chunk_with_info(struct meta2_raw_chunk_s *rc,
		check_info_t *check_info, GError **p_err)
{
	struct chunk_textinfo_s *ci = check_info->ck_info;

	if (!rc)
		return FALSE;

	// HASH
	if (!hex2bin(ci->hash, rc->hash, sizeof(rc->hash), p_err))
		return FALSE;

	// ID
	if (!hex2bin(ci->id, rc->id.id, sizeof(rc->id.id), p_err))
		return FALSE;
	memset(rc->id.vol, 0, sizeof(rc->id.vol));
	memcpy(rc->id.vol, check_info->rawx_vol, sizeof(rc->id.vol));
	grid_string_to_addrinfo(check_info->rawx_str_addr, NULL, &(rc->id.addr));

	// SIZE
	if (ci->size)
		rc->size = g_ascii_strtoll(ci->size, NULL, 10);

	// METADATA
	if (ci->metadata) {
		if (rc->metadata)
			g_byte_array_free(rc->metadata, TRUE);
		rc->metadata = g_byte_array_append(g_byte_array_new(),
				(const guint8*) ci->metadata, strlen(ci->metadata));
	}

	// POSITION
	if (ci->position)
		rc->position = g_ascii_strtoull(ci->position, NULL, 10);

	return TRUE;
}

static gboolean
_add_missing_chunk(struct meta2_ctx_s *ctx, check_info_t *check_info,
		check_result_t *cres, GError **p_err)
{
	const gboolean is_dryrun = check_option_get_bool(check_info->options,
			CHECK_OPTION_DRYRUN);
	gboolean ret = FALSE;

	if (!ctx->content) {
		GRID_DEBUG("Cannot add chunk [%s]: no content.", check_info->ck_info->id);
		return FALSE;
	}

	meta2_raw_chunk_t *newchunk = g_malloc0(sizeof(meta2_raw_chunk_t));
	if (!_fill_raw_chunk_with_info(newchunk, check_info, p_err)) {
		GRID_DEBUG("Error filling new chunk for content [%s]",
				check_info->ct_info->path);
		g_free(newchunk);
		goto clean_up;
	}
	ctx->content->raw_chunks = g_slist_prepend(ctx->content->raw_chunks, newchunk);

	if (is_dryrun) {
		check_result_append_msg(cres, "dryrun prevented chunk update in [%s/%s]",
				check_info->ct_info->container_id,
				check_info->ct_info->path);
	} else {
		if (!meta2raw_remote_update_content(ctx->m2_cnx, p_err, ctx->content, TRUE)) {
			GRID_DEBUG("Error updating chunk [%s] in content [%s]",
					check_info->ck_info->id, check_info->ct_info->path);
			goto clean_up;
		}
		check_result_append_msg(cres, "Chunk referenced in [%s/%s]",
				check_info->ct_info->container_id,
				check_info->ct_info->path);
	}

	ret = TRUE;

clean_up:
	return ret;
}

static gboolean
_find_content_from_chunkid(struct meta2_ctx_s *ctx, check_info_t *check_info)
{
	gboolean ret = FALSE;
	GSList *chunk_ids = NULL;
	struct hc_url_s *url = NULL;
	gchar m2addr_str[STRLEN_ADDRINFO];
	GError *local_error = NULL;
	struct content_textinfo_s *content_info = check_info->ct_info;
	gchar *old_content_path = content_info->path;

	// init container url
	url = hc_url_empty();
	hc_url_set(url, HCURL_NS, check_info->ns_name);
	hc_url_set(url, HCURL_HEXID, content_info->container_id);

	// content path will be reset
	content_info->path = NULL;

	// locate content and all its chunks
	if (ctx->m2_cnx) {
		addr_info_to_string(&(ctx->m2_cnx->addr), m2addr_str, sizeof(m2addr_str));
		local_error = find_storage_policy_and_friend_chunks_full(
				m2addr_str, url, check_info, &chunk_ids, &(ctx->content));
	}

	// if content not found, return FALSE
	if (local_error || !content_info->path) {
		GRID_DEBUG("content [%s] not found.", old_content_path);
		goto clean_up;
	} else {
		GRID_DEBUG("Content found using chunk id [%s].",
				check_info->ck_info->id);
	}

	ret = TRUE;

clean_up:
	// if path was updated, free the old value, otherwise set it back
	if (content_info->path)
		g_free(old_content_path);
	else
		content_info->path = old_content_path;
	hc_url_clean(url);
	g_slist_free_full(chunk_ids, g_free);
	if (local_error)
		g_error_free(local_error);

	return ret;
}

static GError*
_content_fill(struct meta2_ctx_s *ctx, check_info_t *check_info)
{
	GError* local_error = NULL;
	meta2_raw_content_clean(ctx->content);
	ctx->content = g_malloc0(sizeof(meta2_raw_content_t));
	if (!_fill_raw_content_with_info(ctx->content, check_info, &local_error))
		GRID_DEBUG("Error filling new content [%s]", check_info->ct_info->path);
	return local_error;
}

static GError*
_content_remove(struct meta2_ctx_s *ctx, check_info_t *check_info,
		check_result_t *cres)
{
	const gboolean is_dryrun = check_option_get_bool(check_info->options,
			CHECK_OPTION_DRYRUN);
	GError *local_error = NULL;
	gchar*      hexid = check_info->ct_info->container_id;
	container_id_t cid;
	gchar *content_path = check_info->ct_info->path;

	if (is_dryrun) {
		check_result_append_msg(cres, "dryrun prevented from removing "
				"content [%s] in container [%s]", content_path, hexid);
		return NULL;
	}

	if (!container_id_hex2bin(hexid, strlen(hexid), &cid, &local_error))
		return local_error;

	addr_info_t m2;
	grid_string_to_addrinfo(ctx->loc->m2_url[0], NULL, &m2);

	//remove content
	if (!meta2_remote_content_remove(&m2, META2_TIMEOUT, &local_error, cid, content_path)) {
		if (!local_error)
			GSETERROR(&local_error, "content_remove error");
		return local_error;
	}

	// content commit ?
	if (!meta2_remote_content_commit(&m2, META2_TIMEOUT, &local_error, cid, content_path)) {
		if (!local_error)
			GSETERROR(&local_error, "content_remove, commit error");
		return local_error;
	}

	return NULL;
}

static gboolean
_check_chunk_pending(check_info_t *check_info, check_result_t *cres)
{
	const gboolean is_dryrun = check_option_get_bool(check_info->options,
			CHECK_OPTION_DRYRUN);

	if (_check_chunk_md5(check_info)) {
		if (is_dryrun) {
			check_result_append_msg(cres, "dryrun prevented from removing extension [%s]",
					check_info->source_path);
		} else {
			if (remove_file_extension(check_info->source_path))
				check_result_append_msg(cres, "Removed extension of filename [%s]",
						check_info->source_path);
			else
				check_result_append_msg(cres, "Could not rename file [%s]",
						check_info->source_path);
		}
		return TRUE;
	}

	// wrong md5, move .pending chunk to trash
	if (trash_chunk(check_info, cres))
		check_result_append_msg(cres, "(corrupted .pending)");

	return FALSE;
}

gboolean
replace_chunk(struct meta2_ctx_s *ctx, struct meta2_raw_chunk_s *rc,
		check_info_t *check_info, GError **p_err)
{
	if (!meta2raw_remote_delete_chunks(ctx->m2_cnx, p_err, ctx->content)) {
		GRID_DEBUG("Error deleting chunks in content [%s]",
				check_info->ct_info->path);
		return FALSE;
	}
	if (!_fill_raw_chunk_with_info(rc, check_info, p_err)) {
		GRID_DEBUG("Error updating raw chunks in content [%s]",
				check_info->ct_info->path);
		return FALSE;
	}
	if (!meta2raw_remote_update_content(ctx->m2_cnx, p_err,
			ctx->content, TRUE)) {
		GRID_DEBUG("Error fixing chunk [%s] in content [%s]",
				check_info->ck_info->id, check_info->ct_info->path);
		return FALSE;
	}
	return TRUE;
}

static void
_append_brk_el_to_result(struct content_textinfo_s *content_info,
		GSList *broken_elements, check_result_t *cres)
{
	static const gchar* const property_names[] = {
			"containerid",
			"contentname",
			"contentsize",
			"contentchunknb",
			"contentmetadata",
			"contentsystemmetadata",
			"chunkid",
			"chunksize",
			"chunkhash",
			"chunkposition",
			"chunkmetadata"
	};

	void _append_brk_el(gpointer _brk_el, gpointer _udata)
	{
		struct broken_element_s *brk_el = _brk_el;
		const gint prop_index = brk_el->property - 1;
		const gchar *reason = reason_to_str[brk_el->reason];
		const gchar *location = loc_to_str[brk_el->location];
		(void) _udata;
		if (prop_index >= 0)
			check_result_append_msg(cres, "%s (%s on %s)",
					property_names[prop_index], reason, location);
		else
			check_result_append_msg(cres, "unknown (index %i) ", prop_index);
	}

	check_result_append_msg(cres, "[%s/%s] broken elements:[",
			content_info->path, content_info->container_id);
	g_slist_foreach(broken_elements, _append_brk_el, NULL);
	check_result_append_msg(cres, "]");
}

static gboolean
_rename_file(const gchar *src_file, const gchar *dst_file)
{
	errno = 0;
	if (-1 == rename(src_file, dst_file)) {
		GRID_ERROR("Could not move file from [%s] to [%s] (%s).",
				src_file, dst_file, strerror(errno));
		return FALSE;
	}
	return TRUE;
}

static gboolean
_ensure_dir_created(const gchar *dir_path)
{
	if (!g_file_test(dir_path, G_FILE_TEST_IS_DIR)) {
		errno = 0;
		// create directory with permissions 775
		if (-1 == mkdir(dir_path, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) {
			GRID_ERROR("Could not create directory [%s] (%s).",
					dir_path, strerror(errno));
			return FALSE;
		}
		GRID_DEBUG("Created directory [%s]", dir_path);
	}

	return TRUE;
}

static gboolean
_move_file_to_dir(const gchar *src_file, const gchar *dst_dir)
{
	gboolean ret;
	GString *dst_file = NULL;

	if (!_ensure_dir_created(dst_dir))
		return FALSE;

	// append source file name to destination path, including '/'
	dst_file = g_string_new(dst_dir);
	g_string_append(dst_file, strrchr(src_file, G_DIR_SEPARATOR));
	ret = _rename_file(src_file, dst_file->str);
	g_string_free(dst_file, TRUE);
	return ret;
}

gboolean
remove_file_extension(const gchar *path)
{
	gboolean ret;
	GString *dst_file = g_string_new(path);
	const gsize dst_len = strrchr(path, '.') - path;

	g_string_truncate(dst_file, dst_len);
	ret = _rename_file(path, dst_file->str);
	g_string_free(dst_file, TRUE);

	return ret;
}

gboolean
trash_chunk(check_info_t *check_info, check_result_t *cres)
{
	gboolean ret;
	GString *dst_dir = g_string_new(check_info->rawx_vol);
	GString *src_file = g_string_new(check_info->source_path);
	const gboolean is_dryrun = check_option_get_bool(check_info->options,
			CHECK_OPTION_DRYRUN);

	// if rawx volume does not end with '/', append it
	if (dst_dir->str[dst_dir->len - 1] != G_DIR_SEPARATOR)
		g_string_append_c(dst_dir, G_DIR_SEPARATOR);

	g_string_append(dst_dir, REDC_LOSTFOUND_FOLDER);
	if (is_dryrun) {
		ret = TRUE;
		check_result_append_msg(cres, "dryrun prevented from moving chunk to "
				REDC_LOSTFOUND_FOLDER);
	} else {
		ret = _move_file_to_dir(src_file->str, dst_dir->str);
		if (ret)
			check_result_append_msg(cres, "chunk moved to "
					REDC_LOSTFOUND_FOLDER);
	}
	g_string_free(dst_dir, TRUE);
	g_string_free(src_file, TRUE);

	return ret;
}

static gboolean
_reinit_ctx(struct meta2_ctx_s **p_ctx,
		struct content_textinfo_s *content_info, GError **p_err)
{
	gboolean ret = FALSE;
	struct meta2_ctx_s *new_ctx = NULL;
	gchar* ns = NULL;

	if (!p_ctx)
		return FALSE;

	ns = g_strdup((*p_ctx)->ns);

	// clear old ctx
	content_check_ctx_clear(*p_ctx);
	*p_ctx = NULL;

	// create new ctx
	new_ctx = get_meta2_ctx(ns, content_info->container_id,
			content_info->path, TRUE, p_err);
	if (!new_ctx) {
		GRID_DEBUG("Failed to get meta2 context (reloaded), check your NS is started. (NS:%s)", ns);
		goto clean_up;
	}
	if (new_ctx->loc == NULL || new_ctx->loc->m2_url == NULL) {
		GRID_DEBUG("Failed to locate container on a meta2 (reloaded) [%s][%s/%s]",
				content_info->container_id, new_ctx->ns, new_ctx->loc->container_name);
		goto clean_up;
	}

	*p_ctx = new_ctx;
	ret = TRUE;

clean_up:
	g_free(ns);
	return ret;
}

static gboolean
_is_newer_than_content(struct meta2_raw_content_s *content,
		check_info_t *check_info, gboolean *p_same_age)
{
	gint64 date_in_m2 = 0;
	gint64 date_in_extd_attr = 0;

	if (content->system_metadata)
		date_in_m2 = _extract_date_from_sysmd(
				content->system_metadata->data,
				content->system_metadata->len);

	if (check_info->ct_info->system_metadata)
		date_in_extd_attr = _extract_date_from_sysmd(
				(guint8*) check_info->ct_info->system_metadata,
				strlen(check_info->ct_info->system_metadata));

	if (p_same_age)
		*p_same_age = (date_in_m2 == date_in_extd_attr);

	return date_in_extd_attr > date_in_m2;
}

static gboolean
_recreate_content(struct meta2_ctx_s *ctx, check_info_t *check_info,
		check_result_t *cres)
{
	GError *local_error = NULL;
	gboolean ret = FALSE;
	gchar *content_path = check_info->ct_info->path;

	local_error = _content_remove(ctx, check_info, cres);
	if (local_error) {
		GRID_DEBUG("Failed to remove content [%s] from container [%s/%s] (%s)",
				content_path, ctx->ns, ctx->loc->container_name, local_error->message);
		goto clean_up;
	} else {
		GRID_DEBUG("Content [%s] removed from container [%s/%s]",
				content_path, ctx->ns, ctx->loc->container_name);
	}
	local_error = _content_fill(ctx, check_info);
	if (local_error)
		goto clean_up;

	if (!_add_missing_chunk(ctx, check_info, cres, &local_error))
		goto clean_up;

	ret = TRUE;

clean_up:
	if (local_error)
		g_error_free(local_error);
	return ret;
}

gboolean
check_chunk_orphan(check_info_t *check_info, check_result_t *cres, GError **p_err)
{
	const gboolean is_dryrun = check_option_get_bool(check_info->options,
			CHECK_OPTION_DRYRUN);
	gboolean ret = FALSE, is_referenced = FALSE, has_extension = FALSE;
	GSList *broken_elements = NULL;
	struct meta2_ctx_s *ctx = NULL;
	struct content_textinfo_s *content_info = check_info->ct_info;
	gchar *src_basename = NULL;
	struct meta2_raw_chunk_s *raw_chunk = NULL;
	GError *local_error = NULL;
	gboolean same_age, is_chunk_newer;

	// find container and content
	ctx = get_meta2_ctx(check_info->ns_name, content_info->container_id,
			content_info->path, TRUE, p_err);

	if (!ctx) {
		GRID_DEBUG("Failed to get meta2 context, check your NS is started. (NS:%s)", check_info->ns_name);
		return FALSE;
	}

	// if container NOT FOUND on meta1, trash chunk and exit successfully
	// if ctx->loc == NULL: cid not referenced on meta1
	if (ctx->loc == NULL) {
		if (trash_chunk(check_info, cres))
			check_result_append_msg(cres, "(container [%s] not found on meta1)",
					content_info->container_id);
		goto success;
	}

	// if   service's container NOT FOUND on meta1, create it
	// elif service's container FOUND on meta1, check if container really exist on meta2_url
	//            container and service found on meta1,
	//            if content not found: check if container exist on meta2
	if (!ctx->loc->m2_url || !ctx->content) {
		if (is_dryrun) {
			check_result_append_msg(cres, "Content [%s/%s] not found "
					"(not fixable in dryrun mode)",
					content_info->container_id, content_info->path);
			goto success;
		}
		// check / create
		if (!_ensure_container_created(ctx, check_info, cres, p_err)) {
			GRID_DEBUG("Giving up chunk integration (no container).");
			goto clean_up;
		}

		if (ctx->loc->m2_url == NULL) {
			if (!_reinit_ctx(&ctx, check_info->ct_info, p_err))
				goto clean_up;
		}
	}

	// if content not found, try to find content from chunk id
	if (!ctx->content) {
		g_clear_error(&local_error);
		if (!_find_content_from_chunkid(ctx, check_info)) {
			local_error = _content_fill(ctx, check_info);
			if (local_error)
				goto clean_up;
			check_result_append_msg(cres, "Content [%s] in container [%s]"
					" will be created",
					content_info->path, content_info->container_id);
		}
	}

	// if chunk is newer than the content it refers to, re-create content
	// if both have the same date, check referencing
	// if chunk is older, trash it and exit successfully
	is_chunk_newer = _is_newer_than_content(ctx->content, check_info, &same_age);
	if (is_chunk_newer) {
		if (!_recreate_content(ctx, check_info, cres))
			goto clean_up;
		is_referenced = TRUE;
	} else if (same_age) {
		// check if chunk is well referenced in meta2
		raw_chunk = _get_chunk(ctx->content->raw_chunks, check_info->ck_info->position);
		is_referenced = check_chunk_referencing_full(content_info, check_info->ck_info,
				ctx->content, raw_chunk, &broken_elements, p_err);
	} else {
		// crawled chunk is older than content, trash it
		if (trash_chunk(check_info, cres))
			check_result_append_msg(cres, "(chunk too old)");
		goto success;
	}

	src_basename = g_path_get_basename(check_info->source_path);
	has_extension = (NULL != strchr(src_basename, '.'));

	// if chunk is not referenced at all, add it
	if (!is_referenced) {
		// handles .pending chunk: if not referenced, trash
		if (has_extension) {
			if (trash_chunk(check_info, cres))
				check_result_append_msg(cres, "(unreferenced .pending)");
		} else {
			if (!_add_missing_chunk(ctx, check_info, cres, p_err))
				goto clean_up;
		}
	} else {
		// handles .pending chunk: if referenced and md5 ok, remove extension
		if (has_extension && !broken_elements) {
			if (_check_chunk_pending(check_info, cres))
				goto success;
			goto clean_up;
		}
		// chunk is referenced in meta2, print broken elements if any
		if (broken_elements) {
			_append_brk_el_to_result(content_info, broken_elements, cres);

			// handles .pending: move to trash
			if (has_extension) {
				if (trash_chunk(check_info, cres))
					check_result_append_msg(cres, "(.pending with broken elements)");
				goto success;
			}
		} else {
			if (cres && cres->msg == NULL) {
				cres->check_ok = TRUE;
				GRID_DEBUG("Chunk [%s] is well referenced.", check_info->ck_info->id);
			}
		}
	}

success:
	ret = TRUE;

clean_up:
	g_free(src_basename);
	content_check_ctx_clear(ctx);
	g_slist_free_full(broken_elements, broken_element_free);
	if (local_error) {
		g_prefix_error(p_err, "%s", local_error->message);
		g_error_free(local_error);
	}

	return ret;
}
