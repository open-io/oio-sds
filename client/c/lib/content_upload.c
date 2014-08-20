#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.upload"
#endif

#include "./gs_internals.h"

// TODO FIXME replace by the GLib equivalent
#include <openssl/md5.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2_utils.h>

#include "./rawx.h"
#include "./rainx.h"
#include "./http_put.h"
#include <glib/gprintf.h>

#define MAX_ATTEMPTS_COMMIT 2
#define MAX_ADD_ATTEMPTS 2

#define UPLOAD_CLEAN() do {	/*finish cleaning the structures*/\
	if (spare) g_slist_free (spare);\
	if (chunks) { \
		_bean_cleanl2(chunks); \
	} \
	if (system_metadata)\
		g_byte_array_free(system_metadata, TRUE);\
	if (system_metadata_str_esc)\
		g_free(system_metadata_str_esc);\
	g_free((gpointer)actual_stgpol);\
} while (0)

#define UPLOAD_CLEAN_MAIN_THREAD() do { \
	if (chunks_at_position) { \
		for (iter_chunks = 0; iter_chunks < g_hash_table_size(chunks_at_position); iter_chunks++) { \
			fixed = g_hash_table_lookup(chunks_at_position, &iter_chunks); \
			if (fixed) \
				g_slist_free(fixed); \
		} \
		g_hash_table_destroy(chunks_at_position); \
	} \
	if (url) { hc_url_clean(url); } \
	if (local_error) { g_error_free(local_error); } \
	if(orig_sys_metadata_gba) \
		g_byte_array_free(orig_sys_metadata_gba, TRUE); \
} while (0)

static guint
get_maximum_spare_chunks ()
{
	gint64 res64;
	guint res;

	/*nevermind the client nor the namespace, take the environment*/
	gchar *nb_str=getenv(GS_ENVKEY_MAXSPARE);
	if (!nb_str) nb_str = GS_DEFAULT_MAXSPARE;
	res64 = g_ascii_strtoll(nb_str, NULL, 10);
	if (res64<0 || res64>65536LL) {
		GRID_ERROR("out of range");
		return 0;
	}

	res = res64;
	return res;
}

typedef GSList* (*meta2_content_add_f) (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *system_metadata, GByteArray **new_system_metadata);

typedef GSList* (*meta2_content_add_v2_f) (int *fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *user_metadata, GByteArray *system_metadata, GByteArray **new_system_metadata);

static gs_status_t _gs_upload_content (meta2_content_add_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err);

static gs_status_t _gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *mdusr,
		const char *sys_metadata, gs_error_t **err);

static gs_status_t _gs_upload(gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *mdusr,
		const char *mdsys, const char *stgpol, gs_error_t **err);

gs_status_t gs_upload(gs_container_t *container, const char *content_name,
		const int64_t content_size, gs_input_f feeder, void *user_data,
		const char *mdusr, const char *mdsys, const char *stgpol,
		gs_error_t **err)
{
	return _gs_upload(container, content_name, FALSE, content_size, feeder,
			user_data, mdusr, mdsys, stgpol, err);
}

/* upload the given chunk from the retry buffer */
gs_status_t gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *mdusr,
		const char *sys_metadata, gs_error_t **err)
{
	return gs_upload(container, content_name, content_size, feeder,
			user_data, mdusr, sys_metadata, NULL, err);
}

gs_status_t gs_upload_content (gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err)
{
	return _gs_upload_content(meta2_remote_content_add_in_fd, container, content_name, content_size, feeder, user_data, err);
}

/* upload the given chunk from the retry buffer */
gs_status_t gs_append_content (gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err)
{
	return _gs_upload_content_v2(container, content_name, TRUE, content_size, feeder, user_data,
			NULL, NULL, err);
}

static guint
get_nb_chunks_at_position(GSList *chunks, const chunk_position_t position)
{
	guint nb_chunks = 0U;
	GSList *l = NULL;

	for(l = chunks; l && l->data; l = l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			struct bean_CONTENTS_s *content = (struct bean_CONTENTS_s *) l->data;
			char *tmp = CONTENTS_get_position(content)->str;
			char **tok = g_strsplit(tmp, ".", 2);
			gint64 pos64 = g_ascii_strtoll(tok[0], NULL, 10);
			guint32 pos = pos64;
			if (pos  == position) {
				nb_chunks++;
			}
			g_strfreev(tok);
		}
	}

	return nb_chunks;
}

static void
_update_content_bean_hash(content_hash_t *ch, gpointer beans)
{
	GSList * l =(GSList *) beans;
	GSList *b = NULL;

	for(b = l; b && b->data; b = b->next) {
		if(DESCR(b->data) != &descr_struct_CONTENTS_HEADERS)
			continue;
		struct bean_CONTENTS_HEADERS_s *bean = (struct bean_CONTENTS_HEADERS_s *) b->data;
		CONTENTS_HEADERS_nullify_hash(bean);
		if (ch)
			CONTENTS_HEADERS_set2_hash(bean, *ch, sizeof(content_hash_t));
	}
}

static struct bean_CHUNKS_s *
_get_chunk_matching_content(GSList *beans, struct bean_CONTENTS_s *content)
{
	GSList *l = NULL;
	/*split the chunks into the spare and used chunks*/
	for (l = beans; l && l->data ; l=l->next) {
		if(DESCR(l->data) != &descr_struct_CHUNKS)
			continue;
		struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) l->data;
		char *cid1 = CONTENTS_get_chunk_id(content)->str;
		char *cid2 = CHUNKS_get_id(ck)->str;
		if(0 == g_ascii_strcasecmp(cid1, cid2)) {
			return ck;
		}
	}

	return NULL;
}

/* upload the given chunk from the retry buffer */
static gs_status_t _gs_upload_content (meta2_content_add_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err)
{
	(void) adder;
	return _gs_upload_content_v2(container, content_name, FALSE, content_size, feeder, user_data, NULL, NULL, err);
}

static GStaticMutex global_mutex = G_STATIC_MUTEX_INIT;

/**
 * Update chunk extended attributes (position, content size, number of chunks)
 * which have changed during an append operation.
 *
 * @param beans List of all beans of the content
 * @return the version of the content
 */
static content_version_t _get_vers_and_update_attr_if_needed(GSList *beans,
		gboolean append)
{
	GError *err = NULL;
	gint64 content_size = 0;
	gint64 max_pos = 0;
	content_version_t version = 0;

	/* Compute number of chunks and get content size */
	for (GSList *l = beans; l != NULL; l = l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES) {
			version = ALIASES_get_version(l->data);
			DEBUG("version of the content: %"G_GINT64_FORMAT, version);
		} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			content_size = CONTENTS_HEADERS_get_size(l->data);
		} else if (DESCR(l->data) == &descr_struct_CONTENTS) {
			/* We may have several chunks at the same position,
			 * we cannot just count the number of chunk beans,
			 * so we search the highest position. */
			gchar *str_pos = CONTENTS_get_position(l->data)->str;
			gint pos = 0, subpos = 0;
			gboolean par = FALSE;
			m2v2_parse_chunk_position(str_pos, &pos, &par, &subpos);
			if (pos > max_pos)
				max_pos = pos;
		}
	}
	/* Update chunk attributes */
	if (append) {
		for (GSList *l = beans; l != NULL; l = l->next) {
			if (DESCR(l->data) != &descr_struct_CONTENTS)
				continue;
			gboolean res = TRUE;
			GSList *attrs = NULL;
			const gchar *url = CONTENTS_get_chunk_id(l->data)->str;
			const gchar *pos = CONTENTS_get_position(l->data)->str;
			struct chunk_attr_s attr_pos = {RAWX_ATTR_CHUNK_POSITION, pos};
			struct chunk_attr_s attr_size = {RAWX_ATTR_CONTENT_SIZE,
				g_strdup_printf("%"G_GINT64_FORMAT, content_size)};
			struct chunk_attr_s attr_chunknb = {RAWX_ATTR_CONTENT_CHUNKNB,
				g_strdup_printf("%"G_GINT64_FORMAT, max_pos+1)};
			attrs = g_slist_prepend(attrs, &attr_pos);
			attrs = g_slist_prepend(attrs, &attr_chunknb);
			attrs = g_slist_prepend(attrs, &attr_size);
			res = rawx_update_chunk_attrs(url, attrs, &err);
			if (!res || err != NULL) {
				GRID_WARN("Could not update extended attributes of chunk %s: %s",
						url, err?err->message:"reason unknown");
				g_clear_error(&err);
			}
			g_free((gpointer)attr_size.val);
			g_free((gpointer)attr_chunknb.val);
			g_slist_free(attrs);
		}
	}

	return version;
}

static GError *_rawx_update_beans_hash_from_request(struct http_put_s *http_put)
{
	GSList *i_list = NULL, *beans;
	struct bean_CHUNKS_s *bc;
	const gchar *hash_str;
	chunk_hash_t hash;
	GError *error = NULL;
	gboolean ret;

	beans = http_put_get_success_dests(http_put);

	for (i_list = beans; i_list != NULL ; i_list = g_slist_next(i_list)) {
		bc = i_list->data;

		hash_str = http_put_get_header(http_put, bc, "chunk_hash");
		if (hash_str == NULL)
		{
			GSETERROR(&error,"Missing chunk hash in response from rawx");
			goto end;
		}

		ret = hex2bin(hash_str, hash, sizeof(hash), &error);
		if (ret != TRUE)
			goto end;

		CHUNKS_set2_hash(bc, hash, sizeof(hash));
	}

end:
	g_slist_free(beans);
	return error;
}

/**
 * Get CONTENT corresponding to one CHUNK.
 *
 * @param all_chunks chunks list with CONTENTS, CHUNKS, ALIAS, CONTENTS_HEADERS...
 * @param bc chunk
 *
 * @return CONTENT if found, NULL otherwise
 */
static struct bean_CONTENTS_s *_bean_get_content_from_chunk(GSList *all_chunks, struct bean_CHUNKS_s *bc)
{
	GSList *i_list = NULL;
	struct bean_CONTENTS_s *content;

	for (i_list = all_chunks ; i_list != NULL ; i_list = g_slist_next(i_list)) {
		if(DESCR(i_list->data) != &descr_struct_CONTENTS)
			continue;

		content = i_list->data;

		if (0 == g_ascii_strcasecmp(CHUNKS_get_id(bc)->str, CONTENTS_get_chunk_id(content)->str)) {
			return content;
		}
	}

	return NULL;
}

/**
 * Update chunks with information from the header 'chunklist' sent by rainx
 * and remove unused chunks (in case of small data).
 *
 * @params all_chunks chunk list with CONTENTS, CHUNKS, ALIAS, CONTENTS_HEADERS...
 * @param chunks_by_pos list of CHUNKS for one position
 * @param header_chunklist 'chunklist' header sent by rainx
 *
 * @return NULL if ok, otherwise error
 */
static GError * _rainx_update_chunks_with_response(GSList **all_chunks, GSList **chunks_by_pos, const gchar *header_chunklist)
{
	gchar **split_header = NULL;
	gchar **iter;
	gchar *chunk_addr, *chunk_id, *chunk_hash, *chunk_size;
	chunk_hash_t hash;
	gint64 size;
	GSList *i_list;
	struct bean_CHUNKS_s *bc;
	const gchar *bean_id;
	GSList * beans_to_remove = NULL;
	struct bean_CONTENTS_s *content_to_remove;
	GError *error = NULL;

	g_assert(header_chunklist != NULL);

	/* chunklist format: ip:port/chunk_id|chunk_size|chunk_hash;... */

	split_header = g_strsplit(header_chunklist, ";", 0);

	beans_to_remove = g_slist_copy(*chunks_by_pos);

	for (iter = split_header ; *iter != NULL ; iter++)
	{
		chunk_addr = *iter;
		
		chunk_id = g_strstr_len(chunk_addr, -1, "/");
		if (chunk_id == NULL)
		{
			GSETERROR(&error,"Bad format for chunklist header (address)");
			goto end;
		}

		chunk_id[0] = '\0';
		chunk_id++;

		chunk_size = g_strstr_len(chunk_id, -1, "|");
		if (chunk_id == NULL)
		{
			GSETERROR(&error,"Bad format for chunklist header (size)");
			goto end;
		}
		chunk_size[0] = '\0';
		chunk_size++;
		size = g_ascii_strtoll(chunk_size, NULL, 10);

		chunk_hash = g_strstr_len(chunk_size, -1, "|");
		if (chunk_id == NULL)
		{
			GSETERROR(&error,"Bad format for chunklist header (hash)");
			goto end;
		}
		chunk_hash[0] = '\0';
		chunk_hash++;
		if (!hex2bin(chunk_hash, hash, sizeof(hash), &error))
		{
			GSETERROR(&error,"Bad format for chunklist header (hash hex)");
			goto end;
		}

		TRACE("chunklist [%s] [%s] [%s] [%s]",
				chunk_addr, chunk_id, chunk_size, chunk_hash);

		/* search the bean and update their attributes */
		for (i_list = beans_to_remove ; i_list != NULL ; i_list = i_list->next)
		{
			bc = i_list->data;
			bean_id = g_strrstr(CHUNKS_get_id(bc)->str, "/");
			g_assert(bean_id != NULL);
			bean_id++;

			if (g_strcmp0(bean_id, chunk_id) == 0)
			{
				CHUNKS_set2_hash(bc, hash, sizeof(hash));
				CHUNKS_set_size(bc, size);

				/* This chunk is ok so no need to remove it from global list */
				beans_to_remove = g_slist_delete_link(beans_to_remove, i_list);
				break;
			}
		}
	}

	/* Remove unused chunks */
	for (i_list = beans_to_remove ; i_list != NULL ; i_list = g_slist_next(i_list))
	{
		/* Remove CONTENT associated to this CHUNK */
		content_to_remove = _bean_get_content_from_chunk(*all_chunks, i_list->data);
		if (content_to_remove == NULL)
		{
			GSETERROR(&error,"Content bean not found");
			goto end;
		}
		*all_chunks = g_slist_remove(*all_chunks, content_to_remove);
		_bean_clean(content_to_remove);

		/* Remove all links to this CHUNK bean
		 */
		*chunks_by_pos = g_slist_remove(*chunks_by_pos, i_list->data);
		*all_chunks = g_slist_remove(*all_chunks, i_list->data);
		_bean_clean(i_list->data);
	}

end:
	if (split_header != NULL)
		g_strfreev(split_header);
	if (beans_to_remove != NULL)
		g_slist_free(beans_to_remove);

	return error;
}

/**
 * subchunk = -1: on NONE/DUPPLI mode for format position field 
 *          >=0: on RAINX mode for format position field "<chunkpos>.<subchunk>"
 *          used only if content_size == 0. no need parity format, only data format
 */
static GError * _http_put_set_dest(struct http_put_s *http_put, const gchar *url,
		gpointer user_data,
		const gchar *containerid, const gchar * chunkid, const gchar *contentpath,
		gint64 contentsize, gint chunkpos, gint subchunk, guint chunknb, gint64 chunksize,
		const gchar *metadata, const char *rawxlist,
		const char *storagepolicy, const gchar *reqid)
{
	struct http_put_dest_s *http_dest;
	GError * error;

	http_dest = http_put_add_dest(http_put, url, user_data);
	if (http_dest == NULL)
	{
		GSETERROR(&error,"Failed to add destination");
		return error;
	}

	http_put_dest_add_header(http_dest, "containerid", containerid);

	http_put_dest_add_header(http_dest, "contentpath", contentpath);

	if (subchunk >= 0) {
		http_put_dest_add_header(http_dest, "chunkpos", "%d.%d", chunkpos, subchunk);
    }else{
		http_put_dest_add_header(http_dest, "chunkpos", "%d", chunkpos);
	}

	http_put_dest_add_header(http_dest, "chunknb", "%u", chunknb);

	http_put_dest_add_header(http_dest, "chunksize", "%"G_GINT64_FORMAT, chunksize);

	http_put_dest_add_header(http_dest, "contentsize", "%"G_GINT64_FORMAT, contentsize);

	/* No chunk id in case of rain
	 */
	if (NULL != chunkid)
		http_put_dest_add_header(http_dest, "chunkid", chunkid);

	http_put_dest_add_header(http_dest, "contentmetadata-sys", metadata);

	http_put_dest_add_header(http_dest, "GSReqId", reqid);

	if (rawxlist != NULL)
		http_put_dest_add_header(http_dest, "rawxlist", rawxlist);

	if (storagepolicy != NULL)
		http_put_dest_add_header(http_dest, "storagepolicy", storagepolicy);

	return NULL;
}

/**
 * subchunk = -1: on NONE/DUPPLI mode for format position field
 *          >=0: on RAINX mode for format position field "<chunkpos>.<subchunk>"
 *          used only if content_size == 0. no need parity format, only data format
 */
static GError * _http_put_set_dests(struct http_put_s *http_put, GSList *bean_list,
		const gchar *containerid, const gchar *contentpath,
		gint64 contentsize, gint chunkpos, gint subchunk, guint chunknb,
		const gchar *metadata, const gchar *reqid)
{
	struct bean_CHUNKS_s *bc;
	GSList *i_list;
	const gchar *chunkid;
	GError *error;

	for (i_list = bean_list ; i_list != NULL ; i_list = i_list->next)
	{
		bc = i_list->data;

		GRID_DEBUG("\t=> %s (%"G_GINT64_FORMAT" bytes)", CHUNKS_get_id(bc)->str, CHUNKS_get_size(bc));

		chunkid = strrchr(CHUNKS_get_id(bc)->str, '/');
		if (chunkid == NULL)
		{
			GSETERROR(&error,"Bad format for chunk id");
			return error;
		}
		chunkid++;

		error = _http_put_set_dest(http_put, CHUNKS_get_id(bc)->str, bc,
				containerid, chunkid,
				contentpath, contentsize, chunkpos, subchunk, chunknb,
				CHUNKS_get_size(bc), metadata, NULL, NULL, reqid);
		if (error != NULL)
			return error;
	}

	return NULL;
}

/* Must have as least the same number of spare beans as broken beans
 */
static GError *_update_broken_beans(GSList *all_beans, GSList *broken_beans, GSList *spare_beans)
{
	struct bean_CHUNKS_s *spare_bc;
	struct bean_CHUNKS_s *broken_bc;
	struct bean_CONTENTS_s *content;
	GError *error;

	while (broken_beans != NULL)
	{
		g_assert(spare_beans != NULL);

		broken_bc = broken_beans->data;
		spare_bc = spare_beans->data;

		GRID_DEBUG("SPARE: replace %s by %s",
				CHUNKS_get_id(broken_bc)->str,
				CHUNKS_get_id(spare_bc)->str);

		content = _bean_get_content_from_chunk(all_beans, broken_bc);
		if (content == NULL)
		{
			GSETERROR(&error,"Content bean not found");
			return error;
		}
		CONTENTS_set_chunk_id(content, CHUNKS_get_id(spare_bc));

		/* fill broken bean with spare bean data
		 */
		CHUNKS_set_id(broken_bc, CHUNKS_get_id(spare_bc));
		CHUNKS_set_ctime(broken_bc, CHUNKS_get_ctime(spare_bc));

		broken_beans = g_slist_next(broken_beans);
		spare_beans = g_slist_next(spare_beans);
	}

	return NULL;
}

static gchar* _rainx_create_rawxlist_from_chunk_bean_list(GSList *bean_list)
{
	GString *res = NULL;
	struct bean_CHUNKS_s *bc;
	const gchar *chunk_id;
	const gchar *tok_begin, *tok_end;

	g_assert(bean_list != NULL);

	res = g_string_new("");

	for (GSList *l = bean_list; l; l = l->next) {
		bc = l->data;
		chunk_id = CHUNKS_get_id(bc)->str;

		/* chunkid format: http://10.24.244.158:6032/DATA/CCANS/common/rawx-2/EC2E74D2A69A17C0CC099956E7C557CC5ED3D5C6881DF4BA0120FFACC91A6B11
		 */
		tok_begin = g_strstr_len(chunk_id, -1, "://"); /* ip:port */
		g_assert(tok_begin != NULL);
		tok_begin += 3; /* skip :// */
		tok_end = g_strstr_len(tok_begin, -1, "/");
		g_assert(tok_end != NULL);
		
		g_string_append_len(res, tok_begin, tok_end - tok_begin);

		tok_begin = g_strrstr(chunk_id, "/"); /* chunk id, keep the / */
		g_assert(tok_begin != NULL);

		g_string_append(res, tok_begin);

		if (l->next)
			g_string_append(res, "|");
	}

	return g_string_free(res, FALSE);
}

static GError *_rainx_get_url(const gchar *nsname, gchar *buffer, gsize buffer_size)
{
	addr_info_t *rainx_addr = NULL;
	gchar ip[256]; /* string representation of ipv6 address is 46 chars */
	guint16 port;
	GError *error = NULL;

	g_assert(nsname != NULL);
	g_assert(buffer != NULL);

	rainx_addr = get_rainx_from_conscience(nsname, &error);
	if (error != NULL)
		return error;

	if (! addr_info_get_addr(rainx_addr, ip, sizeof(ip), &port))
	{
		GSETERROR(&error,"Failed to convert ip and port to string");
		g_free(rainx_addr);
		return error;
	}

	g_snprintf(buffer, buffer_size, "http://%s:%"G_GUINT16_FORMAT"/rainx",
			ip, port);

	g_free(rainx_addr);
	return NULL;
}

static GError *_rainx_upload(struct hc_url_s *url, const gchar *target,
		GSList **chunks, GHashTable *chunks_at_position,
		gs_input_f feeder, void *feeder_user_data, const gchar *container_id,
		const gchar *content_name, const gint64 content_size,
		const gchar *system_metadata, const gchar *stgpolicy,
		const gchar *reqid, long timeout_cnx, long timeout_op)
{
	struct http_put_s *http_put = NULL;
	GError *error = NULL;
	GSList *val_l;
	const gchar *chunk_buf;
	gsize chunk_buf_size;
	gint64 chunksize;
	gchar *rawxlist = NULL;
	GChecksum *checksum_md5 = NULL;
	content_hash_t content_hash;
	gsize content_hash_size = sizeof(content_hash);
	gint retry;
	gchar rainx_url[256]; /* http://ip:port/rainx always < 256 chars */
	GSList *spare_list = NULL;
	guint failure_nb;
	const gchar *header_chunklist;

	checksum_md5 = g_checksum_new(G_CHECKSUM_MD5);

	error = _rainx_get_url(hc_url_get(url, HCURL_NS), rainx_url, sizeof(rainx_url));
	if (error != NULL)
		goto error_label;
	GRID_DEBUG("rainx url [%s]", rainx_url);

	for (guint pos = 0 ; pos < g_hash_table_size(chunks_at_position) ; pos++)
	{
		val_l = g_hash_table_lookup(chunks_at_position, &pos);

		chunksize = CHUNKS_get_size((struct bean_CHUNKS_s*)val_l->data);

		http_put = http_put_create(feeder, feeder_user_data, chunksize, timeout_cnx, timeout_op);
		if (http_put == NULL)
		{
			GSETERROR(&error,"Failed to create put request");
			goto error_label;
		}

		/* Try to upload data and use spare chunks if necessary */
		retry = 0;
		while (TRUE)
		{
			GRID_DEBUG("Position %d:", pos);

			rawxlist = _rainx_create_rawxlist_from_chunk_bean_list(val_l);
			if (rawxlist == NULL)
			{
				GSETERROR(&error,"Failed to generate rawxlist for the request");
				goto error_label;
			}
			GRID_DEBUG("rawxlist [%s]", rawxlist);

			/* Add all destinations to http_put handle */
			http_put_clear_dests(http_put);
			error =_http_put_set_dest(http_put, rainx_url, val_l, 
					container_id, NULL, content_name, content_size,
					pos, -1, g_hash_table_size(chunks_at_position),
					chunksize, system_metadata, rawxlist, stgpolicy, reqid);
			if (error != NULL)
				goto error_label;

			g_free(rawxlist);
			rawxlist = NULL;

			gscstat_tags_start(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);
			error = http_put_run(http_put);
			gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);
			if (error != NULL)
				goto error_label;

			failure_nb = http_put_get_failure_number(http_put);
			if (failure_nb == 0 || retry >= MAX_ADD_ATTEMPTS)
				break;

			/* Rainx didn't send us the list of broken rawx so
			 * we replace all our beans by news beans.
			 * We can't ask meta2 to ignore all current rawx because it
			 * might have not enough rawx to fulfill this request.
			 */

			/* Get spare beans */
			error = m2v2_remote_execute_SPARE(target, NULL, url, stgpolicy, NULL, NULL, &spare_list);
			if (error != NULL)
				goto error_label;

			GRID_DEBUG("Number of beans in spare list : %u", g_slist_length(spare_list));

			if (g_slist_length(spare_list) != g_slist_length(val_l))
			{
				GSETERROR(&error,"Not enough spare chunks");
				goto error_label;
			}

			/* update broken chunks with data from spare chunks
			 */
			error = _update_broken_beans(*chunks, val_l, spare_list);
			if (error != NULL)
				goto error_label;

			g_slist_free_full(spare_list, _bean_clean);
			spare_list = NULL;

			retry++;
		}

		if (http_put_get_failure_number(http_put) > 0)
		{
			GSETERROR(&error,"Failed to upload all chunks");
			goto error_label;
		}

		header_chunklist = http_put_get_header(http_put, val_l, "chunklist");
		if (header_chunklist == NULL)
		{
			GSETERROR(&error,"Failed to get chunklist header");
			goto error_label;
		}

		/* Browse all beans to remove unused beans and update their
		 * size and hash according to the response header 'chunklist'
		 */
		error = _rainx_update_chunks_with_response(chunks, &val_l, header_chunklist);
		if (error != NULL)
			goto error_label;

		/* update the checksum of the whole content
		*/
		http_put_get_buffer(http_put, &chunk_buf, &chunk_buf_size);
		g_checksum_update(checksum_md5, (const guchar *)chunk_buf, chunk_buf_size);

		http_put_destroy(http_put);
		http_put = NULL;
	}

	g_checksum_get_digest(checksum_md5, content_hash, &content_hash_size);
	g_checksum_free(checksum_md5);
	checksum_md5 = NULL;

	_update_content_bean_hash(&content_hash, *chunks);

	return NULL;

error_label:
	if (http_put != NULL)
		http_put_destroy(http_put);
	if (rawxlist != NULL)
		g_free(rawxlist);
	if (checksum_md5 != NULL)
		g_checksum_free(checksum_md5);
	if (spare_list != NULL)
		g_slist_free_full(spare_list, _bean_clean);
	return error;
}

static void _debug_bean_chunk_list(GSList *bck_list, const char * message)
{
	GSList *i_list;

	for (i_list = bck_list ; i_list != NULL ; i_list = i_list->next)
	{
		struct bean_CHUNKS_s *bc = i_list->data;
		GRID_DEBUG("%s: %s", message, CHUNKS_get_id(bc)->str);
	}
}

/* is_rain =true when on rainx stgpol but the content_size==0.
 * rawx upload it's used, but extended attribute.position it's on already rainx mode 
 * */
static GError *_rawx_upload(struct hc_url_s *url, const gchar *target,
		GSList **chunks, GHashTable *chunks_at_position,
		gs_input_f feeder, void *feeder_user_data, const gchar *container_id,
		const gchar *content_name, const gint64 content_size,
		const gchar *system_metadata, const gchar *stgpolicy,
		const gchar *reqid, long timeout_cnx, long timeout_op, 
		gboolean is_rain)
{
	struct http_put_s *http_put = NULL;
	GSList *tosend_list = NULL;
	const gchar *chunk_buf;
	gsize chunk_buf_size;
	gint64 chunksize;
	GChecksum *checksum_md5 = NULL;
	content_hash_t content_hash;
	gsize content_hash_size = sizeof(content_hash);
	GSList *notin_list = NULL;
	GSList *broken_list = NULL;
	GSList *spare_list = NULL;
	guint failure_nb;
	guint max_spare, remaining_spare;
	GError *error = NULL;

	max_spare = remaining_spare = get_maximum_spare_chunks();

	checksum_md5 = g_checksum_new(G_CHECKSUM_MD5);

	for (guint pos = 0 ; pos < g_hash_table_size(chunks_at_position) ; pos++)
	{
		tosend_list = g_slist_copy(g_hash_table_lookup(chunks_at_position, &pos));

		chunksize = CHUNKS_get_size((struct bean_CHUNKS_s*)tosend_list->data);

		http_put = http_put_create(feeder, feeder_user_data, chunksize, timeout_cnx, timeout_op);
		if (http_put == NULL)
		{
			GSETERROR(&error,"Failed to create put request");
			goto error_label;
		}

		/* Try to upload data and use spare chunks if necessary */
		remaining_spare = max_spare;
		while (TRUE)
		{
			GRID_DEBUG("Position %d:", pos);

			/* Add all destinations to http_put handle */
			http_put_clear_dests(http_put);
			_http_put_set_dests(http_put, tosend_list, container_id,
					content_name, content_size, pos, ((is_rain)?0:-1),
					g_hash_table_size(chunks_at_position),
					system_metadata, reqid);

			gscstat_tags_start(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);
			error = http_put_run(http_put);
			gscstat_tags_end(GSCSTAT_SERVICE_RAWX, GSCSTAT_TAGS_REQPROCTIME);
			if (error != NULL)
				goto error_label;

			/* update hash for successful transfers */
			error = _rawx_update_beans_hash_from_request(http_put);
			if (error != NULL)
				goto error_label;

			failure_nb = http_put_get_failure_number(http_put);
			if (failure_nb == 0 || remaining_spare < failure_nb)
				break;

			remaining_spare -= failure_nb;

			notin_list = g_slist_concat(notin_list, http_put_get_success_dests(http_put));
			_debug_bean_chunk_list(notin_list, "SUCCESS");

			broken_list = http_put_get_failure_dests(http_put);
			_debug_bean_chunk_list(broken_list, "FAILED");

			/* Get spare beans */
			error = m2v2_remote_execute_SPARE(target, NULL, url, stgpolicy, notin_list, broken_list, &spare_list);
			if (error != NULL)
				goto error_label;

			GRID_DEBUG("Number of beans in notin list : %u", g_slist_length(notin_list));
			GRID_DEBUG("Number of beans in broken list : %u", g_slist_length(broken_list));
			GRID_DEBUG("Number of beans in spare list : %u", g_slist_length(spare_list));

			/* In case of RAIN with empty file, this normal upload
			 * function is used but m2v2_remote_execute_spare use type
			 * M2V2_SPARE_BY_STGPOL instead of M2V2_SPARE_BY_BLACKLIST
			 * so the number of spare can be greater than the number of
			 * broken beans.
			 */
			if (g_slist_length(spare_list) < failure_nb)
			{
				GSETERROR(&error,"Not enough spare chunks");
				goto error_label;
			}

			/* update broken chunks with data from spare chunks
			 */
			error = _update_broken_beans(*chunks, broken_list, spare_list);
			if (error != NULL)
				goto error_label;

			/* try new upload using modified broken beans
			*/
			g_slist_free(tosend_list);
			tosend_list = broken_list;
			broken_list = NULL;

			g_slist_free_full(spare_list, _bean_clean);
			spare_list = NULL;
		}

		g_slist_free(notin_list);
		notin_list = NULL;

		if (http_put_get_failure_number(http_put) > 0)
		{
			GSETERROR(&error,"Failed to upload all chunks");
			goto error_label;
		}

		g_slist_free(tosend_list);
		tosend_list = NULL;

		/* update the checksum of the whole content
		*/
		http_put_get_buffer(http_put, &chunk_buf, &chunk_buf_size);
		g_checksum_update(checksum_md5, (const guchar *)chunk_buf, chunk_buf_size);

		http_put_destroy(http_put);
		http_put = NULL;
	}

	g_checksum_get_digest(checksum_md5, content_hash, &content_hash_size);
	g_checksum_free(checksum_md5);
	checksum_md5 = NULL;

	_update_content_bean_hash(&content_hash, *chunks);

	return NULL;

error_label:
	if (http_put != NULL)
		http_put_destroy(http_put);
	if (tosend_list != NULL)
		g_slist_free(tosend_list);
	if (checksum_md5 != NULL)
		g_checksum_free(checksum_md5);
	if (spare_list != NULL)
		g_slist_free_full(spare_list, _bean_clean);
	if (broken_list != NULL)
		g_slist_free(broken_list);
	if (notin_list != NULL)
		g_slist_free(notin_list);

	return error;
}

static gchar * _esc_gba(GByteArray *metadata)
{
	gchar *metadata_esc, *tmp;

	tmp = g_strndup((const gchar*)metadata->data, metadata->len);

	metadata_esc = g_strescape(tmp, "");

	g_free(tmp);

	return metadata_esc;
}

/* upload the given chunk */
static gs_status_t _gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *mdusr,
		const char *sys_metadata, gs_error_t **err)
{
	return _gs_upload(container, content_name, append, content_size, feeder, user_data, mdusr,
			sys_metadata, NULL, err);
}

static gs_status_t _gs_upload(gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *mdusr,
		const char *sys_metadata, const char *stgpol, gs_error_t **err)
{
#define CONTENT_ADD_V2() m2v2_remote_execute_BEANS(target, NULL, url, actual_stgpol, content_size, append, &chunks)
#define CONTENT_COMMIT() m2v2_remote_execute_PUT(target, NULL, url, chunks, &beans)
#define APPEND_COMMIT() m2v2_remote_execute_APPEND(target, NULL, url, chunks, &beans)

	int nb_attempts;

	/*parameters declaration and initiation*/
	GError *local_error = NULL;
	gchar pos_str[20];
	GHashTable *chunks_at_position = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	GByteArray *system_metadata = NULL;
	gchar *system_metadata_str_esc = NULL;
	GByteArray *orig_sys_metadata_gba=NULL;
	guint iter_chunks = 0;
	guint nb_copies = 0;
	char target[64];
	gchar reqid[1024];
	struct hc_url_s *url = NULL;
	GSList
		*chunks=NULL,           /*free: structure and content*/
		*spare=NULL,            /*free: structure only*/
		*fixed=NULL,            /*free: structure only*/
		*cursor=NULL;           /*do not free*/
	GSList *beans = NULL;
	long timeout_cnx, timeout_op;
	gchar *actual_stgpol = stgpol ? g_strdup(stgpol) : NULL;

	gboolean is_rainx, tmp_is_rainx;
	content_version_t content_version;

	/*sanity checks*/
	if (!container || !content_name || content_size<0 || !feeder) {
		GSERRORSET(err,"Invalid parameter");
		return GS_ERROR;
	}

	timeout_cnx = MAX(gs_grid_storage_get_timeout(container->info.gs, GS_TO_RAWX_CNX) / 1000, 1);
	timeout_op = MAX(gs_grid_storage_get_timeout(container->info.gs, GS_TO_RAWX_OP) / 1000, 1);
	GRID_DEBUG("Timeout cnx %ld s ; timeout op %ld s", timeout_cnx, timeout_op);

	is_rainx = stg_pol_is_rainx(&(container->info.gs->ni), actual_stgpol);

	/* New meta1 purpose : ensure to be linked with a meta2 */
	if(container->meta2_addr.port <= 0) {
		gs_container_t *tmp = NULL;
		tmp = gs_get_storage_container(container->info.gs, C0_NAME(container),
				NULL, container->ac, err);
		if(NULL != tmp ) {
			memcpy(&(container->meta2_addr), &(tmp->meta2_addr), sizeof(addr_info_t));
			gs_container_free(tmp);
		}
	}

	if(sys_metadata && strlen(sys_metadata) > 0) {
		orig_sys_metadata_gba = g_byte_array_new();
		g_byte_array_append(orig_sys_metadata_gba, (guint8*)sys_metadata, strlen(sys_metadata));
	}

	bzero(target, sizeof(target));
	addr_info_to_string(&container->meta2_addr, target, 64);

	url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(container->info.gs));
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(container));
	hc_url_set(url, HCURL_PATH, content_name);

	/*get a list of chunks*/
	g_static_mutex_lock(&global_mutex);
	(void) gs_container_reconnect_if_necessary (container,NULL);
	for (nb_attempts=MAX_ADD_ATTEMPTS; (NULL != (local_error=CONTENT_ADD_V2())) && nb_attempts>0 ;nb_attempts--) {
		CONTAINER_REFRESH(container,local_error,error_label_unlock,"PUT error");
		if ((!local_error || local_error->code<200/*error is local*/)
			&& wait_on_add_failed>0UL && nb_attempts>1)
		{
			GRID_DEBUG("Waiting [%lu] ms before retrying ADD", wait_on_add_failed);
			usleep( wait_on_add_failed * 1000UL );
		}
		if (local_error)
			g_clear_error(&local_error);
	}
	g_static_mutex_unlock(&global_mutex);

	if (!chunks) {
		GSETERROR(&local_error, "PUT error: Too many attempts");
		goto exit_label;
	}

	nb_copies = get_nb_chunks_at_position(chunks, 0);

	/*save the system_metadata_information that will be copied into the last-chunk attributes*/

	/*split the chunks into the spare and used chunks*/
	for (cursor=chunks; cursor && cursor->data ;cursor=cursor->next) {
		/* TODO: search contents item, foreach search chunk item and add it at the good pos */

		if (DESCR(cursor->data) == &descr_struct_CONTENTS_HEADERS) {
			/* Get the actual storage policy selected by meta2 */
			GString *pol_str = CONTENTS_HEADERS_get_policy(cursor->data);
			if (pol_str != NULL) {
				if(NULL != actual_stgpol)
					g_free(actual_stgpol);
				actual_stgpol = g_strdup(pol_str->str);
			}
			continue;
		} else if (DESCR(cursor->data) == &descr_struct_ALIASES) {
			GString *sysmd = ALIASES_get_mdsys(cursor->data);
			if (!system_metadata)
				system_metadata = g_byte_array_new();
			if (orig_sys_metadata_gba && orig_sys_metadata_gba->len > 0) {
				g_byte_array_append(system_metadata,
						orig_sys_metadata_gba->data,
						orig_sys_metadata_gba->len);
				g_byte_array_append(system_metadata, (guint8*)";", 1);
			}
			g_byte_array_append(system_metadata,
					(guint8*)sysmd->str, sysmd->len);
			continue;

		} else if (DESCR(cursor->data) != &descr_struct_CONTENTS) {
			continue;
		}

		struct bean_CONTENTS_s *content = (struct bean_CONTENTS_s *) cursor->data;
		struct bean_CHUNKS_s *ck = _get_chunk_matching_content(chunks, content);
		if(NULL == ck) {
			GRID_WARN("No chunk matching content, meta2 return some bad informations");
			continue;
		}
		TRACE("Chunk id [%s] pos [%s] size[%"G_GINT64_FORMAT"]", CHUNKS_get_id(ck)->str, CONTENTS_get_position(content)->str, CHUNKS_get_size(ck));
		char *tmp = CONTENTS_get_position(content)->str;
		char **tok = g_strsplit(tmp, ".", 2);
		gint64 pos64 = g_ascii_strtoll(tok[0], NULL, 10);
		if (pos64 < 0) {
			spare = g_slist_prepend(spare, ck);
		} else {
			gint pos = pos64;
			fixed = g_hash_table_lookup(chunks_at_position, &pos);
			fixed = g_slist_append(fixed, ck);
			g_hash_table_insert(chunks_at_position, g_memdup(&pos, sizeof(pos)), fixed);
		}
		g_strfreev(tok);
	}

	if (!fixed && content_size > 0) {
		GSETERROR(&local_error,"no fixed chunks have been found!");
		goto error_label;
	}

	// Don't do RAIN with empty contents
	tmp_is_rainx = stg_pol_is_rainx(&(container->info.gs->ni), actual_stgpol);
	is_rainx = (content_size > 0 && tmp_is_rainx);
	if (is_rainx) {
		GRID_DEBUG("'%s' of size %"G_GINT64_FORMAT" split into %u chunks (every chunk has %u sub-chunks, there are %u unique presets and %u spares)",
				content_name, content_size,
				g_slist_length(chunks) / 2 / (nb_copies?nb_copies:1), nb_copies,
				g_hash_table_size(chunks_at_position), g_slist_length(spare));
	} else {
		GRID_DEBUG("'%s' of size %"G_GINT64_FORMAT" split into %u chunks (every chunk is duplicated %u times, there are %u unique presets and %u spares)",
				content_name, content_size,
				g_slist_length(chunks) / 2 / (nb_copies?nb_copies:1), nb_copies,
				g_hash_table_size(chunks_at_position), g_slist_length(spare));
	}

	if (GRID_TRACE_ENABLED()) {
		for (iter_chunks = 0; iter_chunks < g_hash_table_size(chunks_at_position); ++iter_chunks) {
			fixed = g_hash_table_lookup(chunks_at_position, &iter_chunks);
			g_snprintf(pos_str, 20, "chunks[pos=%u]:", iter_chunks);
		}
	}

	system_metadata_str_esc = _esc_gba(system_metadata);
	gen_req_id_header(reqid, sizeof(reqid));

	if (is_rainx) {
		local_error = _rainx_upload(url, target,
				&chunks, chunks_at_position,
				feeder, user_data, container->str_cID,
				content_name, content_size,
				system_metadata_str_esc, actual_stgpol,
				reqid, timeout_cnx, timeout_op);
	} else {
		local_error = _rawx_upload(url, target,
				&chunks, chunks_at_position,
				feeder, user_data, container->str_cID,
				content_name, content_size,
				system_metadata_str_esc, actual_stgpol,
				reqid, timeout_cnx, timeout_op, tmp_is_rainx);
	}

	if (local_error != NULL) {
		GRID_WARN("Failed to upload chunks: %s", local_error->message);
		goto error_label;
	}


	/* ------------ *
	 * COMMIT phase *
	 * ------------ */

	// TODO handle error cases occurring in upload_thread
	GRID_DEBUG("whole upload successful");

	/* Pack mdusr into M2V2_PROPERTY beans */
	if(mdusr &&  0 < strlen(mdusr)) {
		struct bean_PROPERTIES_s *bp = _bean_create(&descr_struct_PROPERTIES);
		PROPERTIES_set2_alias(bp, hc_url_get(url, HCURL_PATH));
		PROPERTIES_set_alias_version(bp, (guint64)hc_url_get(url, HCURL_VERSION));
		PROPERTIES_set_key(bp, g_string_new("sys.m2v1_mdusr"));
		PROPERTIES_set_value(bp, g_byte_array_append(g_byte_array_new(),
					(guint8*)g_strdup(mdusr), strlen(mdusr)));
		PROPERTIES_set_deleted(bp, FALSE);
		chunks = g_slist_prepend(chunks, bp);
	}

	/*tries to commit the content*/

	g_static_mutex_lock(&global_mutex);
	if(!append) {
		for (nb_attempts=MAX_ATTEMPTS_COMMIT; (NULL != (local_error = CONTENT_COMMIT())) && nb_attempts>0 ;nb_attempts--) {
			if (local_error && local_error->code==CODE_CONTENT_ONLINE && nb_attempts<MAX_ATTEMPTS_COMMIT) {
				/*this is not an error, but a retry attempt that failed */
				/* we do not clean the error, it might be useful to know something
				 * happened if the whole upload failed */
				break;
			}
			CONTAINER_REFRESH(container,local_error,error_label_unlock,"commit error");
			GRID_DEBUG("FVE: error pointer: %p", local_error);
			if (local_error)
				g_clear_error(&local_error);
		}
	} else {
		for (nb_attempts=MAX_ATTEMPTS_COMMIT; (NULL != (local_error = APPEND_COMMIT())) && nb_attempts>0 ;nb_attempts--) {
			if (local_error && local_error->code==CODE_CONTENT_ONLINE && nb_attempts<MAX_ATTEMPTS_COMMIT) {
				/*this is not an error, but a retry attempt that failed */
				/* we do not clean the error, it might be useful to know something
				 * happened if the whole upload failed */
				break;
			}
			CONTAINER_REFRESH(container,local_error,error_label_unlock,"commit error");
			if (local_error)
				g_clear_error(&local_error);
		}
	}

	content_version = _get_vers_and_update_attr_if_needed(beans, append);

	/* Try to save the chunk in the metacd. In case of failure this is
	 * not an error for the whole upload. */
	if (resolver_metacd_is_up(container->info.gs->metacd_resolver)) {
		struct meta2_raw_content_s *raw_content;
		GError *gerr_metacd = NULL;
		gboolean rc = 0;

		/* Register a fake content */
		raw_content = meta2_maintenance_create_content(C0_ID(container), content_size,
				0, 0, content_name, strlen(content_name));
		if (!raw_content) {
			GSETERROR(&gerr_metacd, "memory allocation failure");
		}
		else {
			raw_content->version = content_version;
			GSList *l;
			for (l = chunks ; l ; l = l->next) {
				chunk_id_t chunk_id;
				struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) l->data;
				struct bean_CONTENTS_s *ct;
				struct meta2_raw_chunk_s *raw_chunk;
				guint64 position;
				gchar *endptr;
				if(DESCR(l->data) != &descr_struct_CHUNKS)
					continue;
				ct = _bean_get_content_from_chunk(chunks, ck);
				if (ct == NULL)
					break;
				fill_chunk_id_from_url(CHUNKS_get_id(ck)->str, &chunk_id);
				position = g_ascii_strtoull(CONTENTS_get_position(ct)->str, &endptr, 10);
				if (endptr != NULL && *endptr != '\0')
					continue; /* found a spare chunk */
				TRACE("Inserting chunk pos=[%"G_GUINT64_FORMAT"] size=[%"G_GINT64_FORMAT"] id=[%s] in metacd...", position, CHUNKS_get_size(ck), CHUNKS_get_id(ck)->str);
				g_assert(CHUNKS_get_hash(ck)->len == sizeof(chunk_hash_t));
				raw_chunk = meta2_maintenance_create_chunk(&chunk_id, CHUNKS_get_hash(ck)->data,
						0x00, CHUNKS_get_size(ck), position);
				meta2_maintenance_add_chunk(raw_content, raw_chunk);
				meta2_raw_chunk_clean(raw_chunk);
			}
			if (l == NULL) { /* all chunks added to meta2_raw_content */
				rc = resolver_metacd_put_content(container->info.gs->metacd_resolver,
						raw_content, &gerr_metacd);
			}
			else {
				GSETERROR(&gerr_metacd, "Not all chunks added to metacd content");
			}
			meta2_maintenance_destroy_content(raw_content);
		}

		if (!rc) {
			GRID_WARN("Failed to save the chunks : %s",
					(gerr_metacd ? gerr_metacd->message : "unknown error"));
		}
		else {
			GRID_DEBUG("Chunks saved in the metacd for [%s/%s/%s]",
					gs_get_full_vns(container->info.gs),
					container->info.name, content_name);
		}
		if (gerr_metacd)
			g_clear_error(&gerr_metacd);
	}
	g_static_mutex_unlock(&global_mutex);
	if (!beans) {
		GSETERROR(&local_error,"CONTENT_COMMIT error : too many attempts");
		goto error_label;
	}

	_bean_cleanl2(beans);

	UPLOAD_CLEAN_MAIN_THREAD();
	UPLOAD_CLEAN();
	return GS_OK;

error_label_unlock:
	g_static_mutex_unlock(&global_mutex);

error_label:

	/* ----------- *
	 * CLEAN phase *
	 * ----------- */

	/*rollback*/
	if ((!local_error) || ((local_error->code != CODE_POLICY_NOT_SATISFIABLE) && (local_error->code != CODE_PLATFORM_ERROR) )) {
	}

	GSERRORCAUSE(err,local_error,"Cannot perform the whole upload");
	UPLOAD_CLEAN_MAIN_THREAD();
	UPLOAD_CLEAN();
	return GS_ERROR;

	g_static_mutex_unlock(&global_mutex);

exit_label:
	GSERRORCAUSE(err,local_error,"Cannot perform the whole upload");
	UPLOAD_CLEAN_MAIN_THREAD();
	return GS_ERROR;
}
