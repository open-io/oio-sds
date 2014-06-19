#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.upload"
#endif

#include "./gs_internals.h"

// TODO FIXME replace by the GLib equivalent
#include <openssl/md5.h>

#define MAX_ATTEMPTS_COMMIT 2
#define MAX_ADD_ATTEMPTS 2

#define UPLOAD_CLEAN() do {	/*finish cleaning the structures*/\
	if (spare) g_slist_free (spare);\
	if (chunks) { \
		_bean_cleanl2(chunks); \
	} \
	if (system_metadata)\
		g_byte_array_free(system_metadata, TRUE);\
	if (storage_policy != actual_stgpol)\
		g_free((gpointer)actual_stgpol);\
} while (0)

#define UPLOAD_CLEAN_MAIN_THREAD() do { \
	if (chunks_at_position) { \
		for (iter_chunks = lowest_position; iter_chunks < lowest_position + g_hash_table_size(chunks_at_position); iter_chunks++) { \
			fixed = g_hash_table_lookup(chunks_at_position, &iter_chunks); \
			if (fixed) \
				g_slist_free(fixed); \
		} \
		g_hash_table_destroy(chunks_at_position); \
	} \
	if (rb) { rb_destroy(rb); rb = NULL; } \
	if (committed_counter) g_hash_table_destroy(committed_counter); \
	g_free(uis); \
	g_free(rainx_addr); \
	if (url) { hc_url_clean(url); } \
	if (local_error) { g_error_free(local_error); } \
	g_ptr_array_free(threads_per_copy_number, TRUE); \
	if(orig_sys_metadata_gba) \
		g_byte_array_free(orig_sys_metadata_gba, TRUE); \
} while (0)

static int
get_maximum_spare_chunks (gs_grid_storage_t *gs, guint32 nb_original)
{
	gint64 res64;
	int res;

	(void)nb_original;

	if (!gs) {
		GRID_ERROR("invalid parameter");
		return 0;
	}

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
		gs_input_f feeder, void *user_data, const char *user_metadata, const char *sys_metadata, gs_error_t **err);

/* upload the given chunk from the retry buffer */
gs_status_t gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *stgpol, const char *sys_metadata,
		gs_error_t **err)
{
	return _gs_upload_content_v2(container, content_name, FALSE, content_size, feeder, user_data,
			stgpol, sys_metadata, err);
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

static chunk_position_t
get_lowest_position(GSList *chunks)
{
	chunk_position_t found_position = G_MAXUINT32;
	GSList *l = NULL;
	for(l = chunks; l && l->data; l = l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			struct bean_CONTENTS_s *content = (struct bean_CONTENTS_s *) l->data;
			char *tmp = CONTENTS_get_position(content)->str;
			char **tok = g_strsplit(tmp, ".", 2);
			gint64 pos64 = g_ascii_strtoll(tok[0], NULL, 10);
			guint32 pos = pos64;
			if (pos < found_position) {
				found_position = pos;
			}
			g_strfreev(tok);
		}
	}

	return found_position;
}

static char *
_compute_str_id(chunk_id_t *chunk_id)
{
	char result[256];
	char addr[64];
	char id[65];
	memset(result, '\0', 256);
	memset(addr, '\0', 64);
	memset(id, '\0', 65);

	addr_info_to_string(&(chunk_id->addr), addr, 64);
	buffer2str(chunk_id->id, sizeof(hash_sha256_t), id, 65);
	g_snprintf(result, 256, "http://%s%s/%s", addr, chunk_id->vol, id);
	return g_strdup(result);
}

static void
_update_bean_hash(gpointer chunk, gpointer beans)
{
	GSList * l =(GSList *) beans;
	GSList *b = NULL;
	chunk_info_t *ck = (chunk_info_t*)chunk;
	char *chunk_str_id = _compute_str_id(&(ck->id));

	for(b = l; b && b->data; b = b->next) {
		if(DESCR(b->data) != &descr_struct_CHUNKS)
			continue;
		struct bean_CHUNKS_s *bean = (struct bean_CHUNKS_s *) b->data;
		if(0 == g_ascii_strcasecmp(chunk_str_id, CHUNKS_get_id(bean)->str)) {
			CHUNKS_set2_hash(bean, ck->hash, sizeof(chunk_hash_t));
			break;
		}
	}
	g_free(chunk_str_id);
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

static void
_set_hash_to_beans(GSList *beans, GSList *chunks)
{
	g_slist_foreach(chunks, _update_bean_hash, beans);
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

static void
_fill_cid_from_bean(chunk_info_t *ci, struct bean_CHUNKS_s *ck)
{
	GError *e = NULL; 

	/* split bean id into chunk id part rawx://ip:port/VOL/ID */
	char *bean_id = CHUNKS_get_id(ck)->str;
	char *id = strrchr(bean_id, '/');
	char *addr = strchr(bean_id,':') + 3; /* skip :// */
	char *vol = strchr(addr, '/');

	/* addr */
	char tmp[128];
	memset(tmp, '\0', 128);
	memcpy(tmp, addr, vol - addr);
	if(!l4_address_init_with_url(&(ci->id.addr), tmp, &e)) {
		GRID_WARN("Failed to init chunk addr");
	}

	/* vol */
	memcpy(ci->id.vol, vol, id - vol);

	/* id */
	id = g_ascii_strup(id + 1, strlen(id + 1));
	if(!hex2bin(id, ci->id.id, sizeof(ci->id.id), &e)) {
		GRID_WARN("Failed to convert hexa chunk id to binary");
	}
	g_free(id);

	/* debug: dump id */
	char dst[65];
	bzero(dst, 65);
	container_id_to_string(ci->id.id, dst, 65);

	if(NULL != e)
		g_clear_error(&e);
}

static GSList *
_build_ci_list_from_beans(GSList *chunk_beans, guint32 first, guint32 chunk_count, guint32 *metachunksize)
{
	GSList *result = NULL;
	GSList *l = NULL;
	guint32 pos = first;
	chunk_info_t *first_chunk = NULL;

	for(l = chunk_beans; l && l->data; l = l->next) {
		struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) l->data;
		chunk_info_t *ci = g_malloc0(sizeof(chunk_info_t));	
		_fill_cid_from_bean(ci, ck);
		ci->size = CHUNKS_get_size(ck);
		ci->nb = chunk_count;
		ci->position = pos;
		guint8 *hash = CHUNKS_get_hash(ck)->data;
		memcpy(ci->hash, hash, sizeof(ci->hash));
		result = g_slist_append(result, ci);
		pos++;
	}

	if (metachunksize) {
		if (NULL != (first_chunk = g_slist_nth_data(result, 0))) {
			*metachunksize = first_chunk->size;
		} else {
			*metachunksize = 0;
		}
	}

	return result;
}

static void
_update_spare_chunks_from_beans(GSList *spare_chunks, GSList *beans, guint32 first, guint32 chunk_count, guint32 metachunksize)
{
	GSList *lbeans, *lspare;
	guint32 pos = first;

	for (lbeans = beans, lspare = spare_chunks;
			lbeans && lbeans->data && lspare && lspare->data;
			lbeans = lbeans->next, lspare = lspare->next) {
		struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) lbeans->data;
		chunk_info_t *ci = lspare->data;
		/* Meta2 returns spare chunks with full chunk_size which is not
		   relevent for the last metachunk of the content */
		ci->size = metachunksize;
		ci->nb = chunk_count;
		ci->position = pos++;
		guint8 *hash = CHUNKS_get_hash(ck)->data;
		memcpy(ci->hash, hash, sizeof(ci->hash));
	}
}

struct upload_info_common
{
	GHashTable *committed_counter;
	guint *nb_copies;
	gs_container_t *container;
	GByteArray *system_metadata;
	gs_content_t *hollow_content;
	GSList *spare;
	const char *content_name;
	round_buffer_t *rb;
	GByteArray *user_metadata_gba;
	GByteArray *orig_sys_metadata_gba;
	GMutex *lock;
	GCond *cond;
};

struct upload_info
{
	GSList *chunk_list;
	GSList *confirmed_list;
	const struct upload_info_common *common;
};

static gpointer upload_thread(gpointer data);

/* upload the given chunk from the retry buffer */
static gs_status_t _gs_upload_content (meta2_content_add_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err)
{
	(void) adder;
	return _gs_upload_content_v2(container, content_name, FALSE, content_size, feeder, user_data, NULL, NULL, err);
}

static void
_update_chunks(GSList **p_chunks, GSList *all_confirmed_chunks, guint k)
{
	GSList *confirmed_beans = NULL;

	if (NULL == p_chunks || NULL == *p_chunks || NULL == all_confirmed_chunks)
		return;

	/* Extract content_header bean from original chunks */
	struct bean_CONTENTS_HEADERS_s *content_header = NULL;
	struct bean_ALIASES_s *alias = NULL;
	for (GSList *l = *p_chunks; l && l->data; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			content_header = (struct bean_CONTENTS_HEADERS_s*)l->data;
		else if (DESCR(l->data) == &descr_struct_ALIASES)
			alias = (struct bean_ALIASES_s*)l->data;
	}
	if (content_header == NULL || alias == NULL) {
		WARN("content_header or alias not found in chunk beans");
		return;
	}

	/* Get a list of beans from confirmed chunks */
	confirmed_beans = m2v2_beans_from_chunk_info_list(CONTENTS_HEADERS_get_id(content_header),
			ALIASES_get_alias(alias)->str, all_confirmed_chunks);

	/* Re-introduce header and alias from original chunks */
	guint64 mpos = 0;
	GList *beans_copy = g_list_reverse(g_list_copy((GList*)confirmed_beans));
	for (GList *l = beans_copy; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS ||
				DESCR(l->data) == &descr_struct_ALIASES) {
			confirmed_beans = g_slist_remove(confirmed_beans, l->data);
			_bean_clean(l->data);
			l->data = NULL;
		}
		else if (DESCR(l->data) == &descr_struct_CONTENTS) {
			struct bean_CONTENTS_s *c = (struct bean_CONTENTS_s*)l->data;
			/* Get rain position from bean and deduce metachunk position */
			guint64 rainpos = g_ascii_strtoull(CONTENTS_get_position(c)->str, NULL, 10);
			if (rainpos == 0)
				mpos++;

			char pos[6];
			g_snprintf(pos, sizeof(pos), "%lu.%s%lu", mpos-1, (rainpos > (k-1)) ? "p" : "", rainpos);
			CONTENTS_set2_position(c, pos);
		}
	}
	g_list_free(beans_copy);
	confirmed_beans = g_slist_prepend(confirmed_beans, _bean_dup(content_header));
	confirmed_beans = g_slist_prepend(confirmed_beans, _bean_dup(alias));

	_bean_cleanl2(*p_chunks);
	*p_chunks = confirmed_beans;
}

static gboolean
_upload_to_rainx(addr_info_t *rainx_addr, GHashTable *chunks_at_position,
		chunk_position_t lowest_position, gs_content_t *p_hollow_content,
		gs_input_f input, void *user_data, GByteArray *system_metadata,
		GSList **p_returned_chunk_list, const gchar *storage_policy, gs_error_t **err)
{
	GSList *chunk_list_beans = NULL, *chunk_list_to_send = NULL;
	gboolean upload_successful = FALSE;
	guint iter_chunks = 0, count_chunks, attempt_number, metachunksize;
	gint64 distance;
	GError *local_error = NULL;

	GRID_DEBUG("Starting upload into rainx");

	for (iter_chunks = lowest_position;
			iter_chunks < lowest_position + g_hash_table_size(chunks_at_position);
			iter_chunks++) {
		chunk_list_beans = g_hash_table_lookup(chunks_at_position, &iter_chunks);
		chunk_list_to_send = _build_ci_list_from_beans(chunk_list_beans, lowest_position,
				g_hash_table_size(chunks_at_position), &metachunksize);

		/* Set mark in rb to support upload retry */
		rb_set_mark(user_data);

		upload_successful = rainx_upload(chunk_list_to_send, p_hollow_content,
				rainx_addr, input, user_data, system_metadata, p_returned_chunk_list,
				storage_policy, iter_chunks, metachunksize, &local_error);
		count_chunks = g_slist_length(chunk_list_to_send);
		if (upload_successful) {
			g_slist_free_full(chunk_list_to_send, g_free);
			GRID_DEBUG("chunk list successfully uploaded to rainx (position %u)", iter_chunks);
			continue;
		}

		GRID_WARN("failed to upload chunk list to rainx (position %u): [%s]", iter_chunks, NULL == local_error ? "" : local_error->message);

		if (!stg_pol_rainx_get_param(&(p_hollow_content->info.container->info.gs->ni),
					storage_policy, DS_KEY_DISTANCE, &distance)) {
			distance = 1;
		}

		attempt_number = 0;
		do {
			GSList *spare_chunks = NULL;
			attempt_number++;
			GRID_DEBUG("Retrying upload after getting spare from meta2 (retry#%d)",
					attempt_number);

			/* FVE: The sixth parameter should be the list of RAWX which failed
			 * upload, but rainx_upload func doesn't return it. We could
			 * ban all RAWX of the upload batch but it could lead to a lack
			 * of available RAWX on small platforms. */
			spare_chunks = rainx_get_spare_chunks(
					p_hollow_content->info.container,
					p_hollow_content->info.path,
					count_chunks, distance, NULL, NULL, err);
			if (spare_chunks) {
				_update_spare_chunks_from_beans(spare_chunks, chunk_list_beans, lowest_position,
						g_hash_table_size(chunks_at_position), metachunksize);
				rb_return_to_mark (user_data);
				upload_successful = rainx_upload(spare_chunks, p_hollow_content, rainx_addr,
						input, user_data, system_metadata, p_returned_chunk_list,
						storage_policy, iter_chunks, metachunksize, &local_error);
				g_slist_free_full(spare_chunks, g_free);
				if (upload_successful) {
					GRID_DEBUG("chunk list successfully uploaded to rainx (position %u) (retry#%d)",
							iter_chunks, attempt_number);
					break;
				}
			}
			GRID_WARN("failed to upload chunk list to rainx (position %u): [%s] (retry#%d)",
					iter_chunks, NULL == local_error ? "" : local_error->message, attempt_number);
			g_clear_error(&local_error);
		} while (attempt_number <= MAX_ADD_ATTEMPTS);

		g_slist_free_full(chunk_list_to_send, g_free);

		if (FALSE == upload_successful) {
			GSERRORCAUSE(err, local_error, "All attemps to put content failed (position %u)", iter_chunks);
			break;
		}
	}

	GRID_DEBUG("All (%d) chunks successfully uploaded to rainx.", g_slist_length(*p_returned_chunk_list));
	g_clear_error(&local_error);
	return upload_successful;
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

/* upload the given chunk from the retry buffer */
static gs_status_t _gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *storage_policy, const char *sys_metadata, gs_error_t **err)
{
#define CONTENT_ADD_V2() m2v2_remote_execute_BEANS(target, NULL, url, actual_stgpol, content_size, append, &chunks)
#define CHUNK_COMMIT(chunks) meta2_remote_chunk_commit_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), hollow_content.info.path, chunks)
#define CONTENT_COMMIT() m2v2_remote_execute_PUT(target, NULL, url, chunks, &beans)
#define APPEND_COMMIT() m2v2_remote_execute_APPEND(target, NULL, url, chunks, &beans)
#define CONTENT_ROLLBACK()   meta2_remote_content_rollback_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), hollow_content.info.path)

	int nb_attempts;

	/*parameters declaration and initiation*/
	GError *local_error = NULL;
	gchar pos_str[20];
	GHashTable *chunks_at_position = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	GPtrArray *threads_per_copy_number = g_ptr_array_new();
	gs_content_t hollow_content;
	GByteArray *system_metadata = NULL;
	GByteArray *orig_sys_metadata_gba=NULL;
	guint iter_chunks = 0;
	guint iter_copies = 0;
	GThread *iter_threads = NULL;
	guint nb_copies = 0;
	chunk_position_t lowest_position = 0;
	gpointer chunk_copy = NULL;
	char target[64];
	struct hc_url_s *url = NULL;
	GSList
		*chunks=NULL,           /*free: structure and content*/
		*spare=NULL,            /*free: structure only*/
		*fixed=NULL,            /*free: structure only*/
		*cursor=NULL;           /*do not free*/
	struct upload_info *uis = NULL;
	GHashTable *committed_counter = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, g_free);
	GSList* all_confirmed_chunks = NULL;
	GSList *beans = NULL;
	const gchar *actual_stgpol = storage_policy;

	/*this will keep the source bytes in memory, until each chunk can be comited*/
	round_buffer_t *rb = NULL;
	addr_info_t *rainx_addr = NULL;
	gboolean is_rainx;
	content_version_t content_version;

	if (!g_thread_supported())
		g_thread_init(NULL);

	/*sanity checks*/
	if (!container || !content_name || content_size<0 || !feeder) {
		GSERRORSET(err,"Invalid parameter");
		return GS_ERROR;
	}

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

	/* Pack metadata in gba */

	if(sys_metadata && strlen(sys_metadata) > 0) {
		orig_sys_metadata_gba = g_byte_array_new();
		g_byte_array_append(orig_sys_metadata_gba, (guint8*)sys_metadata, strlen(sys_metadata));
	}

	/*inits the hollow con	tent and the dummy chunk*/
	memset (&hollow_content, 0x00, sizeof(hollow_content));
	hollow_content.info.size = content_size;
	hollow_content.info.container = container;
	memset (hollow_content.info.path, 0x00, sizeof(hollow_content.info.path));
	memcpy (hollow_content.info.path, content_name,
			MIN(strlen(content_name), sizeof(hollow_content.info.path)-1));

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

	lowest_position = get_lowest_position(chunks);
	nb_copies = get_nb_chunks_at_position(chunks, lowest_position);
	uis = (struct upload_info*) g_malloc0(nb_copies * sizeof(struct upload_info));

	/*save the system_metadata_information that will be copied into the last-chunk attributes*/

	/*split the chunks into the spare and used chunks*/
	for (cursor=chunks; cursor && cursor->data ;cursor=cursor->next) {
		/* TODO: search contents item, foreach search chunk item and add it at the good pos */

		if (DESCR(cursor->data) == &descr_struct_CONTENTS_HEADERS) {
			/* Get the actual storage policy selected by meta2 */
			GString *pol_str = CONTENTS_HEADERS_get_policy(cursor->data);
			if (pol_str != NULL) {
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
	is_rainx = (content_size > 0 &&
			stg_pol_is_rainx(&(container->info.gs->ni), actual_stgpol));
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

	/* create a round buffer. it should not store more than the bounded size
	 * of a chunk */
	rb = rb_create_with_callback(CHUNKS_get_size((struct bean_CHUNKS_s*)fixed->data), feeder, user_data);
	if (!rb)
	{
		GSETERROR(&local_error,"Memory allocation failure");
		goto error_label;
	}


	if (GRID_TRACE_ENABLED()) {
		for (iter_chunks = 0; iter_chunks < g_hash_table_size(chunks_at_position); ++iter_chunks) {
			fixed = g_hash_table_lookup(chunks_at_position, &iter_chunks);
			g_snprintf(pos_str, 20, "chunks[pos=%u]:", iter_chunks);
		}
	}


	if (is_rainx) {
		/* Get k for policy */
		gint64 k = 0;
		stg_pol_rainx_get_param(&(hollow_content.info.container->info.gs->ni),
				actual_stgpol, DS_KEY_K, &k);

		rainx_addr = get_rainx_from_conscience(hc_url_get(url, HCURL_NS), &local_error);
		rainx_init_content_hash();
		if (_upload_to_rainx(rainx_addr, chunks_at_position, lowest_position,
				&hollow_content, (gs_input_f)rb_input_from, rb, system_metadata,
				&all_confirmed_chunks, actual_stgpol, err)) {
			_update_chunks(&chunks, all_confirmed_chunks, k);
			_update_content_bean_hash(rainx_finalize_content_hash(), chunks);
		} else {
			goto error_label;
		}
	} else {
		const struct upload_info_common thread_data_common =
		{committed_counter, &nb_copies, container, system_metadata, &hollow_content, spare, content_name, rb, NULL, orig_sys_metadata_gba,
				g_mutex_new(), g_cond_new()};

		for (iter_copies = 0, fixed = NULL; iter_copies < nb_copies; iter_copies++, fixed = NULL) {
			for (iter_chunks = lowest_position; iter_chunks < lowest_position + g_hash_table_size(chunks_at_position); iter_chunks++) {
				chunk_copy = g_slist_nth_data(g_hash_table_lookup(chunks_at_position, &iter_chunks), iter_copies);
				fixed = g_slist_append(fixed, chunk_copy);
			}
			GSList *chunk_list = _build_ci_list_from_beans(fixed, lowest_position, g_slist_length(fixed), NULL);
			g_slist_free(fixed);
			uis[iter_copies].chunk_list = chunk_list;
			uis[iter_copies].common = &thread_data_common;
			if (NULL != (iter_threads = g_thread_create(upload_thread, &uis[iter_copies], TRUE, NULL))) {
				g_ptr_array_add(threads_per_copy_number, iter_threads);
			} else {
				GSETERROR(&local_error,"unable to create upload thread for copy #%u", iter_copies);
				g_mutex_free(thread_data_common.lock);
				g_cond_free(thread_data_common.cond);
				goto error_label;
			}
		}

		for (iter_copies = 0; iter_copies < nb_copies; iter_copies++) {
			if (NULL != (iter_threads = g_ptr_array_index(threads_per_copy_number, iter_copies))) {
				g_thread_join(iter_threads);
			} else {
				GRID_DEBUG("Cannot find thread #%u", iter_copies);
			}
		}

		finalize_content_hash();

		for (iter_copies = 0; iter_copies < nb_copies; iter_copies++) {
			all_confirmed_chunks = g_slist_concat(all_confirmed_chunks, uis[iter_copies].confirmed_list);
			g_slist_free(uis[iter_copies].chunk_list);
		}

		/* set computed hash in our beans */
		_update_content_bean_hash(get_content_hash(), chunks);
		_set_hash_to_beans(chunks, all_confirmed_chunks);
		g_mutex_free(thread_data_common.lock);
		g_cond_free(thread_data_common.cond);
	}
	clean_after_upload(rb);

	/* ------------ *
	 * COMMIT phase *
	 * ------------ */

	// TODO handle error cases occurring in upload_thread
	GRID_DEBUG("whole upload successful");

	/*tries to commit the content*/

	/* TODO : copy hash from chunks_info into chunks bean */

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
			for (l=all_confirmed_chunks; l ;l=l->next) {
				struct chunk_info_s *ci;
				struct meta2_raw_chunk_s *raw_chunk;
				ci = l->data;
				raw_chunk = meta2_maintenance_create_chunk(&(ci->id), ci->hash,
						0x00, ci->size, ci->position);
				meta2_maintenance_add_chunk(raw_content, raw_chunk);
			}
			rc = resolver_metacd_put_content(container->info.gs->metacd_resolver,
					raw_content, &gerr_metacd);
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

	g_slist_free_full (all_confirmed_chunks, g_free);

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
	g_slist_free_full (all_confirmed_chunks, g_free);
	UPLOAD_CLEAN_MAIN_THREAD();
	UPLOAD_CLEAN();
	return GS_ERROR;

	g_static_mutex_unlock(&global_mutex);

exit_label:
	GSERRORCAUSE(err,local_error,"Cannot perform the whole upload");
	UPLOAD_CLEAN_MAIN_THREAD();
	return GS_ERROR;
}

static gpointer
upload_thread(gpointer data)
{
	struct upload_info *ui = data;

	// Locks accesses to committed_counter hash table
	GMutex *committed_counter_lock = ui->common->lock;
	// GCond used to signal threads that they can process next chunk
	GCond *committed_counter_cond = ui->common->cond;

	// The md5 will be computed once
	gboolean compute_md5 = FALSE;

	GHashTable *committed_counter  = ui->common->committed_counter;
	guint *nb_copies               = ui->common->nb_copies;
	gs_container_t *container      = ui->common->container;
	GByteArray *system_metadata    = ui->common->system_metadata;
	gs_content_t hollow_content    = *ui->common->hollow_content;
	GSList *spare                  = ui->common->spare;
	const char *content_name       = ui->common->content_name;
	round_buffer_t *rb             = ui->common->rb;
	GByteArray *user_metadata_gba  = ui->common->user_metadata_gba;
	GByteArray *orig_sys_metadata_gba = ui->common->orig_sys_metadata_gba;

	GSList *fixed = ui->chunk_list;
	GSList *confirmed_chunks = NULL;
	// chunks to free when they are replaced by a spare chunk
	GSList *chunks = NULL;

	int nb_attempts;
	GError *local_error=NULL;
	gchar ci_str[2048];
	int remaining_spare, max_spare;

	GSList *cursor=NULL;           /*do not free*/

	gs_chunk_t dummy_chunk;
	chunk_info_t *dummy_ci = NULL;

	dummy_chunk.ci = NULL;
	dummy_chunk.content = &hollow_content;

	guint count_cursor = 0;
	guint *p_value = NULL;

	/*get the max number of chunks*/
	max_spare = remaining_spare = get_maximum_spare_chunks (container->info.gs, g_slist_length(fixed));

	/* ------------ *
	 * UPLOAD phase *
	 * ------------ */
	for (cursor=fixed; cursor;cursor=cursor->next)
	{
		gboolean upload_successful = FALSE;

		// The committed_counter hash table counts the number of processed chunks for a given
		// chunk position.  When this chunk count is equal to the number of copies asked,
		// all threads can start processing next chunk.
		g_mutex_lock(committed_counter_lock);
		dummy_chunk.ci = (chunk_info_t*) cursor->data;
		p_value = g_hash_table_lookup(committed_counter, GINT_TO_POINTER(count_cursor));
		if (NULL == p_value) {
			p_value = (gpointer) calloc(1, sizeof(guint));
			g_hash_table_insert(committed_counter, GINT_TO_POINTER(count_cursor), p_value);
			compute_md5 = TRUE;
		} else {
			compute_md5 = FALSE;
		}
		g_mutex_unlock(committed_counter_lock);

		chunk_info_to_string(dummy_chunk.ci, ci_str, sizeof(ci_str));

		GRID_TRACE("thread %p: starting upload, compute_md5=%i (chunk#%i)", g_thread_self(), compute_md5, count_cursor);
		upload_successful = rawx_upload_v2 (&dummy_chunk, &local_error, (gs_input_f)rb_input_from, rb, user_metadata_gba, system_metadata, compute_md5);

		if (upload_successful) {
			GRID_TRACE("chunk successfully uploaded (nominal) : %s", ci_str);
		} else {
			chunk_info_t *original_ci = dummy_chunk.ci;
			if (!original_ci) {
				GRID_ERROR("Lost chunk info, cannot retry upload.");
				GSETERROR(&local_error,"Lost chunk info, cannot retry upload.");
				goto error_label;
			}

			/*Write then Get rid of previous errors*/
			GRID_WARN("failed to upload the normal chunk [%s] : %s", ci_str, local_error->message);

			/*stops on the first successfull upload in a spare chunk*/
			while (!upload_successful)
			{
				g_static_mutex_lock(&global_mutex);
				/*try to get more spare chunks of there aren't enough*/
				if (!spare)
				{
					if (remaining_spare<=0) {
						GRID_ERROR("no more spare chunks to retry the upload");
						GSETERROR(&local_error,"no more spare chunks to retry the upload");
						g_static_mutex_unlock(&global_mutex);
						goto error_label;
					} else {
						GSList *newSpare;
						remaining_spare --;
						(void) gs_container_reconnect_if_necessary (container,NULL);
						newSpare = meta2_remote_content_spare_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), content_name);
						if (!newSpare) {
							GRID_ERROR("could not get more spare chunks from the server");
							GSETERROR(&local_error, "could not get more spare chunks from the server");
							g_static_mutex_unlock(&global_mutex);
							goto error_label;
						} else {
							GRID_DEBUG("thread %p: we have a spare chunk", g_thread_self());
							GSList *cL;
							for (cL=newSpare; cL && cL->data ;cL=cL->next) {
								/*keep in mind the chunk will have to be freed...*/
								chunks = g_slist_prepend (chunks, cL->data);
								/*...and prepend it to the spare*/
								spare = g_slist_prepend (spare, cL->data);
							}
							g_slist_free (newSpare);
						}
					}
				}

				/*get the chunk and step to the next*/
				do {
					GSList *old_spare = spare;
					spare = g_slist_remove_link (spare, old_spare);

					/*prepare the spare chunk*/
					dummy_chunk.ci = (chunk_info_t*) old_spare->data;
					dummy_chunk.ci->size = original_ci->size;
					dummy_chunk.ci->position = original_ci->position;
					dummy_chunk.ci->nb = original_ci->nb;
					memcpy(&(dummy_chunk.ci->hash), original_ci->hash, MD5_DIGEST_LENGTH);
					chunk_info_to_string(dummy_chunk.ci, ci_str, sizeof(ci_str));

					g_slist_free_1 (old_spare);
				} while (0);
				g_static_mutex_unlock(&global_mutex);

				/*try to upload*/
				rb_return_to_mark (rb);
				if (rawx_upload_v2 (&dummy_chunk, &local_error,
						(gs_input_f)rb_input_from, rb, user_metadata_gba,
						system_metadata, compute_md5))
				{
					remaining_spare = max_spare;
					GRID_DEBUG("chunk successfully uploaded (spare) : %s", ci_str);
					upload_successful = TRUE;
				}
				else
				{
					/*Write then Get rid of previous errors*/
					GRID_WARN("failed to upload a spare chunk : %s", ci_str);
					GSETERROR(&local_error, "failed to upload a spare chunk : %s", ci_str);
					upload_successful = FALSE;
				}
			}
		}

		g_mutex_lock(committed_counter_lock);
		(*p_value)++;
		dummy_ci = dummy_chunk.ci;
		if (*p_value == *nb_copies) {
			GRID_TRACE("thread %p: all uploads are done for chunk#%i, broadcasting.", g_thread_self(), count_cursor);
			g_cond_broadcast(committed_counter_cond);
		} else {
			GRID_TRACE("thread %p: waiting for all uploads to be done for chunk#%i (%i copies left).",
					g_thread_self(), count_cursor, *nb_copies - *p_value);
			while (*p_value < *nb_copies)
				g_cond_wait(committed_counter_cond, committed_counter_lock);
			GRID_TRACE("thread %p: resuming operations for chunk#%i.", g_thread_self(), count_cursor);
		}
		confirmed_chunks = g_slist_prepend (confirmed_chunks, dummy_ci);
		count_cursor++;
		g_mutex_unlock(committed_counter_lock);
	}

	ui->confirmed_list = confirmed_chunks;

	return NULL;


error_label:
	/* ----------- *
	 * CLEAN phase *
	 * ----------- */
	// Other threads may be waiting for all uploads to be done, which may
	// never occur in case of retry failure.
	g_mutex_lock(committed_counter_lock);
	GRID_DEBUG("thread %p: broadcasting after error.", g_thread_self());
	(*p_value)++;
	g_cond_broadcast(committed_counter_cond);
	g_mutex_unlock(committed_counter_lock);

	// Other threads may be waiting for md5 computing, in which case we need
	// to unlock them.
	if (compute_md5) {
		GRID_DEBUG("thread %p: error uploading chunk, force other threads to continue.", g_thread_self());
		rawx_upload_v2 (NULL, NULL, NULL, NULL, NULL, NULL, -1);
	}

	/*remove remote chunks*/
	for (cursor=confirmed_chunks; cursor ;cursor=cursor->next)
	{
		GError *removeError=NULL;
		gs_chunk_t temp_chunk;
		temp_chunk.ci = (chunk_info_t*) cursor->data;
		temp_chunk.content = &hollow_content;
		if (!rawx_delete (&temp_chunk, &removeError)) {
			GRID_ERROR("Cannot delete a chunk : %s", g_error_get_message(removeError));
		}
		if (removeError)
			g_error_free(removeError);
	}

	/*rollback*/
	if (confirmed_chunks && (!local_error || local_error->code != 481)) {
		g_static_mutex_lock(&global_mutex);
		(void) gs_container_reconnect_if_necessary (container,NULL);
		for (nb_attempts=MAX_ATTEMPTS_ROLLBACK_UPLOAD; !CONTENT_ROLLBACK() && nb_attempts>0 ;nb_attempts--) {
			/*CODE_CONTENT_PRECONDITION -> content online, we cannot do anything*/
			if (local_error && local_error->code==CODE_CONTENT_NOTFOUND && nb_attempts<MAX_ATTEMPTS_ROLLBACK_UPLOAD) {
				/*this is not an error, rollback already succeeded but answer not received*/
				break;
			}
			CONTAINER_REFRESH(container,local_error,exit_label,"rollback error");
		}
		g_static_mutex_unlock(&global_mutex);
	}

	if (spare) g_slist_free (spare);
	if (chunks) {
		g_slist_foreach (chunks, chunk_info_gclean, NULL);
		g_slist_free (chunks);
	}
	if (local_error) g_clear_error(&local_error);
	if (system_metadata) g_byte_array_free(system_metadata, TRUE);

	if (confirmed_chunks)
		g_slist_free (confirmed_chunks);

	return NULL;

exit_label:
	g_static_mutex_unlock(&global_mutex);
	return NULL;
}

