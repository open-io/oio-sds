/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef LOG_DOMAIN
# define LOG_DOMAIN "grid.client.upload"
#endif
#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.client.upload"
#endif

#include "./gs_internals.h"
#include "./round_buffer.h"
#include "./rawx.h"
#include <openssl/md5.h>

#define MAX_ATTEMPTS_COMMIT 2
#define MAX_ADD_ATTEMPTS 2

#define UPLOAD_CLEAN() do {	/*finish cleaning the structures*/\
	if (spare) g_slist_free (spare);\
	if (chunks) { \
		/*g_slist_foreach (chunks, chunk_info_gclean, NULL);*/ \
		/* g_slist_free (chunks);*/ \
		_bean_cleanl2(chunks); \
	} \
	if (local_error) g_clear_error(&local_error);\
	if (system_metadata) g_byte_array_free(system_metadata, TRUE);\
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
	if (uis) { \
		g_mutex_free(uis->common->lock); \
		g_cond_free(uis->common->cond); \
		free(uis); \
	} \
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

typedef GSList* (*meta2_content_add_f) (int fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *system_metadata, GByteArray **new_system_metadata);

typedef GSList* (*meta2_content_add_v2_f) (int fd, gint ms, GError **err, const container_id_t container_id, const gchar *content_path,
	content_length_t content_length, GByteArray *user_metadata, GByteArray *system_metadata, GByteArray **new_system_metadata);

static gs_status_t _gs_upload_content (meta2_content_add_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, gs_error_t **err);

/* static gs_status_t _gs_upload_content_v2 (meta2_content_add_v2_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *user_metadata, const char *sys_metadata, gs_error_t **err); */

static gs_status_t _gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *user_metadata, const char *sys_metadata, gs_error_t **err);

#if 0
static GSList* _meta2_remote_content_append_in_fd_v2(int fd, gint ms, GError **err,
	const container_id_t container_id, const gchar *content_path, content_length_t content_length,
        GByteArray *user_metadata, GByteArray *system_metadata, GByteArray **new_system_metadata)
{
	(void) user_metadata;
	(void) system_metadata;

	return meta2_remote_content_append_in_fd_v2(fd, ms, err, container_id, content_path, content_length, new_system_metadata);
}
#endif

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
_build_ci_list_from_beans(GSList *chunk_beans, guint32 first)
{
	GSList *result = NULL;
	GSList *l = NULL;
	guint32 chunk_count = g_slist_length(chunk_beans);
	guint32 pos = first;
	
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

	return result;
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
	/* GSList* _adder_v2(int _fd, gint _ms, GError **_err, const container_id_t _container_id, const gchar *_content_path,
			content_length_t _content_length, GByteArray *_user_metadata, GByteArray *_system_metadata, GByteArray **_new_system_metadata) {
		(void) _user_metadata;
		return adder(_fd, _ms, _err, _container_id, _content_path, _content_length, _system_metadata, _new_system_metadata);
	} */

	return _gs_upload_content_v2(container, content_name, FALSE, content_size, feeder, user_data, NULL, NULL, err);
}

static GStaticMutex global_mutex = G_STATIC_MUTEX_INIT;

/* upload the given chunk from the retry buffer */
/* static gs_status_t _gs_upload_content_v2 (meta2_content_add_v2_f adder, gs_container_t *container,
		const char *content_name, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *user_metadata, const char *sys_metadata, gs_error_t **err) */
static gs_status_t _gs_upload_content_v2 (gs_container_t *container,
		const char *content_name, gboolean append, const int64_t content_size,
		gs_input_f feeder, void *user_data, const char *storage_policy, const char *sys_metadata, gs_error_t **err)
{
/* #define CONTENT_ADD_V2()        adder (C0_CNX(container), C0_M2TO(container), &local_error,\
	C0_ID(container), hollow_content.info.path, content_size,\
	user_metadata_gba, orig_sys_metadata_gba, &system_metadata) */
#define CONTENT_ADD_V2() 	m2v2_remote_execute_BEANS(target, NULL, url,  storage_policy, content_size, append, &chunks) 
#define CHUNK_COMMIT(chunks) meta2_remote_chunk_commit_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), hollow_content.info.path, chunks)
/* #define CONTENT_COMMIT()     meta2_remote_content_commit_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), hollow_content.info.path) */
#define CONTENT_COMMIT() m2v2_remote_execute_PUT(target, NULL, url, chunks, &beans)
#define APPEND_COMMIT() m2v2_remote_execute_APPEND(target, NULL, url, chunks, &beans)
#define CONTENT_ROLLBACK()   meta2_remote_content_rollback_in_fd (C0_CNX(container), C0_M2TO(container), &local_error, C0_ID(container), hollow_content.info.path)

	int nb_attempts;

	/*parameters declaration and initiation*/
	GError *local_error=NULL;
	gchar pos_str[20];
	GHashTable *chunks_at_position = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, NULL);
	GPtrArray *threads_per_copy_number = g_ptr_array_new();
	gs_content_t hollow_content;
	GByteArray *system_metadata=NULL;
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

	/*this will keep the source bytes in memory, until each chunk can be comited*/
	round_buffer_t *rb = NULL;

	if (!g_thread_supported())
		g_thread_init(NULL);

	/*sanity checks*/
	if (!container || !content_name || content_size<0 || !feeder) {
		GSERRORSET(err,"Invalid parameter");
		return GS_ERROR;
	}

	/* New meta1 purpose : ensure to be linked with a meta2 */
	if(container->meta2_addr.port <= 0) {
		gs_container_t *tmp = NULL;
		tmp = gs_get_storage_container(container->info.gs, NULL, C0_NAME(container), container->ac, err);
		if(NULL != tmp ) {
			memcpy(&(container->meta2_addr), &(tmp->meta2_addr), sizeof(addr_info_t));
			gs_container_free(tmp);
		}
	}

	/* Pack metadata in gba */
//	if(user_metadata && strlen(user_metadata) > 0) {
//		user_metadata_gba = g_byte_array_new();
//		g_byte_array_append(user_metadata_gba, (guint8*)user_metadata, strlen(user_metadata));
//	}

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
	hc_url_set(url, HCURL_NS, container->info.gs->ni.name);
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
	}
	g_static_mutex_unlock(&global_mutex);

	if (!chunks) {
		GSETERROR(&local_error,"PUT error : Too many attempts");
		goto exit_label;
	}

	lowest_position = get_lowest_position(chunks);
	nb_copies = get_nb_chunks_at_position(chunks, lowest_position);
	uis = (struct upload_info*) g_malloc0(nb_copies * sizeof(struct upload_info));

	/*save the system_metadata_information that will be copied into the last-chunk attributes*/

	/*split the chunks into the spare and used chunks*/
	for (cursor=chunks; cursor && cursor->data ;cursor=cursor->next) {
		/* TODO: search contents item, foreach search chunk item and add it at the good pos */	
		if(DESCR(cursor->data) != &descr_struct_CONTENTS) {
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
			fixed = g_slist_prepend(fixed, ck);
			g_hash_table_insert(chunks_at_position, g_memdup(&pos, sizeof(pos)), fixed);
		}
		g_strfreev(tok);
	}


	if (!fixed) {
		GSETERROR(&local_error,"no fixed chunks have been found!");
		goto error_label;
	}

	GRID_DEBUG("'%s' of size %"G_GINT64_FORMAT" split into %u chunks (every chunk is duplicated %u times, there are %u unique presets and %u spares)",
			content_name, content_size, g_slist_length(chunks) / 2 / nb_copies, nb_copies,
			g_hash_table_size(chunks_at_position), g_slist_length(spare));


	/* create a round buffer. it should not store more than the bounded size
	 * of a chunk */
	/* rb = rb_create_with_callback (((chunk_info_t*)(fixed->data))->size, feeder, user_data); */
	rb = rb_create_with_callback (CHUNKS_get_size((struct bean_CHUNKS_s*)fixed->data), feeder, user_data);
	if (!rb)
	{
		GSETERROR(&local_error,"Memory allocation failure");
		goto error_label;
	}

	const struct upload_info_common thread_data_common =
			{committed_counter, &nb_copies, container, system_metadata, &hollow_content, spare, content_name, rb, NULL, orig_sys_metadata_gba,
			g_mutex_new(), g_cond_new()};

	if (GRID_TRACE_ENABLED()) {
		for (iter_chunks = 0; iter_chunks < g_hash_table_size(chunks_at_position); ++iter_chunks) {
			fixed = g_hash_table_lookup(chunks_at_position, &iter_chunks);
			g_snprintf(pos_str, 20, "chunks[pos=%u]:", iter_chunks);
			/*chunk_info_print_all (LOG_DOMAIN, pos_str, fixed);*/
		}
	}

	for (iter_copies = 0, fixed = NULL; iter_copies < nb_copies; iter_copies++, fixed = NULL) {
		for (iter_chunks = lowest_position; iter_chunks < lowest_position + g_hash_table_size(chunks_at_position); iter_chunks++) {
			chunk_copy = g_slist_nth_data(g_hash_table_lookup(chunks_at_position, &iter_chunks), iter_copies);
			fixed = g_slist_append(fixed, chunk_copy);
		}
		GSList *chunk_list = _build_ci_list_from_beans(fixed, lowest_position);
		uis[iter_copies].chunk_list = chunk_list;
		uis[iter_copies].common = &thread_data_common;
		if (NULL != (iter_threads = g_thread_create(upload_thread, &uis[iter_copies], TRUE, NULL))) {
			g_ptr_array_add(threads_per_copy_number, iter_threads);
		} else {
			GSETERROR(&local_error,"unable to create upload thread for copy #%u", iter_copies);
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

	g_ptr_array_free(threads_per_copy_number, TRUE);
	finalize_content_hash();
	clean_after_upload(rb);

	GSList* all_confirmed_chunks = NULL;
	for (iter_copies = 0; iter_copies < nb_copies; iter_copies++) {
		all_confirmed_chunks = g_slist_concat(all_confirmed_chunks, uis[iter_copies].confirmed_list);
	}

	/* set computed hash in our beans */
	_update_content_bean_hash(get_content_hash(), chunks);
	_set_hash_to_beans(chunks, all_confirmed_chunks);

	/* ------------ *
	 * COMMIT phase *
	 * ------------ */

#if 0
	GRID_DEBUG("RAWX upload successful, %u chunks to commit", g_slist_length(all_confirmed_chunks));

	g_static_mutex_lock(&global_mutex);
	/*tries to commit the chunks*/
	for (nb_attempts=2; !(done=CHUNK_COMMIT(all_confirmed_chunks)) && nb_attempts>0 ;nb_attempts--) {
		CONTAINER_REFRESH(container,local_error,error_label_unlock,"chunk commit error");
	}
	if (!done) {
		GSETERROR(&local_error,"CHUNK_COMMIT error : too many attempts");
		goto error_label_unlock;
	}

	GRID_DEBUG("chunk commit successful, ready to commit the content");
#endif

	// TODO handle error cases occurring in upload_thread
	GRID_DEBUG("whole upload successful");

	/*tries to commit the content*/
	GSList *beans = NULL;

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
		}
	}


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
			gs_error_t *reloadErr = NULL;
			// ask a reload to retrieve content version
			if(!gs_content_reload(&hollow_content, TRUE, FALSE, &reloadErr)) {
				g_printerr("Failed to get content informations from meta2 : (%s)\n", gs_error_get_message(reloadErr));
				gs_error_free(reloadErr);
			}
			raw_content->version = g_ascii_strtoll(hollow_content.version, NULL, 10);
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
					container->info.gs->ni.name, container->info.name, content_name);
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

	if(NULL != url)
		hc_url_clean(url);

	g_slist_free (all_confirmed_chunks);
	for (iter_copies = 0; iter_copies < nb_copies; iter_copies++)
		g_slist_free(uis[iter_copies].chunk_list);

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

#if 0
		g_static_mutex_lock(&global_mutex);
		(void) gs_container_reconnect_if_necessary (container,NULL);
		for (nb_attempts=MAX_ATTEMPTS_ROLLBACK_UPLOAD; !CONTENT_ROLLBACK() && nb_attempts>0 ;nb_attempts--) {
			/*CODE_CONTENT_PRECONDITION -> content online, we cannot do anything*/
			if (local_error && local_error->code==CODE_CONTENT_NOTFOUND && nb_attempts<MAX_ATTEMPTS_ROLLBACK_UPLOAD) {
				/*this is not an error, rollback already succeeded but answer not received*/
				break;
			}
			CONTAINER_REFRESH(container,local_error,exit_label_unlock,"rollback error");
		}
		g_static_mutex_unlock(&global_mutex);
#endif 
	}

	GSERRORCAUSE(err,local_error,"Cannot perform the whole upload");
	if(NULL != url)
		hc_url_clean(url);
	UPLOAD_CLEAN_MAIN_THREAD();
	UPLOAD_CLEAN();
	return GS_ERROR;

//exit_label_unlock:
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

	GHashTable *committed_counter 	= ui->common->committed_counter;
	guint *nb_copies 				= ui->common->nb_copies;
	gs_container_t *container 		= ui->common->container;
	GByteArray *system_metadata 	= ui->common->system_metadata;
	gs_content_t hollow_content 	= *ui->common->hollow_content;
	GSList *spare					= ui->common->spare;
	const char *content_name 		= ui->common->content_name;
	round_buffer_t *rb 				= ui->common->rb;
	GByteArray *user_metadata_gba 	= ui->common->user_metadata_gba;
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
			GRID_TRACE("chunk successfully uploaded (nomminal) : %s", ci_str);
		} else {
			chunk_info_t *original_ci = dummy_chunk.ci;
			if (!original_ci) {
				GRID_ERROR("Lost chunk info, cannot retry upload.");
				GSETERROR(&local_error,"Lost chunk info, cannot retry upload.");
				goto error_label;
			}

			/*Write then Get rid of previous errors*/
			GRID_WARN("failed to upload the normal chunk [%s] : %s", ci_str, local_error->message);
			//GSETERROR(&local_error, "failed to upload the normal chunk : %s", ci_str);

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
				if (rawx_upload_v2 (&dummy_chunk, &local_error, (gs_input_f)rb_input_from, rb, user_metadata_gba, orig_sys_metadata_gba, compute_md5))
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

	//UPLOAD_CLEAN();
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
	/*GSERRORCAUSE(err,local_error,"Cannot perform the whole upload");*/
	return NULL;
}

