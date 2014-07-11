#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "client.c.rainx"
#endif

// TODO FIXME replace by the GLib equivalent
#include <openssl/md5.h>

#include "./gs_internals.h"

gboolean
stg_pol_is_rainx(namespace_info_t *ni, const gchar *stgpol)
{
	struct storage_policy_s *sp = storage_policy_init(ni, stgpol);
	const struct data_security_s *datasec = storage_policy_get_data_security(sp);
	gboolean ret;
	if (!datasec) {
		GRID_ERROR("Cannot find datasecurity values for policy [%s]", stgpol);
		ret = FALSE;
	} else {
		ret = data_security_get_type(datasec) == RAIN;
	}
	storage_policy_clean(sp);
	return ret;
}

gboolean
stg_pol_rainx_get_param(namespace_info_t *ni, const gchar *stgpol,
		const gchar *param, gint64 *p_val)
{
	const char *val_str = NULL;
	struct storage_policy_s *sp = storage_policy_init(ni, stgpol);
	const struct data_security_s *datasec = storage_policy_get_data_security(sp);
	gboolean ret;

	if (!datasec) {
		GRID_INFO("Cannot find datasecurity values for policy [%s]", stgpol);
		ret = FALSE;
	} else {
		if (NULL == (val_str = data_security_get_param(datasec, param))) {
			GRID_INFO("Cannot get parameter '%s' from data security [%s]",
					param, data_security_get_name(datasec));
			ret = FALSE;
		} else {
			*p_val = g_ascii_strtoll(val_str, NULL, 10);
			ret = TRUE;
		}
	}
	storage_policy_clean(sp);
	return ret;
}

addr_info_t*
get_rainx_from_conscience(const gchar *nsname, GError **error)
{
	struct service_info_s *si = get_one_namespace_service(nsname, "rainx", error);
	if (!si)
		return NULL;
	struct addr_info_s *ai = g_memdup(&(si->addr), sizeof(struct addr_info_s));
	service_info_clean(si);
	return ai;
}

/**
 * Create one webdav session associated to the given chunk.
 */
static ne_session*
rainx_opensession (const addr_info_t *rainx_addr, gs_content_t *hollow_content, GError **err)
{
	ne_session *session = NULL;

	int connect_timeout = MAX(C1_RAWX_TO_CNX(hollow_content)/1000, 1);
	int read_timeout = MAX(C1_RAWX_TO_OP(hollow_content)/1000, 1);

	if (NULL == (session = opensession_common(rainx_addr, connect_timeout, read_timeout, err)))
		return NULL;

	return session;
}

static gchar*
_chunk_to_rawxlist_element(chunk_info_t *chunk_info)
{
	GString *res = g_string_new(NULL);
	char tmpstr[65];

	// output format: ip:port/id
	addr_info_to_string(&(chunk_info->id.addr), tmpstr, sizeof(tmpstr));
	g_string_append(res, tmpstr);
	g_string_append(res, "/");
	buffer2str(chunk_info->id.id, sizeof(chunk_info->id.id), tmpstr, sizeof(tmpstr));
	g_string_append(res, tmpstr);

	return g_string_free(res, FALSE);
}

static gchar*
_chunk_to_sparerawxlist_element(chunk_info_t *chunk_in_error)
{
	GString *res = g_string_new(NULL);
	char tmpstr[33];
	gchar *rawxlist_element = _chunk_to_rawxlist_element(chunk_in_error);

	g_string_append(res, rawxlist_element);
	g_string_append(res, "|");
	g_string_append_printf(res, "%"G_GUINT32_FORMAT, chunk_in_error->position);
	g_string_append(res, "|");
	memset(tmpstr, 0, sizeof(tmpstr));
	buffer2str(chunk_in_error->hash, MD5_DIGEST_LENGTH, tmpstr, sizeof(tmpstr));
	g_string_append(res, tmpstr);
	g_free(rawxlist_element);

	return g_string_free(res, FALSE);
}

static gchar*
create_rawxlist_from_chunk_list(GSList *chunk_list)
{
	GString *res = NULL;

	if (NULL == chunk_list)
		return NULL;

	void _append_to_res(gpointer _chunk_info, gpointer _last_chunk_info)
	{
		chunk_info_t *chunk_info = _chunk_info;
		chunk_info_t *last_chunk_info = _last_chunk_info;
		gchar *rawxlist_element = _chunk_to_rawxlist_element(chunk_info);
		g_string_append(res, rawxlist_element);
		g_free(rawxlist_element);
		if (chunk_info != last_chunk_info)
			g_string_append(res, "|");
	}
	res = g_string_new(NULL);
	g_slist_foreach(chunk_list, _append_to_res, g_slist_last(chunk_list)->data);

	return g_string_free(res, FALSE);
}

static gchar*
create_sparerawxlist_from_chunk_list(GSList *spare_chunks_list)
{
	GString *res = NULL;

	if (NULL == spare_chunks_list)
		return NULL;

	res = g_string_new(NULL);

	void _append_to_res(gpointer _chunk_in_error, gpointer _last_chunk_in_error)
	{
		chunk_info_t *chunk_in_error = _chunk_in_error;
		chunk_info_t *last_chunk_in_error = _last_chunk_in_error;
		gchar *sparerawxlist_element = _chunk_to_sparerawxlist_element(chunk_in_error);
		g_string_append(res, sparerawxlist_element);
		g_free(sparerawxlist_element);
		if (chunk_in_error != last_chunk_in_error)
			g_string_append(res, ";");
	}

	g_slist_foreach(spare_chunks_list, _append_to_res, g_slist_last(spare_chunks_list)->data);

	return g_string_free(res, FALSE);
}

static char*
create_rainx_request_from_chunk_list(ne_request **req, ne_session *session, const char *method,
		GSList *chunk_list, gs_content_t *hollow_content, GByteArray *system_metadata,
		const gchar *storage_policy, guint32 current_metachunk_pos, guint32 current_metachunk_size, GError **err)
{
	gchar *str_req_id;
	gchar *rawxlist_str;
	gs_chunk_t first_chunk;

	if (NULL == chunk_list) {
		GSETERROR(err, "No chunk list given");
		return NULL;
	}

	first_chunk.ci = g_memdup(g_slist_nth_data(chunk_list, 0), sizeof(chunk_info_t));
	first_chunk.content = hollow_content;

	if (NULL == first_chunk.ci) {
		GSETERROR(err, "First chunk info is NULL");
		return NULL;
	}

	first_chunk.ci->position = current_metachunk_pos;
	first_chunk.ci->size = current_metachunk_size;
	memset(&(first_chunk.ci->id.id), 0, sizeof(first_chunk.ci->id.id));
	str_req_id = create_rawx_request_from_chunk(req, session, method, &first_chunk, system_metadata, err);

	if (*req) {
		rawxlist_str = create_rawxlist_from_chunk_list(chunk_list);
		GRID_DEBUG("rawxlist=%s", rawxlist_str);
		ne_print_request_header(*req, "rawxlist", "%s", rawxlist_str);
		ne_add_request_header  (*req, "storagepolicy", storage_policy);
		// TODO: add "namespace" header
		g_free(rawxlist_str);
		g_free(first_chunk.ci);
		return str_req_id;
	}

	g_free(first_chunk.ci);
	g_free(str_req_id);
	return NULL;
}

GSList *
rainx_get_spare_chunks(gs_container_t *container, gchar *content_path, gint64 count,
		gint64 distance, GSList *notin_list, GSList *broken_rawx_list, gs_error_t **err)
{
	GSList *new_spare = NULL;
	GError *local_gerr = NULL;
	gs_container_t *tmp = NULL;
	gchar *notin_str = NULL, *broken_str = NULL;

	if (NULL == container)
		return NULL;

	if(container->meta2_addr.port <= 0) {
		tmp = gs_get_storage_container(container->info.gs, NULL, C0_NAME(container), container->ac, err);
		if(NULL != tmp ) {
			memcpy(&(container->meta2_addr), &(tmp->meta2_addr), sizeof(addr_info_t));
			gs_container_free(tmp);
			return NULL;
		}
	}
	notin_str = create_rawxlist_from_chunk_list(notin_list);
	broken_str = create_rawxlist_from_chunk_list(broken_rawx_list);
	(void) gs_container_reconnect_if_necessary (container,NULL);
	new_spare = meta2_remote_content_spare_in_fd_full(C0_CNX(container), C0_M2TO(container), &local_gerr,
			C0_ID(container), content_path, count, distance, notin_str, broken_str);
	g_free(notin_str);
	g_free(broken_str);
	if (!new_spare) {
		GSERRORCAUSE(err, local_gerr, "Could not get spare chunks");
	}

	g_clear_error(&local_gerr);
	return new_spare;
}

static void
rawx_dl_advance_status(struct dl_status_s *status, size_t s)
{
	int64_t nbW64 = s;
	status->content_dl = status->content_dl + nbW64;
	status->chunk_dl = status->chunk_dl + nbW64;
	status->chunk_dl_offset = status->chunk_dl_offset + nbW64;
	status->chunk_dl_size = status->chunk_dl_size - nbW64;
}

static void
_compute_real_positions(guint pos, gint k, guint *metachunkpos, guint *subchunkpos)
{
	if (metachunkpos)
		*metachunkpos = pos / k;
	if (subchunkpos)
		*subchunkpos = pos % k;
}

static void
_fill_cid_from_bean(chunk_id_t *ci, struct bean_CONTENTS_s *bc)
{
	char *bean_id = CONTENTS_get_chunk_id(bc)->str;
	fill_chunk_id_from_url(bean_id, ci);
}

static GSList*
_convert_filtered(GSList *list)
{
	GSList *res = NULL;

	void _create_chunk_info(gpointer _bean, gpointer _unused)
	{
		struct bean_CONTENTS_s *bean = _bean;
		chunk_info_t *ci;
		(void) _unused;

		if (DESCR(_bean) == &descr_struct_CONTENTS) {
			ci = g_malloc0(sizeof(chunk_info_t));
			_fill_cid_from_bean(&(ci->id), bean);
			gint64 pos64 = g_ascii_strtoll(CONTENTS_get_position(bean)->str, NULL, 10);
			guint32 pos32 = pos64;
			ci->position = pos32;
			res = g_slist_prepend(res, ci);
		}
	}

	g_slist_foreach(list, _create_chunk_info, NULL);
	return g_slist_reverse(res);
}


static void
_update_chunks(GSList *spare_chunks, GHashTable *failed_chunks, guint k)
{
	GSList *l = spare_chunks;

	if (NULL == spare_chunks)
		return;

	void _update_chunk(gpointer _key, gpointer _value, gpointer _udata)
	{
		guint *key = _key, mcp, scp;
		chunk_info_t *value = _value, *spare_ci = NULL;
		(void) _udata;
		if (l && NULL != (spare_ci = l->data)) {
			_compute_real_positions(*key, k, &mcp, &scp);
			spare_ci->position = scp;
			memcpy(&(spare_ci->hash), &(value->hash), sizeof(chunk_hash_t));
			l = l->next;
		}
	}
	g_hash_table_foreach(failed_chunks, _update_chunk, NULL);
}

static void
_get_all_chunks(GSList **p_all_chunks, GSList *agregated_chunks, GSList *filtered,
		guint metachunkpos, guint k, guint m, guint metachunknb, guint *metachunksize)
{
	GSList *all_chunks = NULL, *l;
	guint nb_chunks_found = 0;

	if (metachunksize)
		*metachunksize = 0;

	for (l = agregated_chunks; l; l = l->next) {
		GSList *chunk_list = g_slist_nth_data(l, 0);
		chunk_info_t *ci = g_slist_nth_data(chunk_list, 0);
		guint mcp, scp;
		_compute_real_positions(ci->position, k, &mcp, &scp);
		if (metachunkpos == mcp) {
			ci->nb = metachunknb;
			all_chunks = g_slist_prepend(all_chunks, g_memdup(ci, sizeof(chunk_info_t)));
			*metachunksize += ci->size;
			nb_chunks_found++;
			if (nb_chunks_found == k)
				break;
		}
	}

	nb_chunks_found = 0;

	for (l = filtered; l; l = l->next) {
		chunk_info_t *ci = g_slist_nth_data(l, 0);
		if (metachunkpos == ci->position) {
			ci->nb = metachunknb;
			ci->size = *metachunksize;
			all_chunks = g_slist_prepend(all_chunks, g_memdup(ci, sizeof(chunk_info_t)));
			nb_chunks_found++;
			if (nb_chunks_found == m)
				break;
		}
	}

	*p_all_chunks = g_slist_reverse(all_chunks);
}

static void
_get_valid_chunks(GSList **valid_chunks, GSList *p_all_chunks,
		GHashTable *failed_chunks)
{
	gboolean _chunk_info_equals(gpointer key,
			chunk_info_t *ci1, chunk_info_t *ci2) {
		(void) key;
		return (memcmp((const void *)&(ci1->id), (const void *)&(ci2->id),
				sizeof(chunk_id_t)) == 0);
	}

	GSList *result = NULL;
	for (GSList *l = p_all_chunks; l != NULL; l = l->next) {
		if (g_hash_table_find(failed_chunks, (GHRFunc)_chunk_info_equals,
					l->data) == NULL)
			result = g_slist_prepend(result, l->data);
	}

	*valid_chunks = result;
}

static chunk_position_t
_find_lowest_position(GHashTable *ht)
{
	GList *poslist = g_hash_table_get_keys(ht);
	chunk_position_t ret = G_MAXINT;

	void _find_lowest(gpointer _intval, gpointer _unused)
	{
		chunk_position_t *intval = _intval;
		(void) _unused;
		if (*intval < ret)
			ret = *intval;
	}
	g_list_foreach(poslist, _find_lowest, NULL);
	g_list_free(poslist);

	return ret;
}

static gboolean
_rainx_reconstruct_init(struct dl_status_s *dl_status, gs_content_t *content, GSList *aggregated_chunks,
		GSList **p_all_chunks, GSList **p_spare_chunks, GSList *filtered, GSList *broken_rawx_list, GHashTable *failed_chunks,
		const gchar *storage_policy, guint *p_metachunkpos, guint *p_metachunksize, guint *p_metachunkoffset, guint *p_k,
		gs_error_t **err)
{
	guint metachunkpos, subchunkpos, nbmetachunks, metachunksize;
	chunk_position_t current_pos;
	gint64 count = g_hash_table_size(failed_chunks);
	gint64 distance;
	gint64 k_signed, m_signed;
	guint k = 0, m = 0;
	GSList *converted_filtered = NULL;
	GSList *valid_chunks = NULL;

	if (FALSE == stg_pol_rainx_get_param(&(content->info.container->info.gs->ni), storage_policy, DS_KEY_DISTANCE, &distance))
		distance = 1;

	if (stg_pol_rainx_get_param(&(content->info.container->info.gs->ni), storage_policy, DS_KEY_K, &k_signed))
		k = k_signed;
	else
		return FALSE;

	if (stg_pol_rainx_get_param(&(content->info.container->info.gs->ni), storage_policy, DS_KEY_M, &m_signed))
		m = m_signed;
	else
		return FALSE;


	GSList *first_agreg = g_slist_nth_data(aggregated_chunks, 0);
	chunk_info_t *first_chunk = g_slist_nth_data(first_agreg, 0);
	chunk_size_t subchunksize = first_chunk->size;
	current_pos = _find_lowest_position(failed_chunks);
	_compute_real_positions(current_pos, k, &metachunkpos, &subchunkpos);
	dl_status->last_position--;
	nbmetachunks = g_slist_length(aggregated_chunks) / k;

	converted_filtered = _convert_filtered(filtered);
	_get_all_chunks(p_all_chunks, aggregated_chunks, converted_filtered,
			metachunkpos, k, m, nbmetachunks, &metachunksize);
	_get_valid_chunks(&valid_chunks, *p_all_chunks, failed_chunks);
	g_slist_free_full(converted_filtered, g_free);

	*p_spare_chunks = rainx_get_spare_chunks(content->info.container, content->info.path,
			count, distance, valid_chunks, broken_rawx_list, err);

	g_slist_free(valid_chunks);
	if (NULL == *p_spare_chunks) {
		GRID_ERROR("Cannot get spare chunks.");
		return FALSE;
	}

	_update_chunks(*p_spare_chunks, failed_chunks, k);

	if (p_metachunkoffset)
		*p_metachunkoffset = subchunkpos * subchunksize;
	if (p_metachunkpos)
		*p_metachunkpos = metachunkpos;
	if (p_metachunksize)
		*p_metachunksize = metachunksize;
	if (p_k)
		*p_k = k;

	return TRUE;
}

static chunk_info_t*
_find_chunk_from_hash(GSList *chunks, chunk_hash_t chunk_hash)
{
	GSList *found_l;

	if (NULL == chunk_hash || NULL == chunks)
		return NULL;

	gint _compare_chunk_to_hash(gconstpointer _chunk, gconstpointer _hash)
	{
		const chunk_info_t *chunk = _chunk;
		const guint8 *hash = _hash;
		return memcmp(&(chunk->hash), hash, sizeof(chunk_hash_t));
	}
	if (NULL != (found_l = g_slist_find_custom(chunks, chunk_hash, _compare_chunk_to_hash)))
		return found_l->data;
	return NULL;
}

static void
_change_raw_content_id(meta2_raw_content_t *raw_co, GSList *spare_chunks)
{
	GSList *l;
	chunk_info_t *found_spare = NULL;

	for (l = raw_co->raw_chunks; l; l = l->next) {
		struct meta2_raw_chunk_s *rc = l->data;
		GRID_DEBUG("Got raw chunk position=%"G_GUINT32_FORMAT, rc->position);
		if (NULL != (found_spare = _find_chunk_from_hash(spare_chunks, rc->hash))) {
			memcpy(&(rc->id), &(found_spare->id), sizeof(chunk_id_t));
		}
	}
}

static meta2_raw_content_t*
_create_meta2_raw_content(GSList *beans, gs_content_t *content, guint32 metachunkpos, GSList *spare_chunks)
{
	GSList *beans_at_pos = NULL;
	guint32 current_pos;
	meta2_raw_content_t *new_m2rc = g_malloc0(sizeof(meta2_raw_content_t));
	chunk_info_t *found_spare = NULL;
	chunk_hash_t hash;
	char *subpos = NULL;

	memcpy(&(new_m2rc->container_id), &(content->info.container->cID), sizeof(container_id_t));

	GSList *l;
	for (l = beans; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			// Find beans at wanted metachunk position.
			struct bean_CONTENTS_s *bc = (struct bean_CONTENTS_s *) l->data;
			gint64 pos64 = g_ascii_strtoll(CONTENTS_get_position(bc)->str, NULL, 10);
			current_pos = pos64;
			if (current_pos == metachunkpos) {
				// If position matches, find out whether the hash of the bean
				// is the same as one of the chunk_info in spare_chunks, in
				// which case, keep the bean.
				struct bean_CHUNKS_s *ck = get_chunk_matching_content(beans, bc);
				GByteArray *hash_gba = CHUNKS_get_hash(ck);
				memcpy(hash, hash_gba->data, hash_gba->len);
				if (NULL != (found_spare = _find_chunk_from_hash(spare_chunks, hash))) {
					// Set subchunk position as main position (we already know
					// the metachunk position). Full position will be restored
					// using the prefix in meta2raw_remote_update_chunks.
					subpos = strchr(CONTENTS_get_position(bc)->str, '.');
					subpos++;
					if (*subpos == 'p')
						subpos++;
					// This is usually the case, except when we only have 1
					// subchunk: the parity chunks can then be identical to the
					// data chunk, hence they have the same hash. We can filter
					// out unwanted chunks using the subpos.
					if (g_ascii_strtoull(subpos, NULL, 10) != found_spare->position)
						continue;
					CONTENTS_set2_position(bc, subpos);
					beans_at_pos = g_slist_prepend(beans_at_pos, bc);
					beans_at_pos = g_slist_prepend(beans_at_pos, ck);
				}
			}
		} else if (DESCR(l->data) != &descr_struct_CHUNKS) {
			beans_at_pos = g_slist_prepend(beans_at_pos, l->data);
		}
	}
	map_raw_content_from_beans(new_m2rc, beans_at_pos, NULL, FALSE);
	g_slist_free(beans_at_pos);
	return new_m2rc;
}

static GError *
_commit_reconstruct(gs_content_t *content, GSList *beans, GSList *spare_chunks, guint metachunkpos)
{
	GError *local_gerr = NULL;
	gs_container_t *container = content->info.container;
	char target[64], pos_prefix[32];
	meta2_raw_content_t *raw_co = NULL;
	struct metacnx_ctx_s ctx;
	gboolean ret = FALSE;

	bzero(target, sizeof(target));
	addr_info_to_string(&container->meta2_addr, target, 64);

	metacnx_clear(&ctx);
	if (!metacnx_init_with_url(&ctx, target, &local_gerr))
		goto label_error;
	ctx.timeout.cnx = 30000;
	ctx.timeout.req = 60000;

	if (FALSE == (ret = meta2_remote_container_open(&(ctx.addr), MAX(ctx.timeout.cnx, ctx.timeout.req),
			&local_gerr, container->cID)))
		goto label_error;

	raw_co = _create_meta2_raw_content(beans, content, metachunkpos, spare_chunks);

	/* Delete the old chunk */
	if (FALSE == (ret = meta2raw_remote_delete_chunks(&ctx, &local_gerr, raw_co)))
		goto label_error;

	/* Insert the new chunk */
	_change_raw_content_id(raw_co, spare_chunks);
	bzero(pos_prefix, sizeof(pos_prefix));
	g_snprintf(pos_prefix, sizeof(pos_prefix), "%"G_GUINT32_FORMAT".", metachunkpos);
	if (FALSE == (ret = meta2raw_remote_update_chunks(&ctx, &local_gerr, raw_co, TRUE, pos_prefix)))
		goto label_error;

	g_clear_error(&local_gerr);

label_error:
	if (raw_co)
		meta2_raw_content_clean(raw_co);
	return local_gerr;
}

gboolean rainx_ask_reconstruct(struct dl_status_s *dl_status, gs_content_t *content, GSList *aggregated_chunks,
		GSList *filtered, GSList *beans, GSList *broken_rawx_list, GHashTable *failed_chunks,
		const gchar *storage_policy, gs_error_t **err)
{
	gboolean ret = FALSE;
	ne_session *session = NULL;
	ne_request *request = NULL;
	gchar *str_req_id = NULL;
	gchar *sparerawxlist_str = NULL;
	guint read_bytes = 0;
	GSList *all_chunks = NULL, *spare_chunks = NULL;
	guint metachunkpos, metachunksize, metachunkoffset, k;
	GError *local_error = NULL;
	addr_info_t *rainx_addr = get_rainx_from_conscience(
			gs_get_namespace(content->info.container->info.gs), &local_error);
	if (rainx_addr == NULL) {
		GSERRORCAUSE(err, local_error, "Reconstruct Failed");	
		return FALSE;
	}

	int output_wrapper (void *uData, const char *b, const size_t bSize) {
		size_t offset;

		(void) uData; // offset to be skipped
		if (bSize==0)
			return 0;

		if (read_bytes < metachunkoffset) {
			read_bytes += bSize;
			if (read_bytes < metachunkoffset)
				return 0;
			offset = metachunkoffset - (read_bytes - bSize);
		} else {
			offset = 0;
		}
		if (dl_status->caller_stopped) { /* for looping purposes */
			rawx_dl_advance_status(dl_status, bSize - offset);
			return 0;
		}

		for (; offset < bSize ;) {
			int nbW;

			nbW = dl_status->dl_info.writer(dl_status->dl_info.user_data, b+offset, bSize-offset);
			if (nbW < 0) {
				return -1;
			}
			if (nbW == 0) {
				dl_status->caller_stopped = TRUE;
				rawx_dl_advance_status(dl_status, bSize - offset);
				return 0;
			}

			offset = offset + nbW;
			rawx_dl_advance_status(dl_status, nbW);
		}

		return 0;
	}

	if (rainx_addr) {
		if (NULL == (session = rainx_opensession(rainx_addr, content, &local_error)))
			goto error_label;

		if (FALSE == _rainx_reconstruct_init(dl_status, content, aggregated_chunks,
				&all_chunks, &spare_chunks, filtered, broken_rawx_list, failed_chunks,
				storage_policy, &metachunkpos, &metachunksize, &metachunkoffset, &k, err))
			goto error_label;

		if (NULL == (str_req_id = create_rainx_request_from_chunk_list(&request, session, RAINX_DOWNLOAD,
				all_chunks, content, NULL, storage_policy, metachunkpos, metachunksize, &local_error))) {
			goto error_label;
		}

		if (request) {
			sparerawxlist_str = create_sparerawxlist_from_chunk_list(spare_chunks);
			GRID_DEBUG("sparerawxlist=%s", sparerawxlist_str);
			ne_print_request_header(request, "sparerawxlist", "%s", sparerawxlist_str);
			ne_add_response_body_reader(request, ne_accept_2xx, output_wrapper, dl_status);

			switch (ne_request_dispatch(request)) {
			case NE_OK:
				if (ne_get_status(request)->klass != 2) {
					GSERRORCAUSE(err, local_error, "cannot reconstruct (%s) (ReqId:%s)",
							ne_get_error(session), str_req_id);
					goto error_label;
				}
				DEBUG("reconstruct finished (success)");
				break;
			case NE_AUTH:
			case NE_CONNECT:
			case NE_TIMEOUT:
			case NE_ERROR:
				GSERRORCAUSE(err, local_error, "error from the RAINX WebDAV server (%s) (ReqId:%s)",
						ne_get_error(session), str_req_id);
				goto error_label;
			default:
				GSERRORCAUSE(err, local_error, "unexpected error from the RAINX WebDAV server (%s) (ReqId:%s)",
						ne_get_error(session), str_req_id);
				goto error_label;
			}
		}
	} else {
		return FALSE;
	}

	g_clear_error(&local_error);
	if (NULL == (local_error = _commit_reconstruct(content, beans, spare_chunks, metachunkpos))) {
		GRID_INFO("Commit successful after reconstruct.");
	} else {
		GSERRORCAUSE(err, local_error, "Reconstruct succeeded, but commit failed.");
	}

	ret = TRUE;

error_label:
	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);
	g_slist_free_full(spare_chunks, g_free);
	g_slist_free_full(all_chunks, g_free);
	g_free(sparerawxlist_str);
	g_free(str_req_id);
	g_free(rainx_addr);
	return ret;
}

