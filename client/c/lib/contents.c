/*
OpenIO SDS client
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include "./gs_internals.h"
#include "hc.h"

static void
chunk_agregate_debug(GSList *agregates)
{
	GSList *ag;
	GSList *chunks, *c;
	chunk_info_t *ci;
	gint i_ag=0, i_chunk=0;

	if (!TRACE_ENABLED())
		return;

	for (i_ag=0, ag=agregates ; ag ; ag=ag->next,i_ag++) {

		chunks = ag->data;
		ci = chunks->data;

		if (!(chunks = ag->data))
			TRACE("ag-%d : NULL", i_ag);
		else {
			TRACE("ag-%d : %u elements", i_ag, g_slist_length(chunks));

			for (i_chunk=0, c=chunks; c ; c=c->next, i_chunk++) {

				if (!(ci = c->data)) {
					TRACE(" chunk-%d-%d : NULL", i_ag, i_chunk);
				}
				else {
					TRACE(" chunk-%d-%d :  %s", i_ag, i_chunk, ci->id.vol);
				}
			}
		}
	}
}

static gboolean
chunk_agregates_check_sizes(GSList *agregates, gs_error_t **gserr)
{
	GSList *ag;
	GSList *chunks, *c;
	chunk_info_t *ci;
	chunk_size_t size_first;
	chunk_position_t position_first;

	for (ag=agregates ; ag ; ag=ag->next) {

		chunks = ag->data;
		ci = chunks->data;
		size_first = ci ? ci->size : 0;
		position_first = ci ? ci->position : 0;

		for (c=chunks; c; c=c->next) {
			if (size_first != ci->size) {
				GSERRORSET(gserr, "Size mismatch");
				return GS_ERROR;
			}
			if (position_first != ci->position) {
				GSERRORSET(gserr, "Position mismatch");
				return GS_ERROR;
			}
		}
	}

	return GS_OK;
}

static gboolean
chunk_agregates_check_sequence(GSList *agregates, gs_error_t **gserr)
{
	GSList *ag, *chunks;
	chunk_info_t *ci;
	gboolean first_met;
	chunk_position_t position_last;

	position_last = -1;
	first_met = FALSE;

	for (ag=agregates ; ag ; ag=ag->next) {

		chunks = ag->data;
		ci = chunks->data;

		if (!first_met) {
			if (ci->position != 0) {
				GSERRORSET(gserr, "Invalid first chunk's position");
				return GS_ERROR;
			}
			position_last = ci->position;
			first_met = TRUE;
		}
		else {
			if (position_last+1 != ci->position) {
				GSERRORSET(gserr, "Position sequence mismatch");
				return GS_ERROR;
			}
			position_last = ci->position;
		}

	}
	return GS_OK;
}

static gboolean
chunk_agregates_check_nulls(GSList *agregates, gs_error_t **gserr)
{
	GSList *ag, *c;

	for (ag=agregates ; ag ; ag=ag->next) {
		if (!ag->data) {
			GSERRORSET(gserr, "NULL agregate");
			return GS_ERROR;
		}

		for (c=(GSList*)ag->data; c; c=c->next) {
			if (!c->data) {
				GSERRORSET(gserr, "NULL chunk");
				return GS_ERROR;
			}
		}
	}
	return GS_OK;
}

gs_status_t
gs_check_chunk_agregate (GSList *agregate, gs_error_t **gserr)
{
	chunk_agregate_debug(agregate);

	if (!chunk_agregates_check_nulls(agregate, gserr)) {
		GSERRORSET(gserr, "Insane agregates");
		return GS_ERROR;
	}

	if (!chunk_agregates_check_sizes(agregate, gserr)) {
		GSERRORSET(gserr, "Agregate content error");
		return GS_ERROR;
	}

	if (!chunk_agregates_check_sequence(agregate, gserr)) {
		GSERRORSET(gserr, "Agregates sequence error");
		return GS_ERROR;
	}

	return GS_OK;
}

static GByteArray*
_gba_dup(GByteArray *gba)
{
	if (!gba)
		return g_byte_array_append(g_byte_array_sized_new(1), (guint8*)"", 1);
	return g_byte_array_append(g_byte_array_new(), gba->data, gba->len);
}

static void
_free_content_internals(gs_content_t *content)
{
	if (content->gba_sysmd)
		g_byte_array_unref(content->gba_sysmd);
	if (content->gba_md)
		g_byte_array_unref(content->gba_md);
	if (content->chunk_list) {

		TRACE("Freeing %u old chunks in [grid://%s/%s/%s]", g_slist_length(content->chunk_list),
				gs_get_full_vns(content->info.container->info.gs), C1_IDSTR(content), C1_PATH(content));

		g_slist_foreach (content->chunk_list, chunk_info_gclean, NULL);
		g_slist_free (content->chunk_list);
	}
	g_free(content->version);
	g_free(content->policy);

	content->gba_sysmd = NULL;
	content->gba_md = NULL;
	content->chunk_list = NULL;
	content->version = NULL;
}

struct hc_url_s *
fill_hcurl_from_content2 (gs_container_t *container, const char *path)
{
	struct hc_url_s *url = fill_hcurl_from_container (container);
	hc_url_set(url, HCURL_PATH, path);
	g_assert (hc_url_has_fq_path (url));
	return url;
}

struct hc_url_s *
fill_hcurl_from_content (gs_content_t *content)
{
	struct hc_url_s *url = fill_hcurl_from_content2 (content->info.container, C1_PATH(content));
	if (content->version)
		hc_url_set(url, HCURL_VERSION, content->version);
	return url;
}

void
fill_chunk_id_from_url(const char * const url, chunk_id_t *ci)
{
	GError *e = NULL;

	/* rawx://ip:port/VOL/ID */
	char *id = strrchr(url, '/');
	char *addr = strchr(url,':') + 3; /* skip :// */
	char *vol = strchr(addr, '/');

	/* addr */
	char tmp[128];
	memset(tmp, '\0', 128);
	memcpy(tmp, addr, vol - addr);
	if(!l4_address_init_with_url(&(ci->addr), tmp, &e)) {
		GRID_WARN("Failed to init chunk addr");
	}

	/* vol */
	g_strlcpy(ci->vol, vol, MIN(id - vol + 1 /* for '\0' */, (int)sizeof(ci->vol)));

	/* id */
	container_id_hex2bin(id + 1 , strlen(id +1 ), &(ci->id), NULL);

	/* debug: dump id */
	char dst[65];
	bzero(dst, 65);
	container_id_to_string(ci->id, dst, 65);

	if(NULL != e)
		g_clear_error(&e);
}

static void
_fill_cid_from_bean(struct meta2_raw_chunk_s *ci, gpointer bean)
{
	/* split bean id into chunk id part rawx://ip:port/VOL/ID */
	char *bean_id = NULL;
	if (DESCR(bean) == &descr_struct_CHUNKS)
		bean_id = CHUNKS_get_id((struct bean_CHUNKS_s *) bean)->str;
	else if (DESCR(bean) == &descr_struct_CONTENTS)
		bean_id = CONTENTS_get_chunk_id((struct bean_CONTENTS_s *) bean)->str;
	else
		return;

	fill_chunk_id_from_url(bean_id, &(ci->id));
}

struct bean_CHUNKS_s *
get_chunk_matching_content(GSList *beans, struct bean_CONTENTS_s *content)
{
	GSList *l = NULL;
	/*split the chunks into the spare and used chunks*/
	char *cid1 = CONTENTS_get_chunk_id(content)->str;
	GRID_DEBUG("Looking for chunk id %s", cid1);
	for (l = beans; l && l->data ; l=l->next) {
		if(DESCR(l->data) != &descr_struct_CHUNKS)
			continue;
		struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) l->data;
		char *cid2 = CHUNKS_get_id(ck)->str;
		GRID_DEBUG("--> %s", cid2);
		if(0 == g_ascii_strcasecmp(cid1, cid2)) {
			return ck;
		}
	}

	return NULL;
}

static GSList*
_filter_and_sort(GSList *chunk_list, GSList **p_filtered)
{
	GSList *contents_list = NULL, *non_contents_list = NULL;

	void _filter_parity_chunk(gpointer _bean, gpointer _unused)
	{
		struct bean_CONTENTS_s *bean = _bean;
		char *pos_str = NULL;
		(void) _unused;

		if (DESCR(_bean) == &descr_struct_CONTENTS) {
			pos_str = CONTENTS_get_position(bean)->str;
			if (NULL == strchr(pos_str, 'p')) {
				contents_list = g_slist_prepend(contents_list, _bean);
			} else {
				if (p_filtered)
					*p_filtered = g_slist_prepend(*p_filtered, _bean);
			}
		} else {
			non_contents_list = g_slist_prepend(non_contents_list, _bean);
		}
	}

	gint _contents_cmp(gconstpointer _bean1, gconstpointer _bean2)
	{
		gint mainpos1, mainpos2, secondpos1, secondpos2;
		gboolean par1, par2;

		m2v2_parse_chunk_position(CONTENTS_get_position((struct bean_CONTENTS_s *)_bean1)->str,
				&mainpos1, &par1, &secondpos1);
		m2v2_parse_chunk_position(CONTENTS_get_position((struct bean_CONTENTS_s *)_bean2)->str,
				&mainpos2, &par2, &secondpos2);

		if (mainpos1 == mainpos2) {
			return memcmp(&secondpos1, &secondpos2, sizeof(gint));
		}
		return memcmp(&mainpos1, &mainpos2, sizeof(gint));
	}

	// Create contents_list containing all CONTENTS beans without those corresponding to parity chunks,
	// and non_contents_list containing all non-CONTENTS beans.
	g_slist_foreach(chunk_list, _filter_parity_chunk, NULL);

	// Sort the contents_list according to chunk position.
	contents_list = g_slist_sort(contents_list, _contents_cmp);
	if (p_filtered)
		*p_filtered = g_slist_sort(*p_filtered, _contents_cmp);

	// Create a new list containing all non-CONTENTS beans, followed by all CONTENTS beans sorted by position.
	non_contents_list = g_slist_concat(non_contents_list, contents_list);

	return non_contents_list;
}

static gboolean
_has_dotted_position(GSList *beans)
{
	GSList *l = beans;
	gchar * pos = NULL;

	for (; l && l->data; l = l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			pos = CONTENTS_get_position((struct bean_CONTENTS_s *)l->data)->str;
			return NULL != strchr(pos, '.');
		}
	}
	return FALSE;
}

gboolean
map_raw_content_from_beans(struct meta2_raw_content_s *raw_content, GSList *beans, GSList **p_filtered, gboolean force_keep_position)
{
	GSList *l = NULL, *l_begining = NULL;

	gint maxpos = -1, pos = 0;
	gboolean rain_style_pos;

	rain_style_pos = _has_dotted_position(beans);
	if (rain_style_pos)
		l = _filter_and_sort(beans, p_filtered);
	else
		l = beans;

	l_begining = l;

	/* read all beans and extract info */
	for (; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			struct bean_CONTENTS_s *bc = (struct bean_CONTENTS_s *) l->data;
			struct bean_CHUNKS_s *ck = get_chunk_matching_content(beans, bc);
			struct meta2_raw_chunk_s *ci = g_malloc0(sizeof(struct meta2_raw_chunk_s));
			_fill_cid_from_bean(ci, ck);
			ci->size = CHUNKS_get_size(ck);
			if (rain_style_pos && !force_keep_position) {
				ci->position = pos++;
			} else {
				gint64 pos64 = g_ascii_strtoll(CONTENTS_get_position(bc)->str, NULL, 10);
				guint32 pos32 = pos64;
				ci->position = pos32;
			}
			guint8 *hash = CHUNKS_get_hash(ck)->data;
			memcpy(ci->hash, hash, sizeof(ci->hash));
			raw_content->raw_chunks = g_slist_prepend(raw_content->raw_chunks, ci);
			if ( pos > maxpos )
				maxpos = pos;
		}
		else if(DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			raw_content->size = CONTENTS_HEADERS_get_size(l->data);
			raw_content->storage_policy = strdup(CONTENTS_HEADERS_get_policy(l->data)->str);
		}
		else if(DESCR(l->data) == &descr_struct_ALIASES) {
			char *mdsys = ALIASES_get_mdsys(l->data)->str;
			g_strlcpy(raw_content->path, ALIASES_get_alias(l->data)->str, sizeof(raw_content->path));
			raw_content->version = ALIASES_get_version(l->data);
			raw_content->system_metadata = g_byte_array_append(g_byte_array_new(), (const guint8*)mdsys, strlen(mdsys));
			raw_content->deleted = ALIASES_get_deleted(l->data);
		}
	}
	raw_content->nb_chunks = maxpos +1;

	if (l_begining != beans)
		g_slist_free(l_begining);

	return TRUE;
}

gboolean
map_properties_from_beans(GSList **properties, GSList *beans)
{
	GSList *l = NULL;

	for (l=beans; l && l->data; l=l->next) {
		if (DESCR(l->data) == &descr_struct_PROPERTIES) {
			struct bean_PROPERTIES_s *bp = (struct bean_PROPERTIES_s *)l->data;
			meta2_property_t *prop = g_malloc0(sizeof(meta2_property_t));

			prop->name = g_strdup(PROPERTIES_get_key(bp)->str);
			prop->version = PROPERTIES_get_alias_version(bp);
			GByteArray *value = PROPERTIES_get_value(bp);
			prop->value = g_byte_array_sized_new (value->len);
			g_byte_array_append (prop->value, value->data, value->len);

			*properties = g_slist_prepend(*properties,prop);

		}
	}
	return TRUE;
}

gboolean
map_policy_from_beans(gchar **policy, GSList *beans)
{
	GSList *l = NULL;

	for (l=beans; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			struct bean_CONTENTS_HEADERS_s *bch = (struct bean_CONTENTS_HEADERS_s *) l->data;
			*policy = g_strdup(CONTENTS_HEADERS_get_policy(bch)->str);
			return TRUE;
		}
	}
	return FALSE;
}

void
map_content_from_raw(gs_content_t *content, struct meta2_raw_content_s *raw_content)
{
	GSList *l;
	struct meta2_raw_chunk_s *raw_chunk;
	struct chunk_info_s chunk;

	_free_content_internals(content);

	content->gba_sysmd = _gba_dup(raw_content->system_metadata);

	content->gba_md = _gba_dup(raw_content->metadata);

	content->policy = g_strdup(raw_content->storage_policy);

	for (l=raw_content->raw_chunks; l ; l=l->next) {
		raw_chunk = l->data;
		if (!raw_chunk->flags) {
			memset(&chunk, 0x00, sizeof(chunk));
			memcpy(&(chunk.id), &(raw_chunk->id), sizeof(chunk_id_t));
			memcpy(&(chunk.hash), &(raw_chunk->hash), sizeof(chunk_hash_t));
			chunk.position = raw_chunk->position;
			chunk.size = raw_chunk->size;
			chunk.nb = raw_content->nb_chunks;
			content->chunk_list = g_slist_prepend(content->chunk_list, g_memdup(&chunk, sizeof(chunk_info_t)));
		}
	}

	char tmp[64];
	memset(tmp, '\0', 64);
	g_snprintf(tmp, 64, "%"G_GINT64_FORMAT, raw_content->version);
	content->version = g_strdup(tmp);
	content->info.size = raw_content->size;
	content->deleted = raw_content->deleted;
}

static void
g_strfreev2(gchar ***v)
{
	if (v && *v) {
		g_strfreev(*v);
		*v = NULL;
	}
}

gboolean
gs_relink_container(gs_container_t *container, GError **err)
{
	gboolean link_needed = FALSE;
	gchar **tmp = NULL;
	gs_error_t *e;
	gboolean rc;

	e = hc_list_reference_services(container->info.gs, C0_NAME(container),
			"meta2", &tmp);
	if (e) {
		GSETCODE(err, e->code, "%s", e->msg);
		gs_error_free(e);
		return FALSE;
	}

	if (!tmp || !*tmp) {
		link_needed = TRUE;
		g_strfreev2(&tmp);
		e = hc_link_service_to_reference(container->info.gs, C0_NAME(container),
				"meta2", &tmp);
		if (e) {
			GSETCODE(err, e->code, "%s", e->msg);
			gs_error_free(e);
			return FALSE;
		}
	}

	if (!tmp || !*tmp) {
		GSETERROR(err, "No service provided by link function,"
				" failed to get a meta1");
		g_strfreev2(&tmp);
		return FALSE;
	}

	do {
		struct meta1_service_url_s *url = meta1_unpack_url(*tmp);
		rc = l4_address_init_with_url(&(container->meta2_addr), url->host, err);
		g_strfreev2(&tmp);
		g_free(url);
	} while (0);

	/* Now create the meta2 entry */
	if (rc && link_needed) {
		struct hc_url_s *url = fill_hcurl_from_container (container);
		rc = meta2_remote_container_create_v3(&(container->meta2_addr), 3000, err, url, NULL);
		hc_url_pclean (&url);
		if (!rc) { /* don't take care of 433 code */
			if ((*err)->code != CODE_CONTAINER_EXISTS)
				return FALSE;
			g_clear_error(err);
		}
	}

	return TRUE;
}

gboolean
gs_reload_container(gs_container_t *container, GError **err)
{
	struct hc_url_s *url = fill_hcurl_from_container (container);
	GSList *meta2 = gs_resolve_meta2(container->info.gs, url, err);
	hc_url_pclean (&url);

	if (!meta2) {
		GSETERROR(err,"Resolution error for NAME=[%s] ID=[%s]", C0_NAME(container), C0_IDSTR(container));
		return FALSE;
	}

	memcpy(&(container->meta2_addr), meta2->data, sizeof(addr_info_t));
	g_slist_foreach (meta2, addr_info_gclean, NULL);
	g_slist_free (meta2);
	return TRUE;
}

static gboolean
_reload_content(gs_content_t *content, GSList **p_filtered, GSList **p_beans, GError **err)
{
	struct meta2_raw_content_s *raw_content;

	if (C1_C0(content)->meta2_addr.port <= 0 &&
			!gs_reload_container(C1_C0(content), err)) {
		GSETERROR(err, "Container resolution error");
		return FALSE;
	}

	char target[64];
	guint32 flags = 0;
	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url = fill_hcurl_from_content (content);
	if (!content->version) {
		flags |= M2V2_FLAG_NODELETED;
	} else if (g_ascii_strcasecmp(content->version, HCURL_LATEST_VERSION) != 0) {
		hc_url_set(url, HCURL_VERSION, content->version);
	} else {
		/* Do not set M2V2_FLAG_NODELETED but do not specify version,
		 * so we get the latest, even if it's marked deleted. */
	}

	GSList *beans = NULL;
	*err = m2v2_remote_execute_GET(target, url, flags, &beans);
	hc_url_pclean(&url);

	if (NULL != *err) {
		GSETERROR(err, "Failed to get content");
		return FALSE;
	}

	raw_content = g_malloc0(sizeof(struct meta2_raw_content_s));
	if (!map_raw_content_from_beans(raw_content, beans, p_filtered, FALSE)) {
		/* content deleted */
		_bean_cleanl2(beans);
		GSETCODE(err, CODE_CONTENT_NOTFOUND, "Content deleted");
		return FALSE;
	}

	map_content_from_raw(content, raw_content);
	meta2_raw_content_clean(raw_content);
	if (p_beans)
		*p_beans = beans;
	else
		_bean_cleanl2(beans);

	TRACE("Content [grid://%s/%s/%s] reloaded (%u chunks)",
		gs_get_full_vns(content->info.container->info.gs), C1_IDSTR(content), C1_PATH(content),
		g_slist_length(content->chunk_list));

	return TRUE;
}

gboolean
gs_content_reload (gs_content_t *content, gs_error_t **err)
{
	return gs_content_reload_with_filtered(content, NULL, NULL, err);
}

gboolean
gs_content_reload_with_filtered (gs_content_t *content, GSList **p_filtered,
		GSList **p_beans, gs_error_t **err)
{
	gboolean rc = FALSE;
	GError *localError=NULL;

	/*santy checks and cleanings*/
	if (!content) {
		GSERRORSET(err, "Invalid argument");
		return FALSE;
	}
	if (content->chunk_list) {
		g_slist_foreach(content->chunk_list, chunk_info_gclean, NULL);
		g_slist_free(content->chunk_list);
		content->chunk_list = NULL;
	}
	if (p_filtered && *p_filtered) {
		g_slist_foreach(*p_filtered, meta2_raw_chunk_gclean, NULL);
		g_slist_free(*p_filtered);
		*p_filtered = NULL;
	}

	/* Try with the META2 */
	for (int nb_refreshes = 1; nb_refreshes >= 0; nb_refreshes--) {
		if (!_reload_content(content, p_filtered, p_beans, &localError)) {
			if (localError->code == CODE_CONTAINER_NOTFOUND) {
				gs_container_t *container = content->info.container;
				CONTAINER_REFRESH(container, localError, end_label,
						"cannot delete content");
			} else {
				GSERRORSET(err, "Content not found");
				goto end_label;
			}
			if (localError)
				g_clear_error(&localError);
		} else {
			break;
		}
	}

	return 1;

end_label:
	_free_content_internals(content);
	if (!localError)
		GSETERROR(&localError,"unknow error");
	GSERRORCAUSE(err, localError, "Cannot reload %s", C1_PATH(content));
	g_clear_error(&localError);
	return rc;
}

gs_status_t
gs_destroy_content (gs_content_t *content, gs_error_t **err)
{
	char target[64];
	GError *localError=NULL;
	int nb_refreshes=1;

	if (!content) {
		GSERRORSET (err, "Invalid parameter");
		return GS_ERROR;
	}

	(void) gs_container_reconnect_if_necessary (C1_C0(content),NULL);

	memset(target, '\0', 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, gs_get_full_vns(C1_C0(content)->info.gs));
	hc_url_set(url, HCURL_HEXID, C0_IDSTR(C1_C0(content)));
	//hc_url_set(url, HCURL_REFERENCE, C0_NAME(C1_C0(content)));
	hc_url_set(url, HCURL_PATH, C1_PATH(content));
	if (content->version) {
		hc_url_set(url, HCURL_VERSION, content->version);
	}

	for (nb_refreshes = 2; nb_refreshes > 0; nb_refreshes--) {
		if (localError)
			g_clear_error(&localError);
		localError = m2v2_remote_execute_DEL(target, url);
		if (!localError)
			break;
		if (NULL != localError) {
			if (localError->code==CODE_CONTENT_NOTFOUND && nb_refreshes<2)
				break;
			CONTAINER_REFRESH(C1_C0(content),localError,end_label,C1_PATH(content));
		}
	}
	hc_url_pclean(&url);

end_label:
	if (localError) {
		GSERRORCAUSE(err, localError, "Removal failed");
		g_clear_error(&localError);
		return GS_ERROR;
	}
	return GS_OK;
}

gs_status_t gs_content_get_info (const gs_content_t *content, gs_content_info_t *info, gs_error_t **err)
{
	if (!content || !info)
	{
		GSERRORSET(err,"Invalid parameter");
		return GS_ERROR;
	}

	memcpy (info, &(content->info), sizeof(gs_content_info_t));
	return GS_OK;
}

gs_status_t
gs_content_get_metadata(gs_content_t *content, uint8_t *dst, size_t *dst_size, gs_error_t **err)
{
	size_t real_size;

	if (!content || !dst || !dst_size || !*dst_size) {
		GSERRORSET(err, "Invalid parameter");
		return GS_ERROR;
	}

	if (!content->gba_md && !gs_content_reload(content, err)) {
		GSERRORSET(err, "Content loading failure path=[%s]", C1_PATH(content));
		return GS_ERROR;
	}

	real_size = MIN(*dst_size, content->gba_md->len);
	if (real_size)
		memcpy(dst, content->gba_md->data, real_size);

	*dst_size = real_size;
	return GS_OK;
}

gs_status_t
gs_content_get_system_metadata(gs_content_t *content, uint8_t *dst, size_t *dst_size, gs_error_t **err)
{
	size_t real_size;

	if (!content || !dst || !dst_size || !*dst_size) {
		GSERRORSET(err, "Invalid parameter");
		return GS_ERROR;
	}

	if (!content->gba_sysmd && !gs_content_reload(content, err)) {
		GSERRORSET(err, "Content loading failure path=[%s]", C1_PATH(content));
		return GS_ERROR;
	}

	real_size = MIN(*dst_size, content->gba_sysmd->len);
	if (real_size)
		memcpy(dst, content->gba_sysmd->data, real_size);

	*dst_size = real_size;
	return GS_OK;
}

gs_status_t
gs_content_set_metadata(gs_content_t *content, uint8_t *src, size_t src_size, gs_error_t **err)
{
	(void) content;
	(void) src;
	(void) src_size;

	GSERRORSET(err, "not yet implemented");
	return GS_ERROR;
}

int64_t
gs_content_get_size(gs_content_t *content)
{
	if (!content)
		return -1;
	return content->info.size;
}

static void
_update_sys_metadata(gpointer data, gpointer metadata)
{
	GError *e = NULL;

	rawx_update_chunk_attr((struct meta2_raw_chunk_s *)data, "sys-metadata", (const char *)metadata, &e);
	if( NULL != e) {
		g_clear_error(&e);
	}

}

gs_status_t
hc_set_content_storage_policy(gs_container_t *c, const char *path, const char *stgpol, gs_error_t **e)
{
	GError *ge = NULL;
	struct meta2_raw_content_s *rc = NULL;
	struct metacnx_ctx_s ctx;
	GHashTable *unpacked = NULL;
	const char *used_pol = NULL;
	char *metadata_str = NULL;

	if (c->meta2_addr.port <= 0 &&
			!gs_reload_container(c, &ge)) {
		GSERRORCAUSE(e, ge, "Container resolution error");
		g_clear_error(&ge);
		return FALSE;
	}

	metacnx_clear(&ctx);
	metacnx_init_with_addr(&ctx, &(c->meta2_addr), NULL);
	ctx.flags = METACNX_FLAGMASK_KEEPALIVE;
	ctx.fd = c->meta2_cnx;
	ctx.timeout.cnx = M2_TOCNX_DEFAULT;
	ctx.timeout.req = M2_TOREQ_DEFAULT;

	do {
		struct hc_url_s *url = fill_hcurl_from_content2 (c, path);
		rc = meta2_remote_stat_content(&ctx, &ge, url);
		hc_url_pclean (&url);
	} while (0);
	c->meta2_cnx = ctx.fd;

	if (!rc) {
		GSERRORCAUSE(e, ge, "Failed to load content information\n");
		g_clear_error(&ge);
		return GS_ERROR;
	}

	if (NULL != rc->system_metadata) {
		/* check stg_pol not already applied before send it */
		unpacked = metadata_unpack_gba(rc->system_metadata, NULL);
		used_pol = g_hash_table_lookup(unpacked, "storage-policy");
		if((NULL != used_pol) && (!g_ascii_strcasecmp(used_pol, stgpol))) {
			/* in place stgpol = new, don't do anything */
			g_hash_table_destroy(unpacked);
			meta2_raw_content_clean(rc);
			return GS_OK;
		}
		g_hash_table_insert(unpacked, g_strdup("storage-policy"), g_strdup(stgpol));
		GByteArray *gba = metadata_pack(unpacked, &ge);
		if(!gba) {
			GSERRORCAUSE(e, ge, "Failed to repack metadata");
			g_hash_table_destroy(unpacked);
			meta2_raw_content_clean(rc);
			return GS_ERROR;
		}
		metadata_str = g_strndup((gchar*)(gba->data), gba->len);
		g_hash_table_destroy(unpacked);
		g_byte_array_free(gba, TRUE);
	} else {
		GSERRORCAUSE(e, ge, "No metadata on content [%s], cannot process", path);
		if(NULL != ge)
			g_clear_error(&ge);
		meta2_raw_content_clean(rc);
		return GS_ERROR;
	}

	int r0;
	do {
		struct hc_url_s *url = fill_hcurl_from_content2 (c, path);
		r0 = meta2_remote_modify_metadatasys(&ctx, &ge, url, metadata_str);
		hc_url_pclean (&url);
	} while (0);

	c->meta2_cnx = ctx.fd;
	if (!r0) {
		GSERRORCAUSE(e, ge, "Failed to update system metadata of content [%s]", stgpol, path);
		g_clear_error(&ge);
		meta2_raw_content_clean(rc);
		return GS_ERROR;
	}

	/* update chunks xattr sysmetadata */
	g_slist_foreach(rc->raw_chunks, _update_sys_metadata, metadata_str);

	g_free(metadata_str);
	meta2_raw_content_clean(rc);

	return GS_OK;
}

gs_status_t
hc_set_content_property(gs_content_t *content, char ** props, gs_error_t **e)
{
	GError *ge = NULL;
	char target[64];
	GSList *beans = NULL;
	gs_status_t status = GS_OK;
	guint i;

	struct hc_url_s *url = fill_hcurl_from_content (content);
	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	for ( i=0; i < g_strv_length(props); i++) {
		struct bean_PROPERTIES_s *bp;

		bp = _bean_create(&descr_struct_PROPERTIES);

		gchar **kv = g_strsplit(props[i],"=",2);
		if (g_strv_length(kv) != 2) {
			GSERRORCODE(e,0,"Invalid property [%s] : format  key=value", props[i]);
			status = GS_ERROR;
			goto enderror;
		}
		PROPERTIES_set2_alias(bp, hc_url_get(url, HCURL_PATH));
		PROPERTIES_set_alias_version(bp, (guint64)hc_url_get(url, HCURL_VERSION));
		PROPERTIES_set_key(bp, g_string_new(kv[0]));
		PROPERTIES_set_value(bp, g_byte_array_append(g_byte_array_new(),
				(guint8*)g_strdup(kv[1]), strlen(kv[1])));

		beans = g_slist_prepend(beans,bp);
	}

	ge = m2v2_remote_execute_PROP_SET(target, url, 0, beans);

	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to update propertes to content [%s]",
				C1_PATH(content));
		g_clear_error(&ge);
		status =  GS_ERROR;
	}

enderror :
	hc_url_pclean (&url);
	_bean_cleanl2 (beans);
	return status;
}

gs_status_t
hc_get_content_properties(gs_content_t *content, char ***result, gs_error_t **e)
{
	GError *ge = NULL;
	char target[64];
	gchar **final;
	guint max;
	GSList *beans = NULL;
	GSList *l;
	gs_status_t status = GS_OK;

	struct hc_url_s *url = fill_hcurl_from_content (content);
	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	ge = m2v2_remote_execute_PROP_GET(target, url, M2V2_FLAG_NODELETED, &beans);

	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to get  properties of content [%s]", C1_PATH(content));
		g_clear_error(&ge);
		status = GS_ERROR;
		goto enderror;
	}

	max =0;
	final = g_malloc0(sizeof(gchar*) * (max+1));
	for (l=beans; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_PROPERTIES) {
			struct bean_PROPERTIES_s *bp = (struct bean_PROPERTIES_s *) l->data;

			max ++;
			final = g_realloc(final, sizeof(gchar*) * (max+1));

			GByteArray *val =PROPERTIES_get_value(bp);

			char buf[val->len + 1];
			memset(buf, '\0', sizeof(buf));
			g_snprintf(buf, sizeof(buf), "%s", val->data);
			final[max-1] = g_strdup_printf("%s=%s",PROPERTIES_get_key(bp)->str, buf);
			final[max] = NULL;
		}
	}

	*result=final;

enderror :
	hc_url_pclean (&url);
	_bean_cleanl2(beans);
	return status;
}

gs_status_t
hc_delete_content_property(gs_content_t *content, char ** keys, gs_error_t **e)
{
	char target[64];
	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url = fill_hcurl_from_content(content);

	GSList *lkeys = metautils_array_to_list((void**)keys);
	GError *ge = m2v2_remote_execute_PROP_DEL(target, url, lkeys);
	g_slist_free(lkeys);

	if (!ge)
		return GS_OK;

	GSERRORCAUSE(e, ge, "Failed to delete propertes of content [%s]",
			C1_PATH(content));
	return GS_ERROR;
}

gs_status_t
hc_copy_content(gs_container_t *c, const char *src, const char *dst, gs_error_t **e)
{
	char target[64];
	GError *ge = NULL;

	struct hc_url_s *url = fill_hcurl_from_content2 (c, dst);
	bzero(target, 64);
	addr_info_to_string(&(c->meta2_addr), target, 64);

	ge = m2v2_remote_execute_COPY(target, url, src);
	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to create a copy of content [%s] to [%s]",
			src, hc_url_get(url, HCURL_WHOLE));
			g_clear_error(&ge);
		return GS_ERROR;
	}

	return GS_OK;
}

static struct hc_url_s *
_init_url(gs_grid_storage_t *hc, const char *container, const char *content)
{
	struct hc_url_s *url = fill_hcurl_from_client (hc);
	hc_url_set(url, HCURL_USER, container);
	hc_url_set(url, HCURL_PATH, content);
	return url;
}

gs_status_t
hc_dl_content_to_file(gs_grid_storage_t *hc, const char *container,
		const char *content, const char *dest, gs_error_t **e)
{
	struct hc_url_s *url = _init_url(hc, container, content);
	gs_error_t *err = hc_get_content(hc, url, dest, FALSE, FALSE, NULL);
	gs_status_t status = err == NULL ? GS_OK : GS_ERROR;
	if (e) *e = err; else gs_error_free(err);
	hc_url_pclean(&url);
	return status;
}

gs_status_t
hc_dl_content_custom(gs_grid_storage_t *hc, const char *container,
		const char *content, gs_download_info_t *dl_info, gs_error_t **e)
{
	struct hc_url_s *url = _init_url(hc, container, content);
	gs_error_t *err = hc_dl_content(hc, url, dl_info, FALSE, NULL);
	gs_status_t status = err == NULL ? GS_OK : GS_ERROR;
	if (e) *e = err; else gs_error_free(err);
	hc_url_pclean (&url);
	return status;
}

static ssize_t
_reader (int *pfd, char *b, size_t max)
{
	/* fill <b> with the data available. At most <max> bytes are expected in <b>. */
	return read (*pfd, b, max);
}

gs_status_t
hc_ul_content_from_file (gs_grid_storage_t *hc, const char *container,
		const char *content, const char *src, gs_error_t **err)
{
	struct stat st;
	int fd;

	if (0 > (fd = open (src, O_RDONLY))) {
		GRID_WARN("LOCAL open error on [%s] : (%d) %s\n", src, errno, strerror(errno));
		return 0;
	}
	if (0 > fstat (fd, &st)) {
		GRID_WARN("LOCAL stat error on [%s] : (%d) %s\n", src, errno, strerror(errno));
		close (fd);
		return 0;
	}

	gs_status_t rc;
	gs_container_t *c = gs_get_container (hc, container, 1/*autocreate*/, err);
	if (!c) {
		rc = GS_ERROR;
	} else {

		rc = gs_upload_content_v2 (c,
				content, st.st_size, (gs_input_f)_reader, &fd,
				"", "", err);
		if (rc != GS_OK) {
			GRID_WARN ("upload error on [%s]/[%s]", container, content);
		}

		gs_container_free (c);
		c = NULL;
	}

	close (fd);
	return rc;
}

