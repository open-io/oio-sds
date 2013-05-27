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

#include "./gs_internals.h"
#include "./rawx.h"

static void
chunk_agregate_debug(GSList *agregates)
{
	gchar ci_str[2048]; 
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
					chunk_info_to_string (ci, ci_str, sizeof(ci_str));
					TRACE(" chunk-%d-%d : %s", i_ag, i_chunk, ci_str);
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
		g_byte_array_free(content->gba_sysmd, TRUE);
	if (content->gba_md)
		g_byte_array_free(content->gba_md, TRUE);
	if (content->chunk_list) {

		TRACE("Freeing %u old chunks in [grid://%s/%s/%s]", g_slist_length(content->chunk_list),
				content->info.container->info.gs->ni.name, C1_IDSTR(content), C1_PATH(content));

		g_slist_foreach (content->chunk_list, chunk_info_gclean, NULL);
		g_slist_free (content->chunk_list);
	}
	if (content->version)
		g_free(content->version);

	content->gba_sysmd = NULL;
	content->gba_md = NULL;
	content->chunk_list = NULL;
	content->version = NULL;
}

static void
_fill_hcurl_from_content(gs_content_t *content, struct hc_url_s **url) 
{
	*url = hc_url_empty();
	hc_url_set(*url, HCURL_NS, C1_C0(content)->info.gs->ni.name);
	hc_url_set(*url, HCURL_REFERENCE, C0_NAME(C1_C0(content)));
	hc_url_set(*url, HCURL_PATH, C1_PATH(content));
	if (content->version)
		hc_url_set(*url, HCURL_VERSION, content->version);

}

static void
_fill_cid_from_bean(struct meta2_raw_chunk_s *ci, struct bean_CHUNKS_s *ck)
{
	GError *e = NULL; 

	/* split bean id into chunk id part rawx://ip:port/VOL/ID */
	char *bean_id = CHUNKS_get_id(ck)->str;
	char *id = strrchr(bean_id, '/');
	char *addr = strchr(bean_id,':') + 3; /* skip :// */
	char *vol = strchr(addr, '/');

	/* id */
	/* hex2bin(id + 1, &(ci->id.id), sizeof(hash_sha256_t), &e); */
	container_id_hex2bin(id + 1 , strlen(id +1 ), &(ci->id.id), NULL);

	/* addr */
	char tmp[128];
	memset(tmp, '\0', 128);
	memcpy(tmp, addr, vol - addr);
	if(!l4_address_init_with_url(&(ci->id.addr), tmp, &e)) {
		WARN("Failed to init chunk addr");
	}

	/* vol */
	memcpy(ci->id.vol, vol, id - vol);

	if(NULL != e)
		g_clear_error(&e);
}

static struct bean_CHUNKS_s *
_get_chunk_matching_content(GSList *beans, struct bean_CONTENTS_s *content)
{
	GSList *l = NULL;
	/*split the chunks into the spare and used chunks*/
	char *cid1 = CONTENTS_get_chunk_id(content)->str;
	for (l = beans; l && l->data ; l=l->next) {
		if(DESCR(l->data) != &descr_struct_CHUNKS)
			continue;
		struct bean_CHUNKS_s *ck = (struct bean_CHUNKS_s *) l->data;
		char *cid2 = CHUNKS_get_id(ck)->str;
		if(0 == g_ascii_strcasecmp(cid1, cid2)) {
			return ck;
		}
	}

	return NULL;
}

gboolean
map_raw_content_from_beans(struct meta2_raw_content_s *raw_content, GSList *beans)
{
	GSList *l = NULL;

	gint maxpos = -1;
	/* read all beans and extract info */
	for (l=beans; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_CONTENTS) {
			struct bean_CONTENTS_s *bc = (struct bean_CONTENTS_s *) l->data;
			struct bean_CHUNKS_s *ck = _get_chunk_matching_content(beans, bc);
			struct meta2_raw_chunk_s *ci = g_malloc0(sizeof(struct meta2_raw_chunk_s));
			_fill_cid_from_bean(ci, ck);
			ci->size = CHUNKS_get_size(ck);
			char *pos_str = CONTENTS_get_position(bc)->str;
			char **tok = g_strsplit(pos_str, ".", 2);
			gint64 pos64 = g_ascii_strtoll(tok[0], NULL, 10);
			guint32 pos = pos64;
			ci->position = pos;
			g_strfreev(tok);
			guint8 *hash = CHUNKS_get_hash(ck)->data;
			memcpy(ci->hash, hash, sizeof(ci->hash));
			raw_content->raw_chunks = g_slist_prepend(raw_content->raw_chunks, ci);
			if ( pos64 > maxpos )
				maxpos = pos;
		}
		else if(DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			raw_content->size = CONTENTS_HEADERS_get_size(l->data);
		}
		else if(DESCR(l->data) == &descr_struct_ALIASES) {
			char *mdsys = ALIASES_get_mdsys(l->data)->str;
			/*
			if(ALIASES_get_deleted(l->data)) {
				return FALSE;
			} */
			g_strlcpy(raw_content->path, ALIASES_get_alias(l->data)->str, sizeof(raw_content->path));
			raw_content->version = ALIASES_get_version(l->data);
			raw_content->system_metadata = g_byte_array_append(g_byte_array_new(), (const guint8*)mdsys, strlen(mdsys));
			raw_content->deleted = ALIASES_get_deleted(l->data);
		}
	}
	raw_content->nb_chunks = maxpos +1;

	return TRUE;
}

gboolean
map_properties_from_beans(GSList **properties, GSList *beans)
{
	GSList *l = NULL;

	for (l=beans; l && l->data; l=l->next) {
		if(DESCR(l->data) == &descr_struct_PROPERTIES) {
			struct bean_PROPERTIES_s *bp = (struct bean_PROPERTIES_s *)l->data;
			if ( PROPERTIES_get_deleted(bp) )
				continue;
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
	struct meta1_service_url_s *url;
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

	url = meta1_unpack_url(*tmp);
	rc = l4_address_init_with_url(&(container->meta2_addr), url->host, err);
	g_strfreev2(&tmp);
	g_free(url);

	/* Now create the meta2 entry */
	if (rc && link_needed) {
		rc = meta2_remote_container_create_v2(&(container->meta2_addr), 3000,
				err, C0_ID(container), C0_NAME(container),
				container->info.gs->virtual_namespace);

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
	struct meta1_service_url_s *url;
	gchar **urlv = NULL;
	gs_error_t *e;
	gboolean rc = TRUE;

	e = hc_list_reference_services(container->info.gs, C0_NAME(container),
			"meta2", &urlv);
	if (e) {
		GSETCODE(err, gs_error_get_code(e), "%s", gs_error_get_message(e));
		gs_error_free(e);
		return FALSE;
	}

	if (!urlv || !*urlv) {
		GSETCODE(err, CODE_CONTAINER_NOTFOUND, "No META2");
		g_strfreev2(&urlv);
		return FALSE;
	}

	url = meta1_unpack_url(*urlv);
	rc = l4_address_init_with_url(&(container->meta2_addr), url->host, err);
	g_strfreev2(&urlv);
	g_free(url);

	if (!rc)
		GSETERROR(err, "Invalid META2 address");
	return rc;
}

static gboolean
_reload_content(gs_content_t *content, GError **err)
{
	struct metacnx_ctx_s ctx;
	struct meta2_raw_content_s *raw_content;

	if (C1_C0(content)->meta2_addr.port <= 0 &&
			!gs_reload_container(C1_C0(content), err)) {
		GSETERROR(err, "Container resolution error");
		return FALSE;
	}

	metacnx_clear(&ctx);
	metacnx_init_with_addr(&ctx, &(C1_C0(content)->meta2_addr), NULL);
	ctx.flags = METACNX_FLAGMASK_KEEPALIVE;
	ctx.fd = C1_C0(content)->meta2_cnx;
	ctx.timeout.cnx = M2_TOCNX_DEFAULT;
	ctx.timeout.req = M2_TOREQ_DEFAULT;

	/* raw_content = meta2_remote_stat_content(&ctx, C1_ID(content),
		C1_PATH(content), strlen(C1_PATH(content)), err);

	if (!raw_content) {
		GSETERROR(err, "Failed to get raw data");
		return FALSE;
	}
	if (raw_content->flags) {
		meta2_maintenance_destroy_content(raw_content);
		GSETERROR(err, "Content now unavailable");
		return FALSE;
	} */

	/*reload the latest know data*/
	/* map_content_from_raw(content, raw_content);
	meta2_maintenance_destroy_content(raw_content);
	*/

	char target[64];
	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, C1_C0(content)->info.gs->ni.name);
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(C1_C0(content)));
	hc_url_set(url, HCURL_PATH, C1_PATH(content));
	if (content->version) {
		hc_url_set(url, HCURL_VERSION, content->version);
	}

	GSList *beans = NULL;

	*err = m2v2_remote_execute_GET(target, NULL, url, 0, &beans);

	hc_url_clean(url);

	if(NULL != *err) {
		GSETERROR(err, "Failed to get content");
		return FALSE;
	}

	raw_content = g_malloc0(sizeof(struct meta2_raw_content_s));
	if(!map_raw_content_from_beans(raw_content, beans)) {
		/* content deleted */
		_bean_cleanl2(beans);
		GSETCODE(err, CODE_CONTENT_NOTFOUND, "Content deleted");
		return FALSE;
	}

	map_content_from_raw(content, raw_content);
	meta2_raw_content_clean(raw_content);
	_bean_cleanl2(beans);

	C1_C0(content)->meta2_cnx = ctx.fd;
	
	TRACE("Content [grid://%s/%s/%s] reloaded (%u chunks)",
		content->info.container->info.gs->ni.name, C1_IDSTR(content), C1_PATH(content),
		g_slist_length(content->chunk_list));

	return TRUE;
}

/*
 * 
 */
gboolean
gs_content_reload (gs_content_t *content, gboolean allow_meta2, gboolean allow_cache, gs_error_t **err)
{
	gboolean rc = FALSE;
	GError *localError=NULL;
	const gchar *metacd_path = NULL;

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

	if (allow_cache) { /* Try with the METACD */
		metacd_t *metacd = C1_C0(content)->info.gs->metacd_resolver;
		if (resolver_metacd_is_up(metacd)) {
			struct meta2_raw_content_s *raw_content;
			metacd_path = make_metacd_path(C1_PATH(content), C1_VERSION(content));
			raw_content = resolver_metacd_get_content(metacd, C1_ID(content), metacd_path, &localError);
			destroy_metacd_path(metacd_path);
			if (!raw_content) {
				if (localError && localError->code == CODE_CONTENT_NOTFOUND)
					goto end_label;
				ERROR("METAcd seemed UP but could not give us our chunks: %s",
					localError?localError->message:"unknown error");
			}
			else {
				map_content_from_raw(content, raw_content);
				meta2_maintenance_destroy_content(raw_content);
			}
			if (localError)
				g_clear_error(&localError);
		}
		if (content->chunk_list) {
			/* XXX */
			content->loaded_from_cache = ~0;
			return 1;
		}
	}

	/* Try with the META2 */
	content->loaded_from_cache = 0;
	if (!allow_meta2) {
		GSERRORSET(err, "Not found");
		goto end_label;
	}
	if (!_reload_content(content, &localError)) {
		GSERRORSET(err, "Content not found");
		goto end_label;
	}

	if (localError)
		g_clear_error(&localError);
	return 1;

end_label:
	_free_content_internals(content);
	if (!localError)
		GSETERROR(&localError,"unknow error");
	GSERRORCAUSE(err, localError, "Cannot reload %s", C1_PATH(content));
	g_clear_error(&localError);
	return rc;
}


gs_status_t gs_destroy_content (gs_content_t *content, gs_error_t **err)
{
	int nb_refreshes=1;
	GError *localError=NULL;
	gs_status_t remove_done=0;
	struct meta2_raw_content_s *raw_content = NULL;

	if (!content)
	{
		GSERRORSET (err, "Invalid parameter");
		return GS_ERROR;
	}

	/*loads the chunk's list*/
	/* 
	if (content->loaded_from_cache)
		_free_content_internals(content);
	if (!content->chunk_list) {
		if (!gs_content_reload (content, TRUE, FALSE, err)) {
			GSERRORSET(err,"No chunks in the content after a reload");
			return GS_ERROR;
		}
	}
	*/

	/*mark the content for removal*/
	(void) gs_container_reconnect_if_necessary (C1_C0(content),NULL);

	/* 
	for (nb_refreshes=1; !(remove_done=C1_REMOVE(content,&localError)) && nb_refreshes>0 ; nb_refreshes--) {
		CONTAINER_REFRESH(C1_C0(content),localError,end_label,C1_PATH(content));
	}

	TRACE("REMOVE path=%s %s/%s", C1_PATH(content), C1_NAME(content), C1_IDSTR(content));
	if (localError) g_clear_error(&localError);

	*/

	/*commit the removal*/
#define MAX_ATTEMPTS_COMMIT 2

	GSList *beans = NULL;

	/* for (nb_refreshes=MAX_ATTEMPTS_COMMIT; !C1_COMMIT(content,&localError) && nb_refreshes>0 ; nb_refreshes--) */

	char target[64];
	memset(target, '\0', 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url = hc_url_empty();
	hc_url_set(url, HCURL_NS, C1_C0(content)->info.gs->ni.name);
	hc_url_set(url, HCURL_REFERENCE, C0_NAME(C1_C0(content)));
	hc_url_set(url, HCURL_PATH, C1_PATH(content));
	if (content->version) {
		hc_url_set(url, HCURL_VERSION, content->version);
	}

	for(nb_refreshes = MAX_ATTEMPTS_COMMIT; nb_refreshes > 0; nb_refreshes--) {
		localError = m2v2_remote_execute_DEL(target, NULL, url, &beans);
		if(NULL != localError) {
			if (localError->code==CODE_CONTENT_NOTFOUND && nb_refreshes<MAX_ATTEMPTS_COMMIT) {
				/*content already removed*/
				break;
			}
		CONTAINER_REFRESH(C1_C0(content),localError,end_label,C1_PATH(content));
		} else {
			raw_content = g_malloc0(sizeof(struct meta2_raw_content_s));
			map_raw_content_from_beans(raw_content, beans);
			map_content_from_raw(content, raw_content);
			meta2_raw_content_clean(raw_content);
			break;
		}
	}

	if(NULL != url)
		hc_url_clean(url);

	if(NULL != beans)
		_bean_cleanl2(beans);

	TRACE("COMMIT path=%s %s/%s", C1_PATH(content), C1_NAME(content), C1_IDSTR(content));
	if (localError) g_clear_error(&localError);

	/* We are about to delete the chunks, and the content has been marked for removal,
	 * we send the decache order to the metacd, it won't be possible to reload it */
	/* gs_decache_chunks_in_metacd(content); */


	
	/*delete the remote chunks*/

	/* 
	if (content->chunk_list)
	{
		gs_chunk_t cT;
		GSList *cL;

		cT.content = content;
		for (cL=content->chunk_list; cL ;cL=cL->next)
		{
			GError *localErr=NULL;
			int nb_tries, done=0;

			cT.ci = (chunk_info_t*) cL->data;
			for (nb_tries=2; !done && nb_tries>0 ;nb_tries--)
				done = rawx_delete(&cT, &localErr);

			if (!done) {
				ERROR("Cannot delete a remote chunk of %s (in %s/%s): %s", C1_PATH(content),
					C1_NAME(content), C1_IDSTR(content), g_error_get_message(localErr));
			}
			
			if (localErr)
				g_clear_error(&localErr);
		}
	} */

	if (localError)
		g_clear_error(&localError);
	return GS_OK;

end_label:
	if (remove_done)
	{
		(void) gs_container_reconnect_if_necessary (C1_C0(content),NULL);
		for (nb_refreshes=MAX_ATTEMPTS_ROLLBACK_DELETE; !C1_ROLLBACK(content,&localError) && nb_refreshes>0 ; nb_refreshes--)
		{
			CONTAINER_REFRESH(C1_C0(content),localError,error_label,C1_PATH(content));
		}
	}

error_label:
	if (!localError)
		GSETERROR(&localError,"unknown error");
	GSERRORCAUSE(err,localError,"Cannot destroy %s in %s/%s", C1_PATH(content), C1_NAME(content), C1_IDSTR(content));
	g_clear_error (&localError);
	return GS_ERROR;
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

	if (!content->gba_md && !gs_content_reload(content, TRUE, TRUE, err)) {
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

	if (!content->gba_sysmd && !gs_content_reload(content, TRUE, TRUE, err)) {
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

void
gs_decache_chunks_in_metacd(gs_content_t *content)
{
	GError *flush_error = NULL;
	gs_grid_storage_t *client;
	metacd_t *metacd;
	gs_container_t *container;
	const gchar *metacd_path = NULL;

	if (!content)
		return;

	container = C1_C0(content);
	if (!container)
		return;

	client = container->info.gs;
	if (!client)
		return;

	metacd = client->metacd_resolver;
	if (!metacd)
		return;

	if (!resolver_metacd_is_up(metacd))
		return;

	/* send a decache order to the METACD */
	metacd_path = make_metacd_path(C1_PATH(content), C1_VERSION(content));
	if (!resolver_metacd_del_content(metacd, C0_ID(container), metacd_path, &flush_error)) {
		WARN("METACD flush failed for [%s/%s/%s] : %s",
				client->ni.name, C0_IDSTR(container), C1_PATH(content),
				(flush_error ? flush_error->message : "unknown error"));
	}
	else
		INFO("decache order sent to METACD for [%s/%s/%s]",
				client->ni.name, C0_IDSTR(container), C1_PATH(content));
	destroy_metacd_path(metacd_path);
	if (flush_error)
		g_clear_error(&flush_error);
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

	rc = meta2_remote_stat_content(&ctx, C0_ID(c), path, strlen(path), &ge);

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


	if(!meta2_remote_modify_metadatasys(&ctx,  C0_ID(c), path, metadata_str, &ge)) {
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
	guint i ;

	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url;
	_fill_hcurl_from_content(content,&url);

	for ( i=0; i < g_strv_length(props); i++) {
		struct bean_PROPERTIES_s *bp;

		bp = _bean_create(&descr_struct_PROPERTIES);
		
		gchar **kv = g_strsplit(props[i],"=",2);
		if(g_strv_length(kv) != 2) {
			GSERRORCODE(e,0,"Invalid property [%s] : format  key=value",props[i]);
			status = GS_ERROR;
			goto enderror;
		}
		PROPERTIES_set2_alias(bp, hc_url_get(url, HCURL_PATH));
		PROPERTIES_set_alias_version(bp, (guint64)hc_url_get(url, HCURL_VERSION));
		PROPERTIES_set_key(bp, g_string_new(kv[0]));
		PROPERTIES_set_value(bp, g_byte_array_append(g_byte_array_new(), (guint8*)g_strdup(kv[1]), strlen(kv[1])));
		PROPERTIES_set_deleted(bp, FALSE);

		beans = g_slist_prepend(beans,bp);
	}

	ge = m2v2_remote_execute_PROP_SET(target, NULL, url, beans);

	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to update propertes to content [%s]", C1_PATH(content));
		g_clear_error(&ge);
		status =  GS_ERROR;
	}

enderror :
	hc_url_clean(url);
	_bean_cleanl2(beans);
	return status;
}

gs_status_t
hc_get_content_properties(gs_content_t *content, char ***result, gs_error_t **e)
{
	GError *ge = NULL;
	char target[64];
	gchar **final;
	guint max;
	gs_status_t status = GS_OK;

	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url;
	_fill_hcurl_from_content(content,&url);
	
	GSList *beans = NULL;
	GSList *l;
	
	ge = m2v2_remote_execute_PROP_GET(target, NULL, url, M2V2_FLAG_NODELETED, &beans);

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
	hc_url_clean(url);
	_bean_cleanl2(beans);


	return status;
} 

gs_status_t
hc_delete_content_property(gs_content_t *content, char ** keys ,gs_error_t **e)
{
	GError *ge = NULL;
	char target[64];
	gs_status_t status= GS_OK;
	guint i;

	bzero(target, 64);
	addr_info_to_string(&(C1_C0(content)->meta2_addr), target, 64);

	struct hc_url_s *url;
	_fill_hcurl_from_content(content,&url);
	
	GSList *out_beans = NULL;
	GSList *in_beans = NULL;
	GSList *l;
	struct bean_PROPERTIES_s *bp;

	ge = m2v2_remote_execute_PROP_GET(target, NULL, url, M2V2_FLAG_NODELETED, &out_beans);
	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to delete propertes of content [%s]", C1_PATH(content));
		status= GS_ERROR;
		goto enderror;
	}
	

	for ( i=0; i < g_strv_length(keys); i++) {
		for ( l=out_beans ; l && l->data ; l=l->next) {
			if(DESCR(l->data) == &descr_struct_PROPERTIES) {
				if ( g_ascii_strcasecmp(PROPERTIES_get_key((struct bean_PROPERTIES_s *)l->data)->str,keys[i]) == 0 ) {
					bp = _bean_dup((struct bean_PROPERTIES_s *)l->data);
					PROPERTIES_set_deleted(bp, TRUE);
					in_beans = g_slist_prepend(in_beans,bp);
					break;
				}
			}
		}
	}
	ge = m2v2_remote_execute_PROP_SET(target, NULL, url, in_beans);

	if(NULL != ge) {
		GSERRORCAUSE(e, ge, "Failed to delete propertes of content [%s]", C1_PATH(content));
		status= GS_ERROR;
	}

enderror:
	if (ge != NULL)
		g_clear_error(&ge);
	hc_url_clean(url);
	_bean_cleanl2(out_beans);
	_bean_cleanl2(in_beans);

	return status;
}
