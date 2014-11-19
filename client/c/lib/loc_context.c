#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.location"
#endif

#include "./gs_internals.h"

struct loc_context_s {
	struct gs_container_location_s *loc;
	char **container_props;
	GHashTable *admin_info;
	char *container_stgpol;
	struct beans_content_s *rc;
	const gchar *namespace;
	struct grid_lbpool_s *glp;
};

struct beans_content_s {
	struct bean_ALIASES_s *alias;
	struct bean_CONTENTS_HEADERS_s *header;
	GArray *pairs; /* array of chunk_pair_t */
	GSList *properties; /* list of PROPERTIES beans */
};

/* ------------------------------------------------------------------------------ */

static gboolean _close_meta2_connection(struct metacnx_ctx_s *cnx, container_id_t cid);

static struct storage_policy_s *
_init_storage_policy(const char *ns, const char *polname)
{
	namespace_info_t *ni = NULL;
	GError *e = NULL;
	struct storage_policy_s *sp =NULL;

	ni = get_namespace_info(ns, &e);
	if(NULL != e) {
		GRID_ERROR("Failed to get namespace info : %s", e->message);
		g_clear_error(&e);
		return NULL;
	}

	sp = storage_policy_init(ni, polname);

	namespace_info_clear(ni);
	g_free(ni);
	return sp;
}

static struct service_info_s *
__service_info_from_chunkid(const struct loc_context_s *lc, const char *cid)
{
	struct service_info_s *si = NULL;
	// TODO FIXME Factorizes this with client/c/lib/loc_context.c and
	// TODO FIXME meta2v2/meta2_utils_lb.c, rawx-mover/src/main.c
	char **tok = g_regex_split_simple(
			"(([[:digit:]]{1,3}\\.){3}[[:digit:]]{1,3}:[[:digit:]]{1,5})",
			cid, 0, 0);
	if(!tok)
		return NULL;

	if(g_strv_length(tok) < 3) {
		return NULL;
	}

	si = grid_lbpool_get_service_from_url(lc->glp, "rawx", tok[1]);

	g_strfreev(tok);

	return si;
}

static gboolean
_open_meta2_connection(struct metacnx_ctx_s *cnx, const gchar *m2_url, gs_error_t **e) 
{
	GError *ge = NULL;
	gboolean ret = FALSE;

	metacnx_clear(cnx);

	if (!metacnx_init_with_url(cnx, m2_url, &ge)) {
		GSERRORCAUSE(e, ge, "Invalid META2 address");
		goto clean;
	}

	ret = TRUE;

clean:
	if (ge)
		g_error_free(ge);

	return ret;
}

static char *
_check_chunk(const char *cid)
{
	ne_session *session=NULL;
	ne_request *request=NULL;

	GString *str = g_string_new("");

	char **split = g_strsplit(cid, "/", 0);
	char **addr_tok = g_strsplit(split[2], ":", 2);

	if(NULL != (session = ne_session_create("http", addr_tok[0], atoi(addr_tok[1])))) {
		ne_set_connect_timeout(session, 10);
		ne_set_read_timeout(session, 30);
		/* FIXME: I'm a little harder with strrchr success presumption */
		if(NULL != (request = ne_request_create (session, "HEAD", strrchr(cid, '/')))) {
			switch (ne_request_dispatch (request)) {
				case NE_OK:
					if (ne_get_status(request)->klass != 2) {
						g_string_append_printf(str, "(Chunk unavailable : %s)",
								ne_get_error(session));
					}
					break;
				default:
					g_string_append_printf(str, "(Chunk unavailable : %s)",
							ne_get_error(session));
			}
			ne_request_destroy (request);
		} 
		ne_session_destroy (session);
	}

	g_strfreev(addr_tok);
	g_strfreev(split);

	return g_string_free(str, FALSE);
}

static status_t
_get_container_user_properties(gs_grid_storage_t *hc, struct hc_url_s *url, container_id_t cid,
                char ***props, gs_error_t **gserr)
{
        GError *gerr = NULL;
        gboolean rc;
        addr_info_t *m1 = NULL;
        gs_container_t *c = NULL;
        GSList *excluded = NULL;
        c = gs_get_container(hc, hc_url_get(url, HCURL_REFERENCE), 0, gserr);
        if(!c)
                return 0;
        for (;;) {

                m1 = gs_resolve_meta1v2(hc, cid, c->info.name, 1, &excluded, &gerr);

                if (!m1) {
                        *gserr = gs_error_new(500, "No META1 found for [%s]", hc_url_get(url, HCURL_REFERENCE));
                        break;
                }

                rc = meta1v2_remote_reference_get_property(m1, &gerr, hc_url_get(url, HCURL_NS), cid, NULL, props, -1, -1);

                if (!rc) {
                        excluded = g_slist_prepend(excluded, m1);
                        m1=NULL;
                        if (gerr) {
                                if (gerr->code < 100) { /* network error */
                                        g_error_free(gerr);
                                        gerr = NULL;
                                } else {
                                        GSERRORCAUSE(gserr, gerr, "Cannot get container user properties");
                                        break;
                                }
                        }
                } else {
                        break;
                }
        }
        if (excluded) {
                g_slist_foreach(excluded, addr_info_gclean, NULL);
                g_slist_free(excluded);
        }
        if (m1)
                g_free(m1);

        gs_container_free(c);

        if (gerr)
                g_error_free(gerr);

        return rc;
}

static status_t
_get_container_global_property(gs_grid_storage_t *hc, struct metacnx_ctx_s *cnx, container_id_t cid,
			GHashTable **ht, gs_error_t **gserr)
{
	GSList *prop_list = NULL, *l = NULL;
	GError *gerr = NULL;


	// get all properties with current meta2
	if (!meta2_remote_list_all_container_properties(cnx, cid, &prop_list, &gerr)) {

		GSList     *m2_list = NULL;
                addr_info_t *addr    = NULL;
                GSList      *m2      = NULL;
                gchar       str_addr[STRLEN_ADDRINFO];
                struct metacnx_ctx_s cnxOther;
                gs_error_t  *e       = NULL;
		gboolean    bResult  = FALSE;

        	// search all meta2 fo current contener
        	m2_list = gs_resolve_meta2(hc, cid, &gerr);
        	if (!m2_list) {
        		GSERRORCAUSE(gserr, gerr, "Failed to get container admin entries, Cannot find meta2(s)");
			if (gerr)
				g_error_free(gerr);
			return 0;
		}


		// test each meta2...
		for (m2=m2_list; m2 ;m2=m2->next) {
                        addr = m2->data;
			if (addr) {
				addr_info_to_string(addr, str_addr, sizeof(str_addr));
				DEBUG("Failed to get container admin entries -> test with next meta2 [%s]", str_addr);

				if (!_open_meta2_connection(&cnxOther, str_addr/*ctx->loc->m2_url[0]*/, &e)) {
					GSERRORCODE(gserr, e->code,
							"Failed to open connection to meta2 (%s)\n", str_addr);
					gs_error_free(e);
					continue;
				}

				if (!meta2_remote_list_all_container_properties(&cnxOther, cid, &prop_list, &gerr)) {
				        _close_meta2_connection(&cnxOther, cid);
                                        GSERRORCAUSE(gserr, gerr, "Failed to get container admin entries: %s\n",str_addr);
					continue;

				} else {
					_close_meta2_connection(&cnxOther, cid);
					// no error
					bResult = TRUE;
					break;
				}
			}
		}


		if (m2_list) { 
                	g_slist_foreach(m2_list, addr_info_gclean, NULL); 
	                g_slist_free(m2_list); 
        	}

		if (gerr)
			g_error_free(gerr);

		if (bResult == FALSE) 
			return 0;

	}


	// here: reading properties ok

	*ht = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	for (l = prop_list; l && l->data; l = l->next) {
		gchar *tmp = l->data;
		gchar **tok = g_strsplit(tmp, "=", 2);
		if (tok[0] && tok[1])
			g_hash_table_insert(*ht, g_strdup(tok[0]), g_strdup(tok[1]));
		g_strfreev(tok);
	}
	g_slist_free_full(prop_list, g_free);

	/* Ensure we have some mandatory properties */
	if(!g_hash_table_lookup(*ht, GS_CONTAINER_PROPERTY_STORAGE_POLICY))
		g_hash_table_insert(*ht, g_strdup(GS_CONTAINER_PROPERTY_STORAGE_POLICY), g_strdup("namespace default"));
	if(!g_hash_table_lookup(*ht, GS_CONTAINER_PROPERTY_VERSIONING))
		g_hash_table_insert(*ht, g_strdup(GS_CONTAINER_PROPERTY_VERSIONING), g_strdup("namespace default"));
	if(!g_hash_table_lookup(*ht, GS_CONTAINER_PROPERTY_QUOTA))
		g_hash_table_insert(*ht, g_strdup(GS_CONTAINER_PROPERTY_QUOTA), g_strdup("namespace default"));

	return 1;
}

static struct beans_content_s *
_beans_to_content(const GSList *beans)
{
	struct beans_content_s *c = g_malloc0(sizeof(struct beans_content_s));
	GPtrArray *contents, *chunks;
	chunk_pair_t pair;
	contents = g_ptr_array_new();
	chunks = g_ptr_array_new();

	/*dispatch */
	for(; beans; beans = beans->next) {
		if (DESCR(beans->data) == &descr_struct_CHUNKS)
			g_ptr_array_add(chunks, _bean_dup(beans->data));
		else if (DESCR(beans->data) == &descr_struct_CONTENTS)
			g_ptr_array_add(contents, _bean_dup(beans->data));
		else if (DESCR(beans->data) == &descr_struct_CONTENTS_HEADERS)
			c->header = _bean_dup(beans->data);
		else if (DESCR(beans->data) == &descr_struct_ALIASES)
			c->alias = _bean_dup(beans->data);
		else if (DESCR(beans->data) == &descr_struct_PROPERTIES)
			c->properties = g_slist_append(c->properties, _bean_dup(beans->data));
	}

	/* build pairs */
	c->pairs = g_array_new(FALSE, FALSE, sizeof(chunk_pair_t));
	for(guint i=0; i < contents->len ; i++) {
		init_chunk_pair(chunks, &pair, g_ptr_array_index(contents, i));
		if(pair.chunk != NULL)
			g_array_append_vals(c->pairs, &pair, 1);
	}
	g_array_sort(c->pairs, (GCompareFunc) compare_pairs_positions);                                             

	// what we want to preserve are the pointers to beans created by
	// _bean_dup, not the GPtrArray -> we can safely free the arrays.
	g_ptr_array_unref(contents);
	g_ptr_array_unref(chunks);

	return c;
}

static gs_error_t *
_get_content(struct metacnx_ctx_s *cnx, struct hc_url_s *url, struct beans_content_s **content)
{
	GSList *beans = NULL;
	char target[64];
	GError *e = NULL;
	gs_error_t *result = NULL;

	/* Build target */
	bzero(target, 64);
	addr_info_to_string(&(cnx->addr), target, 64);

	if(!(e = m2v2_remote_execute_GET(target, NULL, url, 0, &beans))) {
		*content = _beans_to_content(beans);
		g_slist_free_full(beans, _bean_clean);
	}

	if(NULL != e) {
		GSERRORCAUSE(&result, e, "Error while retrieving content");
		g_clear_error(&e);
	}

	return result;
}

static void
__dump_property_xml(struct bean_PROPERTIES_s *prop, GString **s)
{
	GByteArray *gba = PROPERTIES_get_value(prop);
	const char *k = PROPERTIES_get_key(prop)->str;

	g_string_append_printf(*s, "   <%s>%.*s</%s>\n",
			k,
			gba->len, gba->data,
			k);
}

static void
__dump_property(struct bean_PROPERTIES_s *prop, GString **s)
{
	GByteArray *gba = PROPERTIES_get_value(prop);
	const char *k = PROPERTIES_get_key(prop)->str;
	g_string_append_printf(*s, "\t\t\t\t%s=%.*s\n", k, gba->len, gba->data);
}

static char *
_chunk_location_row_xml(const struct loc_context_s *lc, const char *cid,
		const char *prefix)
{
	struct service_info_s *si = NULL;
	GString *result = g_string_new("");
	si = __service_info_from_chunkid(lc, cid);

	if(NULL != si) {
		char *avail = _check_chunk(cid);
		g_string_append_printf(result,
				"%s     <location>\n"
				"%s      <url>%s</url>\n"
				"%s      <stgclass>%s</stgclass>\n"
				"%s      <available>%s</available>\n"
				"%s     </location>\n",
				prefix,
				prefix, cid,
				prefix, service_info_get_stgclass(si, "N/A"),
				prefix, (strlen(avail) > 0) ? "no" : "yes",
				prefix);
		service_info_clean(si);
		g_free(avail);
	} else {
		g_string_append_printf(result,
				"%s     <location>\n"
				"%s      <url>%s</url>\n"
				"%s      <stgclass>N/A</stgclass>\n"
				"%s      <available>no</available>\n"
				"%s     </location>\n",
				prefix,
				prefix, cid,
				prefix,
				prefix,
				prefix);
	}

	return g_string_free(result, FALSE);
}

static void
_dump_chunks_xml_NORMAL(const struct loc_context_s *lc, GString **s)
{
	chunk_pair_t *current = NULL;

	for(guint i=0; i < lc->rc->pairs->len; i++) {
		current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
		GByteArray *hash = CHUNKS_get_hash(current->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		char *loc = _chunk_location_row_xml(lc,
			CHUNKS_get_id(current->chunk)->str, "");
		g_string_append_printf(*s, 
				"   <chunk>\n"
				"    <locations>\n"
				"%s"
				"    </locations>\n"
				"    <position>%d</position>\n"
				"    <size>%"G_GINT64_FORMAT"</size>\n"
				"    <md5>%s</md5>\n"
				"   </chunk>\n",
				loc,
				current->position.meta,
				CHUNKS_get_size(current->chunk),
				str_hash);
		g_free(loc);
	}
}

static void
_dump_chunks_xml_DUPLI(const struct loc_context_s *lc, GString **s)
{

	chunk_pair_t *base = NULL;
	chunk_pair_t *current = NULL;
	int copies = 0;
	GString *urls = NULL;

	void _append(void) {
		GByteArray *hash = CHUNKS_get_hash(base->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		g_string_append_printf(*s,
				"   <chunk>\n"
				"    <nb-copies>%d</nb-copies>"
				"    <locations>\n"
				"%s"
				"    </locations>\n"
				"    <position>%d</position>\n"
				"    <size>%"G_GINT64_FORMAT"</size>\n"
				"    <md5>%s</md5>\n"
				"   </chunk>\n",
				copies,
				urls->str,
				base->position.meta,
				CHUNKS_get_size(base->chunk),
				str_hash);
		g_string_free(urls, TRUE);
	}

	void _append_loc(chunk_pair_t *pair) {
		char *loc = _chunk_location_row_xml(lc,
				CHUNKS_get_id(pair->chunk)->str, "");
		urls = g_string_append(urls, loc);
		g_free(loc);
	}

	for(guint i=0; i < lc->rc->pairs->len; i++) {
		if(!base) {	
			urls = g_string_new("");
			base = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			_append_loc(base);
			copies = 1;
		} else {
			current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			if(current->position.meta != base->position.meta)  {
				_append();
				base = NULL;
				i--;
			} else {
				_append_loc(current);
				copies ++;
			}
		}
	}

	_append();
}

static void
_dump_chunks_xml_RAIN(const struct loc_context_s *lc, GString **s)
{
	chunk_pair_t *base = NULL;
	chunk_pair_t *current = NULL;

	void _append_subchunk(chunk_pair_t *pair) {
		GByteArray *hash = CHUNKS_get_hash(pair->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		char *loc = _chunk_location_row_xml(lc,
				CHUNKS_get_id(pair->chunk)->str, " ");
		g_string_append_printf(*s,
				"    <sub-chunk>\n"
				"     <locations>\n"
				"%s"
				"     <locations>\n"
				"     <position>%d</position>\n"
				"     <parity>%s</parity>\n"
				"     <size>%"G_GINT64_FORMAT"</size>\n"
				"     <md5>%s</md5>\n"
				"    </sub-chunk>\n",
				loc,
				pair->position.rain,
				pair->position.parity ? "true" : "false",
				CHUNKS_get_size(pair->chunk),
				str_hash);
		g_free(loc);
	}

	for(guint i=0; i < lc->rc->pairs->len; i++) {
		if(!base) {	
			/* New meta chunk */
			base = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			g_string_append_printf(*s,
				"   <meta-chunk>\n"
				"    <position>%d</position>\n",
				base->position.meta);
			_append_subchunk(base);
		} else {
			current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			if(current->position.meta != base->position.meta)  {
				g_string_append_printf(*s, "   </meta-chunk>\n");
				base = NULL;
				i--;
			} else {
				_append_subchunk(current);
			}
		}
	}
}

static void
__dump_content_xml(const struct loc_context_s *lc, GString **s)
{
	struct storage_policy_s *sp = NULL;
	GSList *l = NULL;

	sp = _init_storage_policy(lc->namespace, CONTENTS_HEADERS_get_policy(lc->rc->header)->str);
	GByteArray *hash = CONTENTS_HEADERS_get_hash(lc->rc->header);
	char str_hash[1 + sizeof(chunk_hash_t) * 2];
	buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));

	g_string_append_printf(*s,
			" <content>\n"
			"  <name>%s</name>\n"
			"  <version>%"G_GINT64_FORMAT"</version>\n"
			"  <size>%"G_GINT64_FORMAT"</size>\n"
			"  <hash>%s</size>\n"
			"  <flags>%s</flags>"
			"  <nb-chunks>%"G_GUINT32_FORMAT"</nb-chunks>\n"
			"  <metadata-sys>%s</metadata-sys>\n",
			ALIASES_get_alias(lc->rc->alias)->str,
			ALIASES_get_version(lc->rc->alias),
			CONTENTS_HEADERS_get_size(lc->rc->header),
			str_hash,
			ALIASES_get_deleted(lc->rc->alias) ? "DELETED" : "ONLINE",
			g_array_index(lc->rc->pairs, chunk_pair_t, lc->rc->pairs->len).position.meta + 1,
			ALIASES_get_mdsys(lc->rc->alias)->str);

	*s = g_string_append(*s, "  <properties>\n");
	for (l=lc->rc->properties; l ;l=l->next)
		__dump_property_xml(l->data, s);

	*s = g_string_append(*s, 	"  </properties>\n");

	/* If content was deleted don't show chunk infos */
	if (!ALIASES_get_deleted(lc->rc->alias)) {
		*s = g_string_append(*s, "  <chunks>\n");
		if(!sp) {
			_dump_chunks_xml_NORMAL(lc, s);
		} else {
			switch(data_security_get_type(storage_policy_get_data_security(sp))) {
				case RAIN:
					_dump_chunks_xml_RAIN(lc, s);
					break;
				case DUPLI:
					_dump_chunks_xml_DUPLI(lc, s);
					break;
				default:
					_dump_chunks_xml_NORMAL(lc, s);
			}
		}
		*s = g_string_append(*s, "  </chunks>\n");
	}

	*s = g_string_append(*s, " </content>\n");

	storage_policy_clean(sp);
}

static char *
_chunk_location_row(const struct loc_context_s *lc, const char *cid)
{
	struct service_info_s *si = NULL;
	GString *result = g_string_new("");
	si = __service_info_from_chunkid(lc, cid);

	if(NULL != si) {
		g_string_append_printf(result, "%s (StgClass:%s)",
			cid, service_info_get_stgclass(si, "N/A"));
		service_info_clean(si);
	} else {
		g_string_append_printf(result, "%s : "
				"ERROR cannot find matching RAW-X", cid);
	}

	return g_string_free(result, FALSE);
}


static void
_dump_chunks_NORMAL(const struct loc_context_s *lc, GString **s)
{
	chunk_pair_t *current = NULL;
	for(guint i=0; i < lc->rc->pairs->len; i++) {
		current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
		char *loc = _chunk_location_row(lc, 
				CHUNKS_get_id(current->chunk)->str);
		GByteArray *hash = CHUNKS_get_hash(current->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		char *avail = _check_chunk(CHUNKS_get_id(current->chunk)->str);
		g_string_append_printf(*s,
				"\t\t[ Chunk.%d ] %s\n"
				"\t\t\t   Location : %s\n"
				"\t\t\t       Size : %"G_GINT64_FORMAT"\n"
				"\t\t\t        MD5 : %s\n",
				current->position.meta, avail,
				loc,
				CHUNKS_get_size(current->chunk),
				str_hash);
		g_free(avail);
		g_free(loc);
	}
}

static void
_dump_chunks_DUPLI(const struct loc_context_s *lc, GString **s)
{

	chunk_pair_t *base = NULL;
	chunk_pair_t *current = NULL;
	int copies = 0;
	GString *urls = NULL;

	void _append(void) {
		GByteArray *hash = CHUNKS_get_hash(base->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		g_string_append_printf(*s,
				"\t\t[ Chunk.%d (%d copies) ]\n"
				"%s"
				"\t\t\t   Position : %d\n"
				"\t\t\t       Size : %"G_GINT64_FORMAT"\n"
				"\t\t\t        MD5 : %s\n",
				base->position.meta, copies,
				urls->str,
				base->position.meta,
				CHUNKS_get_size(base->chunk),
				str_hash);
		g_string_free(urls, TRUE);
	}

	void _append_loc(chunk_pair_t *pair) {
		char *loc = _chunk_location_row(lc,
				CHUNKS_get_id(pair->chunk)->str);
		char *avail = _check_chunk(CHUNKS_get_id(pair->chunk)->str);
		g_string_append_printf(urls, "\t\t\t   Location %s: %s\n", avail, loc);
		g_free(loc);
		g_free(avail);
	}

	for(guint i=0; i < lc->rc->pairs->len; i++) {
		if(!base) {	
			urls = g_string_new("");
			base = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			_append_loc(base);
			copies = 1;
		} else {
			current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			if(current->position.meta != base->position.meta)  {
				_append();
				base = NULL;
				i--;
			} else {
				_append_loc(current);
				copies ++;
			}
		}
	}

	_append();
}

static void
_dump_chunks_RAIN(const struct loc_context_s *lc, GString **s)
{
	chunk_pair_t *base = NULL;
	chunk_pair_t *current = NULL;

	void _append_subchunk(chunk_pair_t *pair) {
		GByteArray *hash = CHUNKS_get_hash(pair->chunk);
		char str_hash[1 + sizeof(chunk_hash_t) * 2];
		buffer2str(hash->data, hash->len, str_hash, sizeof(str_hash));
		char *loc = _chunk_location_row(lc,
				CHUNKS_get_id(pair->chunk)->str);
		char *avail = _check_chunk(CHUNKS_get_id(pair->chunk)->str);
		g_string_append_printf(*s,
				"\t\t\t[ SubChunk.%d%s%s]\n"
				"\t\t\t   Location : %s\n"
				"\t\t\t       Size : %"G_GINT64_FORMAT"\n"
				"\t\t\t        MD5 : %s\n",
				pair->position.rain,
				pair->position.parity ? " (Parity) " : " ",
				avail,
				loc,
				CHUNKS_get_size(pair->chunk),
				str_hash);
		g_free(loc);
		g_free(avail);
	}

	for(guint i=0; i < lc->rc->pairs->len; i++) {
		if(!base) {	
			/* New meta chunk */
			base = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			g_string_append_printf(*s,
				"\t\t[ MetaChunk.%d ]\n",
				base->position.meta);
			_append_subchunk(base);
		} else {
			current = &g_array_index(lc->rc->pairs, chunk_pair_t, i);
			if(current->position.meta != base->position.meta)  {
				base = NULL;
				i--;
			} else {
				_append_subchunk(current);
			}
		}
	}
}

static void
__dump_content(const struct loc_context_s *lc, GString **s)
{
	struct beans_content_s *content = lc->rc;
	struct storage_policy_s *sp = NULL;
	GSList *l = NULL;

	const gchar *stgpol = content->header ? CONTENTS_HEADERS_get_policy(content->header)->str : "(nil)";
	sp = _init_storage_policy(lc->namespace, stgpol);

	char *str_hash = NULL;
	if (content->header) {
		GByteArray *hash = CONTENTS_HEADERS_get_hash(content->header);
		if (hash != NULL && hash->len > 0) {
			gint hash_len = 1 + sizeof(chunk_hash_t) * 2; // 2 digits per byte + '\0'
			str_hash = g_alloca(hash_len);
			buffer2str(hash->data, hash->len, str_hash, hash_len);
		}
	}

	g_string_append_printf(*s,
			"\t[ Content ]\n"
			"\t\t         Name : \"%s\"\n"
			"\t\t      Version : %"G_GINT64_FORMAT"\n"
			"\t\t         Size : %"G_GINT64_FORMAT" bytes\n"
			"\t\t         Hash : %s\n"
			"\t\t       Policy : %s\n"
			"\t\t        Flags : %s\n",
			ALIASES_get_alias(content->alias)->str,
			ALIASES_get_version(content->alias),
			content->header ? CONTENTS_HEADERS_get_size(content->header) : -1,
			str_hash,
			stgpol,
			ALIASES_get_deleted(content->alias) ? "DELETED" : "ONLINE");

	gint chunk_nb = ((content->pairs->len == 0)?
			0 : g_array_index(content->pairs, chunk_pair_t, content->pairs->len -1).position.meta + 1);
	g_string_append_printf(*s, "\t\t     Chunk nb : %d\n", chunk_nb);

	g_string_append_printf(*s, "\t\tSyst Metadata : [%s]\n", ALIASES_get_mdsys(content->alias)->str);

	*s = g_string_append(*s, "\t\t   Properties :\n");
	for (l=content->properties; l ;l=l->next)
		__dump_property(l->data, s);

	*s = g_string_append(*s,	"\n");

	/* If content was deleted don't show chunk infos */
	if (chunk_nb > 0 && !ALIASES_get_deleted(content->alias)) {
		*s = g_string_append(*s,
				"\t[ Chunks ]\n");
		if(!sp) {
			_dump_chunks_NORMAL(lc, s);
		} else {
			switch(data_security_get_type(storage_policy_get_data_security(sp))) {
				case RAIN:
					_dump_chunks_RAIN(lc, s);
					break;
				case DUPLI:
					_dump_chunks_DUPLI(lc, s);
					break;
				default:
					_dump_chunks_NORMAL(lc, s);
			}
		}
	}
	storage_policy_clean(sp);
}

static gboolean
_close_meta2_connection(struct metacnx_ctx_s *cnx, container_id_t cid)
{
	GError *ge = NULL;

	meta2_remote_container_close(&(cnx->addr), 60000, &ge, cid);

	metacnx_close(cnx);
	metacnx_clear(cnx);

	if (NULL != ge) {
		GRID_DEBUG("Meta2 connection closure failed : (%d), %s", ge->code, ge->message);
		g_clear_error(&ge);
		return FALSE;
	}

	return TRUE;
}


static void
__write_admin_info(gpointer k, gpointer v, gpointer gstr)
{
	GString **s = (GString **)gstr;
	*s = g_string_append(*s, "\t\t");
	gsize max_key_len = 40;
	gsize key_len = strlen((char*)k)+1;

	for(uint i = 0; (key_len < max_key_len) && (i < max_key_len - key_len); i++)
		*s = g_string_append(*s, " ");
	g_string_append_printf(*s,"%s : %s\n",(char*)k, (char*) v);
}

static void
__write_admin_info_xml(gpointer k, gpointer v, gpointer gstr)
{
	GString **s = (GString **)gstr;
	g_string_append_printf(*s,"   <%s>%s</%s>\n",(char*)k, (char*) v, (char*)k);
}

static void
__write_container_props_xml(gchar **props, GString **s)
{
	*s = g_string_append(*s, "  <properties>\n");
	for (uint i = 0; i < g_strv_length(props); i++) {
		char *p = strchr(props[i], '=');
		if(!p) {
			/* cannot split into k v, don't take care */
			continue;
		}
		*s = g_string_append(*s, "   <");
		*s = g_string_append_len(*s, props[i], p - props[i]);
		g_string_append_printf(*s, ">%s</", p);
		*s = g_string_append_len(*s, props[i], p - props[i]);
		*s = g_string_append(*s, ">\n");
	}

	*s = g_string_append(*s, "  </properties>\n");
}

static char *
_loc_context_to_xml(const struct loc_context_s *lc)
{
	(void) lc;
	GString *s = NULL;

	void _print_url_tab_xml(char **url_tab, const char *protocol)
	{
		int i = 0;
		if (url_tab) {
			while (url_tab[i])
				g_string_append_printf(s, "   <url>%s://%s</url>\n", protocol, url_tab[i++]);
		}
	}

	if(NULL != lc->rc)
		s = g_string_new("<content-info>\n");
	else
		s = g_string_new("<container-info>\n");
	g_string_append_printf(s, " <directory>\n"
				  "  <meta0>\n"
				  "   <url>tcp://%s</url>\n"
				  "  </meta0>\n",
				 lc->loc->m0_url);
	if (lc->loc->m1_url) {
		s = g_string_append(s, "  <meta1>\n");
		_print_url_tab_xml(lc->loc->m1_url, "tcp");
		s = g_string_append(s, "  </meta1>\n");
	}
	if (lc->loc->m2_url) {
		s = g_string_append(s, "  <meta2>\n");
		_print_url_tab_xml(lc->loc->m2_url, "tcp");
		s = g_string_append(s, "  </meta2>\n");
	}
	g_string_append_printf(s, " </directory>\n"
				  " <storage>\n"
				  "  <name>%s</name>\n"
				  "  <id>%s</id>\n",
				  lc->loc->container_name,
				  lc->loc->container_hexid);

	if(NULL != lc->admin_info && g_hash_table_size(lc->admin_info) > 0) {
		s = g_string_append(s, "  <admin-info>\n");
		g_hash_table_foreach(lc->admin_info, __write_admin_info_xml, &s);
		s = g_string_append(s, "  </admin-info>\n");
	}

	if(NULL != lc->container_props && g_strv_length(lc->container_props) > 0) {
		__write_container_props_xml(lc->container_props, &s);
	}

	s = g_string_append(s, " </storage>\n");

	if (NULL != lc->rc)
		__dump_content_xml(lc, &s);

	if(NULL != lc->rc)
		s = g_string_append(s, "</content-info>\n");
	else
		s = g_string_append(s, "</container-info>\n");

	return g_string_free(s, FALSE);
}

static char *
_loc_context_to_text(const struct loc_context_s *lc)
{
	GString *s = g_string_new("");

	void _print_url_tab(char **url_tab, const char *protocol)
	{
		int i = 0;
		if (url_tab) {
			while (url_tab[i])
				g_string_append_printf(s, "%s://%s ", protocol, url_tab[i++]);
		}
	}

	g_string_append_printf(s, 	"\n"
			"\t[ Directory ]\n"
			"\t\tMETA0 : tcp://%s\n",
					lc->loc->m0_url);
	if (lc->loc->m1_url) {
		s = g_string_append(s, "\t\tMETA1 : ");
		_print_url_tab(lc->loc->m1_url, "tcp");
		s = g_string_append(s, "\n");
	}
	if (lc->loc->m2_url) {
		s = g_string_append(s, "\t\tMETA2 : ");
		_print_url_tab(lc->loc->m2_url, "tcp");
		s = g_string_append(s, "\n");
	}
	g_string_append_printf(s,	"\n"
					"\t[ Container ]\n"
					"\t\t      Name : [%s]\n"
					"\t\t        ID : [%s]\n",
					lc->loc->container_name,
					lc->loc->container_hexid);

	s = g_string_append(s, "\t\tAdmin Info :\n");
	if(NULL != lc->admin_info && g_hash_table_size(lc->admin_info) > 0) {
		g_hash_table_foreach(lc->admin_info, __write_admin_info, &s);
	}
	g_string_append_printf(s, "\n");

	if(NULL != lc->container_props && g_strv_length(lc->container_props) > 0) {
		s = g_string_append(s, "\t\tProperties :\n");
		for (uint i = 0; i < g_strv_length(lc->container_props); i++) {
				g_string_append_printf(s, "\t\t\t     %s\n", lc->container_props[i]);
		}
		g_string_append_printf(s, "\n");
	}


	if (NULL != lc->rc)
		__dump_content(lc, &s);
	
	return g_string_free(s, FALSE);
}

static gboolean
_str_is_hexid(const gchar *str)
{
	const gchar *s;
	if (!str || !*str)
		return FALSE;
	for (s=str; *s ;s++) {
		if (!g_ascii_isxdigit(*s)) {
			GRID_DEBUG("non-xdigit character found : %c", *s);
			return FALSE;
		}
	}
	if ((s-str) == 64)
		return TRUE;

	GRID_DEBUG("Invalid string length : %"G_GSIZE_FORMAT, (s-str));
	return FALSE;
}

static void
_fresh_lb_pool(struct loc_context_s *lc)
{
	GError *err = NULL;

	if (NULL != (err = gridcluster_reload_lbpool(lc->glp))) {
		GRID_WARN("Failed to reload the LB pool services : (%d) %s",
				err->code, err->message);
		g_clear_error(&err);
	}
}

/* ------------------------- PUBLIC FUNCTIONS ----------------------------------- */

struct loc_context_s *
loc_context_init(gs_grid_storage_t *hc, struct hc_url_s *url, gs_error_t **p_e)
{
	gs_error_t *e = NULL;
	struct loc_context_s *ctx = NULL;
	char *ref_name = g_strdup(hc_url_get(url, HCURL_REFERENCE));

	if(!url)
		return NULL;

	ctx = g_malloc0(sizeof(struct loc_context_s));
	ctx->namespace = gs_get_namespace(hc);
	ctx->glp = grid_lbpool_create(ctx->namespace);

	_fresh_lb_pool(ctx);

	/* Locate the container */
	if (_str_is_hexid(ref_name)) {
		GRID_DEBUG("Considering %s is a hexadecimal container id\n", ref_name);
		ctx->loc = gs_locate_container_by_hexid(hc, ref_name, &e);
		if (ctx->loc)
			hc_url_set(url, HCURL_REFERENCE, ctx->loc->container_name);
	}
	else {
		GRID_DEBUG("Considering %s is a regular container id\n", ref_name);
		ctx->loc = gs_locate_container_by_name(hc, ref_name, &e);
	}

	g_free(ref_name);
	ref_name = NULL;

	if (!ctx->loc) {
		gs_error_set(&e, e ? e->code : 0, "Container reference not resolvable : %s\n",
				gs_error_get_message(e));
		goto label_error;
	}

	if (!ctx->loc->m0_url || !ctx->loc->m1_url || !ctx->loc->m2_url || !ctx->loc->m2_url[0]) {
		gs_error_set(&e, e ? e->code : 0, "Container reference partially missing (%p %p %p): %s\n",
				ctx->loc->m0_url, ctx->loc->m1_url, ctx->loc->m2_url,
				gs_error_get_message(e));
		goto label_error;
	}

	struct metacnx_ctx_s cnx;
	container_id_t cid;
	memcpy(&cid, hc_url_get_id(url), sizeof(container_id_t));

	if (!_open_meta2_connection(&cnx, ctx->loc->m2_url[0], &e)) {
		gs_error_set(&e, e ? e->code : 0, "Failed to open connection to meta2: %s\n",
				gs_error_get_message(e));
		goto label_error;
	}

	if (!_get_container_user_properties(hc, url, cid, &ctx->container_props, &e)) {
		gs_error_set(&e, e ? e->code : 0, "Container properties not found : %s\n",
				gs_error_get_message(e));
		goto label_error_close_cnx;
	}

	if (!_get_container_global_property(hc, &cnx, cid, &ctx->admin_info, &e)) {
		gs_error_set(&e, e ? e->code : 0, "Container admin entries not found : %s\n",
				gs_error_get_message(e));
		goto label_error_close_cnx;
	}

	/* Now Dump the content and its chunks */
	ctx->rc = NULL;
	if(hc_url_has(url, HCURL_PATH)) {
		if (NULL != (e = _get_content(&cnx, url, &ctx->rc))) {
			gs_error_set(&e, e ? e->code : 0, "Content not found: %s\n",
					gs_error_get_message(e));
			goto label_error_close_cnx;
		}
	}

	_close_meta2_connection(&cnx, cid);
	return ctx;

label_error_close_cnx:
	_close_meta2_connection(&cnx, cid);

label_error:
	loc_context_clean(ctx);
	if (p_e)
		*p_e = e;
	else
		gs_error_free(e);
	return NULL;
}

struct loc_context_s *
loc_context_init_retry(gs_grid_storage_t *hc, struct hc_url_s *url, gs_error_t **p_e)
{
	struct loc_context_s *lc = NULL;
	gs_error_t *e = NULL;

	for (int nb_refreshes = 1; nb_refreshes >= 0; nb_refreshes--) {
		gs_error_clear(&e);
		if (!(lc = loc_context_init(hc, url, &e))) {
			if (e && e->code == CODE_CONTAINER_NOTFOUND) {
				container_id_t cid;
				memcpy(&cid, hc_url_get_id(url), sizeof(container_id_t));
				gs_decache_container(hc, cid);
				continue;
			}
		}
		break;
	}
	if (!lc && !e) {
		e = g_malloc0(sizeof(gs_error_t));
		e->code = 500;
		e->msg = g_strdup("Cannot initialize loc_context structure");
	}
	if (e && p_e)
		*p_e = e;
	return lc;
}

static void
_beans_content_clean(struct beans_content_s *c)
{
	if(!c)
		return;
	if(NULL != c->alias)
		_bean_clean(c->alias);
	if(NULL != c->header)
		_bean_clean(c->header);
	if(NULL != c->properties) 	
		g_slist_free_full(c->properties, _bean_clean);
	if(NULL != c->pairs) {
		for(guint i =0; i < c->pairs->len; i++) {
			chunk_pair_t pair = g_array_index(c->pairs, chunk_pair_t, i);
			_bean_clean(pair.chunk);
			_bean_clean(pair.content);
		}
		g_array_free(c->pairs, TRUE);
	}
	g_free(c);
}

void
loc_context_clean(struct loc_context_s *lc)
{
	if (!lc)
		return;
	if (NULL != lc->loc)
		gs_container_location_free(lc->loc);

	if (NULL != lc->rc)
		_beans_content_clean(lc->rc);

	if (NULL != lc->admin_info)
		g_hash_table_destroy(lc->admin_info);

	if (NULL != lc->container_props)
		g_strfreev(lc->container_props);
	
	g_free(lc->container_stgpol);
	// do not free namespace
	grid_lbpool_destroy(lc->glp);

	g_free(lc);
}

char *
loc_context_to_string(const struct loc_context_s *lc, int xml)
{
	if(!lc)
		return NULL;

	if(xml)
		return _loc_context_to_xml(lc);
	else
		return _loc_context_to_text(lc);
}



char* loc_context_getstgpol_to_string(const struct loc_context_s *lc, gboolean bContent)
{
	if (bContent == TRUE) {
		return CONTENTS_HEADERS_get_policy(lc->rc->header)->str;
		
	} else {
	        if(NULL == lc->admin_info || g_hash_table_size(lc->admin_info) == 0)
        	        return NULL;

		return (char*) g_hash_table_lookup(lc->admin_info, GS_CONTAINER_PROPERTY_STORAGE_POLICY);
	}
}



