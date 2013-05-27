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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.location"
#endif

#include <glib.h>
#include <metautils.h>
#include <metacomm.h>
#include <hc_url.h>
#include <meta2_remote.h>
#include <meta2_services_remote.h>

#include <neon/ne_basic.h>
#include <neon/ne_request.h>
#include <neon/ne_session.h>

#include "./grid_client.h"
#include "./gs_internals.h"
#include "./loc_context.h"

struct loc_context_s {
	struct gs_container_location_s *loc;
	char **container_props;
	GHashTable *admin_info;
	char *container_stgpol;
	struct meta2_raw_content_v2_s *rc;
};

/* ------------------------------------------------------------------------------ */

static gboolean _close_meta2_connection(struct metacnx_ctx_s *cnx, container_id_t cid);



static void
__print_url_tab(char **url_tab, const char *protocol, GString **s)
{
	int i = 0;
	if (url_tab) {
		while (url_tab[i])
			g_string_append_printf(*s, "%s://%s ", protocol, url_tab[i++]);
	}
}

static void
__print_url_tab_xml(char **url_tab, const char *protocol, GString **s)
{
	int i = 0;
	if (url_tab) {
		while (url_tab[i])
			g_string_append_printf(*s, "   <url>%s://%s</url>\n", protocol, url_tab[i++]);
	}
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
_check_chunk(const meta2_raw_chunk_t *rc)
{
	ne_session *session=NULL;
	ne_request *request=NULL;
	ne_request *request_update=NULL;
	char chunk_hash_str[128];
	char *update_uri = NULL;
	int ne_rc;
	GString *gs = g_string_new("");
	GError *e = NULL;


	gchar dst[128];
	gsize dst_ip_size = sizeof(dst);
	guint16 port = 0;

	addr_info_get_addr(&(rc->id.addr), dst, dst_ip_size, &port, &e);
	if(NULL != e) {
		g_clear_error(&e);
		return g_string_free(gs, TRUE);
	}

	session = ne_session_create("http", dst, port);

	if (!session) {
		goto error_label;
	}

	ne_set_connect_timeout(session, 10);
	ne_set_read_timeout(session, 30);

	bzero(chunk_hash_str, sizeof(chunk_hash_str));
	chunk_hash_str[0] = '/';
	buffer2str(rc->id.id, sizeof(rc->id.id), chunk_hash_str + 1, sizeof(chunk_hash_str) - 2);

	request = ne_request_create (session, "HEAD", chunk_hash_str);
	if (!request) {
		goto error_label;
	}

	/* Now send the request */
	switch (ne_rc = ne_request_dispatch(request)) {
		case NE_OK:
			if (ne_get_status(request)->klass != 2) {
				g_string_append_printf(gs, "(Chunk unavailable : %s)", ne_get_error(session));
				goto error_label;
			}
			break;

		default:
			g_string_append_printf(gs, "(Chunk unavailable : %s)", ne_get_error(session));
			goto error_label;
	}

error_label:

	if (update_uri)
		g_free(update_uri);

	if (request_update)
		ne_request_destroy (request_update);
	if (request)
		ne_request_destroy (request);
	if (session)
		ne_session_destroy (session);

	if(gs->len > 0)
		return g_string_free(gs, FALSE);

	return g_string_free(gs, TRUE);
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

                m1 = gs_resolve_meta1v2(hc, cid, 1, excluded, &gerr);

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
_get_container_global_property(gs_grid_storage_t *hc, struct hc_url_s *url, struct metacnx_ctx_s *cnx, container_id_t cid, 
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
                			GSERRORCAUSE(gserr, gs_error_get_message(e), 
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
	g_slist_free(prop_list);

	/* Ensure we have some mandatory properties */
	if(!g_hash_table_lookup(*ht, GS_CONTAINER_PROPERTY_STORAGE_POLICY))
		g_hash_table_insert(*ht, g_strdup(GS_CONTAINER_PROPERTY_STORAGE_POLICY), g_strdup("namespace default"));
	if(!g_hash_table_lookup(*ht, GS_CONTAINER_PROPERTY_VERSIONING))
		g_hash_table_insert(*ht, g_strdup(GS_CONTAINER_PROPERTY_VERSIONING), g_strdup("namespace default"));

	return 1;
}

static status_t
_get_raw_content(struct metacnx_ctx_s *cnx, struct hc_url_s *url, meta2_raw_content_v2_t **raw_content, gs_error_t **gserr)
{
	GSList *beans = NULL;
	char target[64];
	struct meta2_raw_content_s *raw_content_v1 = NULL;
	GError *gerr = NULL;

	/* Build targer */
	bzero(target, 64);
	addr_info_to_string(&(cnx->addr), target, 64);

	gerr = m2v2_remote_execute_GET(target, NULL, url, 0, &beans);
	if (gerr != NULL) {
		GSERRORCAUSE(gserr, gerr, "Cannot stat content in container");
		g_error_free(gerr);
		return 0;
	}

	raw_content_v1 = g_malloc0(sizeof(struct meta2_raw_content_s));
	if (!map_raw_content_from_beans(raw_content_v1, beans)) {
		GSERRORSET(gserr, "Failed to convert beans to raw_content");
		g_free(raw_content_v1);
		return 0;
	}

	*raw_content = meta2_raw_content_v1_get_v2(raw_content_v1, &gerr);
	meta2_raw_content_clean(raw_content_v1);
	if (NULL == *raw_content) {
		GSERRORSET(gserr, "Failed to convert raw_content to raw_content_v2");
		return 0;
	}

	GSList *properties = NULL;
	map_properties_from_beans(&properties,beans);
	(*raw_content)->properties = properties;

	gchar *policy = NULL;
	map_policy_from_beans(&policy, beans);
	(*raw_content)->header.policy = policy;

	if (gerr)
		g_error_free(gerr);

	return 1;
}

static void
__dump_raw_chunk_xml(struct meta2_raw_chunk_s *chunk, int group_chunks, int number_of_chunks_at_this_pos, GString **s)
{
	static int chunk_number = 0;
	gchar str_hash[1 + sizeof(chunk_hash_t)*2];
	gchar str_addr[1024], str_id[STRLEN_CHUNKID];
	gchar *available_value;

	bzero(str_hash, sizeof(str_hash));
	buffer2str(chunk->id.id, sizeof(chunk->id.id), str_id, sizeof(str_id));
	buffer2str(chunk->hash, sizeof(chunk->hash), str_hash, sizeof(str_hash));
	addr_info_to_string(&(chunk->id.addr), str_addr, sizeof(str_addr));
	char * tmp = NULL;
	tmp = _check_chunk(chunk);

	if (!group_chunks || chunk_number == 0) {
		g_string_append_printf(*s, "   <chunk>\n");
		g_string_append_printf(*s, "    <position>%u</position>\n", chunk->position);
	}

	if (group_chunks && chunk_number == 0) {
		g_string_append_printf(*s,
				"    <nb-copy>%d</nb-copy>\n",
				number_of_chunks_at_this_pos);
	}

	available_value = tmp ? g_strconcat("FALSE(", tmp, ")", NULL) : g_strdup("TRUE");

	if (group_chunks) {
		if (chunk_number == 0)
			g_string_append_printf(*s,
					"    <locations>\n");
		g_string_append_printf(*s,
				"     <location>\n");
		g_string_append_printf(*s,
				"      <url>tcp://%s</url>\n"
				"      <id>%s</id>\n"
				"      <path>%s</path>\n"
				"      <available>%s</available>\n",
				str_addr, str_id, chunk->id.vol, available_value);
	} else {
		g_string_append_printf(*s,
				"    <url>tcp://%s</url>\n"
				"    <id>%s</id>\n"
				"    <path>%s</path>\n"
				"    <available>%s</available>\n",
				str_addr, str_id, chunk->id.vol, available_value);
	}

	if (group_chunks) {
		g_string_append_printf(*s, "     </location>\n");
		if (chunk_number + 1 == number_of_chunks_at_this_pos)
			g_string_append_printf(*s,	"    </locations>\n");
	}

	if (!group_chunks || chunk_number + 1 == number_of_chunks_at_this_pos) {
		g_string_append_printf(*s,
						"    <size>%"G_GINT64_FORMAT"</size>\n"
						"    <md5>%s</md5>\n"
						"    <flags>%04X</flags>\n",
						chunk->size, str_hash, chunk->flags);
		g_string_append_printf(*s, "   </chunk>\n");
	}

	g_free(tmp);
	g_free(available_value);

	if (++chunk_number == number_of_chunks_at_this_pos)
		chunk_number = 0;
}

static void
__dump_raw_chunk(struct meta2_raw_chunk_s *chunk, int group_chunks, int is_last_chunk_of_group, GString **s)
{
	gchar str_hash[1 + sizeof(chunk_hash_t)*2];
	gchar str_addr[1024], str_id[STRLEN_CHUNKID];

	bzero(str_hash, sizeof(str_hash));
	buffer2str(chunk->id.id, sizeof(chunk->id.id), str_id, sizeof(str_id));
	buffer2str(chunk->hash, sizeof(chunk->hash), str_hash, sizeof(str_hash));
	addr_info_to_string(&(chunk->id.addr), str_addr, sizeof(str_addr));

	if (group_chunks) {
		g_string_append_printf(*s,	"\t\t\t     Url : tcp://%s"
				" Id=%s"
				" Path=%s\n",
				str_addr, str_id, chunk->id.vol);
	} else {
		g_string_append_printf(*s,
				"\t\t\t     Url : tcp://%s\n"
				"\t\t\t      Id : %s\n"
				"\t\t\t    Path : %s\n",
				str_addr, str_id, chunk->id.vol);
	}

	char * tmp = NULL;
	tmp = _check_chunk(chunk);
	if(NULL != tmp) {
		g_string_append_printf(*s,      "\t\t\t           %s\n", tmp);
		g_free(tmp);
	}

	if (!group_chunks || is_last_chunk_of_group) {
		g_string_append_printf(*s,	"\t\t\tPosition : %"G_GUINT32_FORMAT"\n"
						"\t\t\t    Size : %"G_GINT64_FORMAT" bytes\n"
						"\t\t\t     Md5 : %s\n"
						"\t\t\t   Flags : %04X\n\n",
						chunk->position, chunk->size, str_hash, chunk->flags);
	}
}

static void
__dump_chunks_xml(GHashTable *chunk_ht, GString **s, int group_chunks)
{
	int cur_pos = 0, list_len;
	GSList **p_chunk_list = NULL, *iter_chunk_list;

	while (TRUE) {
		if (NULL == (p_chunk_list = g_hash_table_lookup(chunk_ht, &cur_pos)))
			break;
		list_len = g_slist_length(*p_chunk_list);
		for (iter_chunk_list = *p_chunk_list; iter_chunk_list; iter_chunk_list = iter_chunk_list->next) {
			__dump_raw_chunk_xml(iter_chunk_list->data, group_chunks, list_len, s);
		}
		cur_pos++;
	}

}

static void
__dump_chunks(GHashTable *chunk_ht, GString **s, int group_chunks)
{
	int cur_pos = 0, length;
	GSList **p_chunk_list = NULL, *iter_chunk_list;

	while (TRUE) {
		if (NULL == (p_chunk_list = g_hash_table_lookup(chunk_ht, &cur_pos)))
			break;
		for (iter_chunk_list = *p_chunk_list; iter_chunk_list; iter_chunk_list = iter_chunk_list->next) {
			// display [ Chunk.N ] if group_chunk is false, or if group_chunk is true and we deal with
			// the first chunk.
			if (!group_chunks || iter_chunk_list == *p_chunk_list) {
				g_string_append_printf(*s,	"\n"
						"\t\t[ Chunk.%u ", cur_pos);
				if (group_chunks && (length = g_slist_length(*p_chunk_list)) > 1)
					g_string_append_printf(*s, "(%i copies)", length);
				*s = g_string_append(*s, " ]\n\n");
			}
			__dump_raw_chunk(iter_chunk_list->data, group_chunks, iter_chunk_list->next == NULL, s);
		}
		cur_pos++;
	}

}

static void
__dump_property_xml(meta2_property_t *prop, GString **s)
{
	gchar *value = NULL;

	if (prop->value) {
		// Make sure value is \0 terminated
		value = g_strndup((const gchar*)prop->value->data, prop->value->len);
		g_string_append_printf(*s, "   <%s>%s</%s>\n", prop->name, value, prop->name);
		g_free(value);
	} else {
		g_string_append_printf(*s, "<%s></%s>\n", prop->name, prop->name);		
	}
}

static void
__dump_property(meta2_property_t *prop, GString **s)
{
	gchar *value = NULL;

	if (prop->value) {
		// Make sure value is \0 terminated
		value = g_strndup((const gchar*)prop->value->data, prop->value->len);
		g_string_append_printf(*s, "\t\t\t\t%s=[%s]\n", prop->name, value);
		g_free(value);
	} else {
		g_string_append_printf(*s, "\t\t\t\t%s=[]\n", prop->name);		
	}
}

static void
__dump_raw_content_xml(meta2_raw_content_v2_t *raw_content, GString **s, int group_chunks)
{
	struct meta2_raw_content_header_s *header = NULL;
	struct meta2_raw_chunk_s *cur_chunk;
	GHashTable *chunk_ht = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
	GSList *l, **p_chunk_list = NULL;
	int cur_pos;

	header = &(raw_content->header);

	g_string_append_printf(*s, 	" <content>\n"
        				"  <name>%s</name>\n"
        				"  <version>%"G_GINT64_FORMAT"</version>\n"
        				"  <size>%"G_GINT64_FORMAT"</size>\n"
        				"  <flags>",
					header->path, header->version, header->size);
	switch(header->flags) {
	case 0:
		*s = g_string_append(*s, "ONLINE");
		break;;
	case 1:
		*s = g_string_append(*s, "Pending ADD");
		break;;
	case 3:
		*s = g_string_append(*s, "Pending APPEND");
		break;;
	case -1:
		*s = g_string_append(*s, "Pending REMOVE");
		break;;
	case 2:
		*s = g_string_append(*s, "ERRONEOUS");
		break;;
	case 4:
		*s = g_string_append(*s, "DELETED");
		break;;
	default:
		*s = g_string_append(*s, "UNKNOWN");
	}

	g_string_append_printf(*s, 	" (%04X)</flags>\n"
					"  <nb-chunks>%"G_GUINT32_FORMAT"</nb-chunks>\n",
					header->flags, header->nb_chunks);
	if(NULL != header->metadata) {
		g_string_append_printf(*s, "  <metadata>%.*s</metadata>\n",
				(int)header->metadata->len,
				header->metadata->data);
	}
	
	if(NULL != header->system_metadata) {
		g_string_append_printf(*s, "  <metadata-sys>%.*s</metadata-sys>\n",
				(int)header->system_metadata->len,
				header->system_metadata->data);
	}

	*s = g_string_append(*s, "  <properties>\n");
	for (l=raw_content->properties; l ;l=l->next)
		__dump_property_xml(l->data, s);
	*s = g_string_append(*s, 	"  </properties>\n"
					"  <chunks>\n");

	for (l=raw_content->raw_chunks; l; l=l->next) {
		cur_chunk = l->data;
		p_chunk_list = g_hash_table_lookup(chunk_ht, &(cur_chunk->position));
		if (p_chunk_list == NULL) {
			p_chunk_list = calloc(1, sizeof(GSList*));
			g_hash_table_insert(chunk_ht, &(cur_chunk->position), p_chunk_list);
		}
		*p_chunk_list = g_slist_append(*p_chunk_list, cur_chunk);
	}

	__dump_chunks_xml(chunk_ht, s, group_chunks);

	*s = g_string_append(*s, 	"  </chunks>\n"
					" </content>\n");

	cur_pos = 0;
	while (TRUE) {
		if (NULL == (p_chunk_list = g_hash_table_lookup(chunk_ht, &cur_pos)))
			break;
		g_slist_free(*p_chunk_list);
		cur_pos++;
	}
	g_hash_table_destroy(chunk_ht);
}

static void
__dump_raw_content(meta2_raw_content_v2_t *raw_content, GString **s, int group_chunks)
{
	struct meta2_raw_content_header_s *header = NULL;
	struct meta2_raw_chunk_s *cur_chunk;
	GHashTable *chunk_ht = g_hash_table_new_full(g_int_hash, g_int_equal, NULL, g_free);
	GSList *l, **p_chunk_list = NULL;
	int cur_pos;

	header = &(raw_content->header);

	g_string_append_printf(*s, 	"\n"
					"\t[ Content ]\n\n"
        				"\t\t         Name : \"%s\"\n"
        				"\t\t      Version : %"G_GINT64_FORMAT"\n"
        				"\t\t         Size : %"G_GINT64_FORMAT" bytes\n"
        				"\t\t       Policy : %s\n"
        				"\t\t        Flags : %s\n",
					header->path, header->version, header->size, header->policy, header->deleted ? "DELETED" : "ONLINE");

	g_string_append_printf(*s,	"\t\t     Chunk nb : %"G_GUINT32_FORMAT"\n", header->nb_chunks);

	if (!header->metadata)
		*s = g_string_append(*s, "\t\tUser Metadata : []\n");
	else
		g_string_append_printf(*s, "\t\tUser Metadata : [%.*s]\n",
				(int)header->metadata->len,
				header->metadata->data);

	if (!header->system_metadata)
		*s = g_string_append(*s, "\t\tSyst Metadata : []\n");
	else
		g_string_append_printf(*s, "\t\tSyst Metadata : [%.*s]\n",
				(int)header->system_metadata->len,
				header->system_metadata->data);

	*s = g_string_append(*s, "\t\t   Properties :\n");
	for (l=raw_content->properties; l ;l=l->next)
		__dump_property(l->data, s);

	*s = g_string_append(*s,	"\n");

	/* If content was deleted don't show chunk infos */
	if (header->deleted)
		return;

	*s = g_string_append(*s,	"\n"
					"\t[ Chunks ]\n");
	for (l=raw_content->raw_chunks; l; l=l->next) {
		cur_chunk = l->data;
		p_chunk_list = g_hash_table_lookup(chunk_ht, &(cur_chunk->position));
		if (p_chunk_list == NULL) {
			p_chunk_list = calloc(1, sizeof(GSList*));
			g_hash_table_insert(chunk_ht, &(cur_chunk->position), p_chunk_list);
		}
		*p_chunk_list = g_slist_append(*p_chunk_list, cur_chunk);
	}

	__dump_chunks(chunk_ht, s, group_chunks);

	*s = g_string_append(*s, "\n");

	cur_pos = 0;
	while (TRUE) {
		if (NULL == (p_chunk_list = g_hash_table_lookup(chunk_ht, &cur_pos)))
			break;
		g_slist_free(*p_chunk_list);
		cur_pos++;
	}
	g_hash_table_destroy(chunk_ht);
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
_loc_context_to_xml(const struct loc_context_s *lc, int group_chunks)
{
	(void) lc;
	GString *s = NULL;
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
		__print_url_tab_xml(lc->loc->m1_url, "tcp", &s);
		s = g_string_append(s, "  </meta1>\n");
	}
	if (lc->loc->m2_url) {
		s = g_string_append(s, "  <meta2>\n");
		__print_url_tab_xml(lc->loc->m2_url, "tcp", &s);
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
		__dump_raw_content_xml(lc->rc, &s, group_chunks);

	if(NULL != lc->rc)
		s = g_string_append(s, "</content-info>\n");
	else
		s = g_string_append(s, "</container-info>\n");

	return g_string_free(s, FALSE);
}

static char *
_loc_context_to_text(const struct loc_context_s *lc, int group_chunks)
{
	GString *s = g_string_new("");
	g_string_append_printf(s, 	"\n"
					"\t[ Directory ]\n\n"
					"\t\tMETA0 : tcp://%s\n",
					lc->loc->m0_url);
	if (lc->loc->m1_url) {
		s = g_string_append(s, "\t\tMETA1 : ");
		__print_url_tab(lc->loc->m1_url, "tcp", &s);
		s = g_string_append(s, "\n");
	}
	if (lc->loc->m2_url) {
		s = g_string_append(s, "\t\tMETA2 : ");
		__print_url_tab(lc->loc->m2_url, "tcp", &s);
		s = g_string_append(s, "\n");
	}
	g_string_append_printf(s,	"\n"
					"\t[ Container ]\n\n"
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
		__dump_raw_content(lc->rc, &s, group_chunks);
	
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

/* ------------------------- PUBLIC FUNCTIONS ----------------------------------- */

struct loc_context_s *
loc_context_init(gs_grid_storage_t *hc, struct hc_url_s *url)
{
	gs_error_t *e = NULL;
	struct loc_context_s *ctx = NULL;

	if(!url)
		return NULL;

	ctx = g_malloc0(sizeof(struct loc_context_s));
	/* Locate the container */
	if (_str_is_hexid(hc_url_get(url, HCURL_REFERENCE))) {
		GRID_DEBUG("Considering %s is a hexidecimal container id\n", hc_url_get(url, HCURL_REFERENCE));
		ctx->loc = gs_locate_container_by_hexid(hc, hc_url_get(url, HCURL_REFERENCE), &e);
	}
	else {
		GRID_DEBUG("Considering %s is a regular container id\n", hc_url_get(url, HCURL_REFERENCE));
		ctx->loc = gs_locate_container_by_name(hc, hc_url_get(url, HCURL_REFERENCE), &e);
	}

	if (!ctx->loc) {
		g_printerr("Container reference not resolvable : %s\n", gs_error_get_message(e));
		loc_context_clean(ctx);
		gs_error_free(e);
		return NULL;
	}

	if (!ctx->loc->m0_url || !ctx->loc->m1_url || !ctx->loc->m2_url || !ctx->loc->m2_url[0]) {
		g_printerr("Container reference partially missing (%p %p %p): %s\n",
				ctx->loc->m0_url, ctx->loc->m1_url, ctx->loc->m2_url,
				gs_error_get_message(e));
		loc_context_clean(ctx);
		gs_error_free(e);
		return NULL;
	}

	struct metacnx_ctx_s cnx;
	container_id_t cid;
	memcpy(&cid, hc_url_get_id(url), sizeof(container_id_t));

	if (!_open_meta2_connection(&cnx, ctx->loc->m2_url[0], &e)) {
		g_printerr("Failed to open connection to meta2: %s\n", gs_error_get_message(e));
		loc_context_clean(ctx);
		gs_error_free(e);
		return NULL;
	}

	if (!_get_container_user_properties(hc, url, cid, &ctx->container_props, &e)) {
		g_printerr("Container properties not found : %s\n", gs_error_get_message(e));
		_close_meta2_connection(&cnx, cid);
		loc_context_clean(ctx);
		gs_error_free(e);
		return NULL;
	}

	if (!_get_container_global_property(hc, url, &cnx, cid, &ctx->admin_info, &e)) {
		g_printerr("Container admin entries not found : %s\n", gs_error_get_message(e));
		_close_meta2_connection(&cnx, cid);
		loc_context_clean(ctx);
		gs_error_free(e);
		return NULL;
	}

	/* Now Dump the content and its chunks */
	if(hc_url_has(url, HCURL_PATH)) {
		if (!_get_raw_content(&cnx, url, &ctx->rc, &e)) {
			g_printerr("Content not found: %s\n", gs_error_get_message(e));
			_close_meta2_connection(&cnx, cid);
			loc_context_clean(ctx);


			gs_error_free(e);
			return NULL;
		}
	} else {
		ctx->rc = NULL;
	}

	_close_meta2_connection(&cnx, (guint8*)hc_url_get_id(url));

	return ctx;
}

void
loc_context_clean(struct loc_context_s *lc)
{
	if (!lc)
		return;
	if (NULL != lc->loc)
		gs_container_location_free(lc->loc);

	if (NULL != lc->rc)
		meta2_raw_content_v2_clean(lc->rc);

	if (NULL != lc->admin_info)
		g_hash_table_destroy(lc->admin_info);

	if (NULL != lc->container_props)
		g_strfreev(lc->container_props);
	
	g_free(lc);
}

char *
loc_context_to_string(const struct loc_context_s *lc, int xml, int group_chunks)
{
	if(!lc)
		return NULL;

	if(xml)
		return _loc_context_to_xml(lc, group_chunks);
	else
		return _loc_context_to_text(lc, group_chunks);
}
