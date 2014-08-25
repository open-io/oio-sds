#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "m2v2.utils"
#endif

#include <string.h>

#include <metautils/lib/metautils.h>

#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_utils.h>
#include <meta2v2/meta2_backend_internals.h>
#include <meta2v2/meta2_macros.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>


/* ------------------------ INTERNALS -----------------------*/

static GByteArray *
_hex_string_to_byte_array(const gchar *src)
{
	GByteArray *gba = g_byte_array_new();
	size_t bufsize = strlen(src) / 2;
	guint8 buf[bufsize];
	hex2bin(src, buf, bufsize, NULL);
	g_byte_array_append(gba, buf, bufsize);
	return gba;
}

static gpointer
_generate_property_from_mdusr(const char *alias, GByteArray *mdusr)
{
	if(!mdusr || mdusr->len <= 0)
		return NULL;

	gpointer prop = _bean_create(&descr_struct_PROPERTIES);
	PROPERTIES_set2_alias(prop, alias);
	PROPERTIES_set_alias_version(prop, 1L);
	PROPERTIES_set2_key(prop, MDUSR_PROPERTY_KEY);
	PROPERTIES_set2_value(prop, mdusr->data, mdusr->len);
	PROPERTIES_set_deleted(prop, FALSE);

	return prop;
}

static GByteArray *
_extract_mdusr_from_props(GSList *props)
{
	GSList *l = NULL;
	GByteArray *result = NULL;

	GRID_DEBUG("%d properties to check", g_slist_length(props));

	for(l = props; l && l->data; l = l->next) {
		if(!g_ascii_strcasecmp(PROPERTIES_get_key(l->data)->str,
				MDUSR_PROPERTY_KEY)) {
			result = g_byte_array_append(g_byte_array_new(),
					PROPERTIES_get_value(l->data)->data, PROPERTIES_get_value(l->data)->len);
			GRID_DEBUG("Found mdusr : %.*s", PROPERTIES_get_value(l->data)->len,
			(char *) PROPERTIES_get_value(l->data)->data);
			return result;
			//break;
		}
	}

	GRID_DEBUG("No mdusr found in properties");

	return NULL /*result*/;
}

static GError *
_fill_chunk_id(chunk_id_t *cid, gpointer chunk)
{
	/*
	 * ^([^:]+)://(([a-fA-F0-9.:\[\]])(:([^/]+))?)/(([^?]*)[?]?(.*))$
	 * $1 : schema
	 * $2 : IP:PORT
	 * $3 : IP
	 * $4 : ":" PORT
	 * $5 : PORT
	 * $6 : QUERY STRING
	 * $7 : URI
	 * $8 : ARGS (packed)
	 */
	GError *e = NULL;
	/* chunk v2 id => http://ip:port/vol/CID */
	char *idv2 = CHUNKS_get_id(chunk)->str;
	char **url_tok = g_strsplit(idv2, "/", 0);

	if(g_strv_length(url_tok) >= 5) {
		char ** tok_addr = g_strsplit(url_tok[2], ":", 2);
		GString *vol = g_string_new("");
		for(guint i = 3; i < g_strv_length(url_tok) - 1; i++)
			g_string_append_printf(vol, "/%s", url_tok[i]);
		memcpy(cid->vol, vol->str, MIN(strlen(vol->str), sizeof(cid->vol) - 1));
		g_string_free(vol, TRUE);
		if(g_strv_length(tok_addr) == 2) {
			addr_info_t *pa = build_addr_info(tok_addr[0], atoi(tok_addr[1]), &e);
			if(NULL == e) {
				memcpy(&(cid->addr), pa, sizeof(addr_info_t));
				hex2bin(url_tok[g_strv_length(url_tok) - 1], cid->id, sizeof(cid->id), &e);
			}
			if(NULL != pa)
				g_free(pa);
		} else {
			e = g_error_new(GQ(), 400, "Unparsable chunk id : [%s]", idv2);
		}
		if(NULL != tok_addr)
			g_strfreev(tok_addr);
	} else {
		e = g_error_new(GQ(), 400, "Unparsable chunk id : [%s]", idv2);
	}

	if(NULL != url_tok)
		g_strfreev(url_tok);

	return e;
}

static GSList *
_build_chunk_info_list(GSList *chunks, GSList *contents)
{
	GSList *ci_list = NULL;
	GSList *l1 = NULL;
	GSList *l2 = NULL;
	GError *e = NULL;
	guint32 nb_chunks = g_slist_length(chunks);

	for(l1 = chunks; l1 && l1->data; l1 = l1->next) {
		chunk_info_t *ci = g_malloc0(sizeof(chunk_info_t));
		ci->nb = nb_chunks;
		ci->size = CHUNKS_get_size(l1->data);
		e = _fill_chunk_id(&(ci->id), l1->data);

		if(NULL != e) {
			GRID_WARN("Error while converting beans in raw_chunk : %s", e->message);
			g_clear_error(&e);
			g_free(ci);
			continue;
		}

		for(l2 = contents; l2 && l2->data; l2 = l2->next) {
			if(0 == g_ascii_strcasecmp(CHUNKS_get_id(l1->data)->str, CONTENTS_get_chunk_id(l2->data)->str)) {
				char **pos_tok = g_strsplit(CONTENTS_get_position(l2->data)->str, ".", 0);
				ci->position = g_ascii_strtoll(pos_tok[0], NULL, 10);
				g_strfreev(pos_tok);
				ci_list = g_slist_prepend(ci_list, ci);
				ci = NULL;
				break;
			}
		}

		if(NULL != ci) {
			g_free(ci);
		}
	}

	return ci_list;
}

static guint32
_build_raw_chunks_list(GSList *chunks, GSList *contents, GSList ** meta2_raw_chunk_lst)
{
	GError *e = NULL;
	guint32 nbChunks = 0;

	for(; chunks ; chunks = chunks->next) {
		struct bean_CHUNKS_s *chunk = chunks->data;

		meta2_raw_chunk_t *rchunk = g_malloc0(sizeof(meta2_raw_chunk_t));

		GByteArray *hash = CHUNKS_get_hash(chunk);
		memcpy(&(rchunk->hash), hash->data, sizeof(rchunk->hash));

		rchunk->size = CHUNKS_get_size(chunk);
		e = _fill_chunk_id(&(rchunk->id), chunk);

		if(NULL != e) {
			GRID_WARN("Error while converting beans in raw_chunk : %s", e->message);
			g_clear_error(&e);
			meta2_raw_chunk_clean(rchunk);
			continue;
		}

		GSList *l2;
		for (l2 = contents; l2 ; l2 = l2->next) {
			struct bean_CONTENTS_s *content = l2->data;
			if (0 == g_ascii_strcasecmp(CHUNKS_get_id(chunk)->str, CONTENTS_get_chunk_id(content)->str)) {
				char **pos_tok = g_strsplit(CONTENTS_get_position(content)->str, ".", 0);
				rchunk->position = g_ascii_strtoll(pos_tok[0], NULL, 10);
				if ( rchunk->position + 1  > nbChunks )
					nbChunks = rchunk->position + 1 ;
				g_strfreev(pos_tok);
				*meta2_raw_chunk_lst = g_slist_prepend(*meta2_raw_chunk_lst, rchunk);
				rchunk = NULL;
				break;
			}
		}

		if(NULL != rchunk) {
			meta2_raw_chunk_clean(rchunk);
		}
	}

	return nbChunks;
}

static void
_fill_raw_content_v2_with_alias(meta2_raw_content_v2_t *rc, gpointer alias)
{
	memset(rc->header.path, '\0', sizeof(rc->header.path));
	g_strlcpy(rc->header.path, ALIASES_get_alias(alias)->str,
			sizeof(rc->header.path));

	/* Map alias metadata on the system metadata */
	GString *md = ALIASES_get_mdsys(alias);
	g_byte_array_set_size(rc->header.system_metadata, 0);
	g_byte_array_append(rc->header.system_metadata, (guint8*)md->str, md->len);
}

static void
_fill_raw_content_with_alias(meta2_raw_content_t *rc, gpointer alias)
{
	memset(rc->path, '\0', sizeof(rc->path));
	g_strlcpy(rc->path, ALIASES_get_alias(alias)->str, sizeof(rc->path));

	/* Map alias metadata on the system metadata */
	GString *md = ALIASES_get_mdsys(alias);
	g_byte_array_set_size(rc->system_metadata, 0);
	g_byte_array_append(rc->system_metadata, (guint8*)md->str, md->len);
}

static void
_fill_sysmd_with_headers(GByteArray *sysmd, gpointer headers)
{
	GString *md = CONTENTS_HEADERS_get_policy(headers);
	if (sysmd->len > 0) {
		if(NULL != strstr((char *)sysmd->data, "storage-policy")) {
			return;
		}
		g_byte_array_append(sysmd, (guint8*)";", 1);
	}
	g_byte_array_append(sysmd, (guint8*) "storage-policy=", 15);
	g_byte_array_append(sysmd, (guint8*) md->str, md->len);
}

static void
_fill_raw_content_v2_with_headers(meta2_raw_content_v2_t *rc, gpointer headers)
{
	rc->header.size = CONTENTS_HEADERS_get_size(headers);
	_fill_sysmd_with_headers(rc->header.system_metadata, headers);
}

static void
_fill_raw_content_with_headers(meta2_raw_content_t *rc, gpointer headers)
{
	rc->size = CONTENTS_HEADERS_get_size(headers);
	_fill_sysmd_with_headers(rc->system_metadata, headers);
}

static GString *
_forge_chunk_id_v2(chunk_id_t *cid)
{
	char str_addr[64];
	char hexid[65];
	GString *result = g_string_new("http://");

	memset(str_addr, '\0', 64);
	memset(str_addr, '\0', 64);

	addr_info_to_string(&(cid->addr), str_addr, 64);
	buffer2str(cid->id, sizeof(cid->id), hexid, 65);

	g_string_append_printf(result, "%s%s/", str_addr, cid->vol);
	result = g_string_append(result, hexid);

	return result;

}

static gpointer
_generate_m2v2_alias_from_raw_content(GByteArray *id, meta2_raw_content_t *rc)
{
	gpointer alias = _bean_create(&descr_struct_ALIASES);

	ALIASES_set2_alias(alias, rc->path);
	ALIASES_set_version(alias, rc->version);
	ALIASES_set_deleted(alias, rc->deleted);
	ALIASES_set_container_version(alias, 1);
	ALIASES_set_content_id(alias, id);
	ALIASES_set_ctime(alias, time(0));

	if (rc->system_metadata != NULL) {
		char *tmp = g_strndup((const char *)rc->system_metadata->data,
				rc->system_metadata->len);
		ALIASES_set2_mdsys(alias, tmp);
		g_free(tmp);
	} else {
		/* FVE: I don't know if it's fatal, so just log it */
		GRID_DEBUG("Empty system metadata for alias '%s' version %ld",
				rc->path, rc->version);
	}

	return alias;
}

static gpointer
_generate_bean_from_meta2_prop(const char *alias, gint64 alias_version, meta2_property_t *prop)
{
	gpointer property = _bean_create(&descr_struct_PROPERTIES);

	PROPERTIES_set2_alias(property, alias);
	PROPERTIES_set_alias_version(property, alias_version);
	PROPERTIES_set_deleted(property, FALSE);
	PROPERTIES_set2_key(property, prop->name);
	PROPERTIES_set_value(property, prop->value);

	return property;
}

meta2_property_t *
bean_to_meta2_prop(struct bean_PROPERTIES_s *in_prop)
{
	meta2_property_t *out_prop = g_malloc0(sizeof(meta2_property_t));
	if (in_prop != NULL) {
		out_prop->name = g_strdup(PROPERTIES_get_key(in_prop)->str);
		if (PROPERTIES_get_value(in_prop) != NULL &&
				PROPERTIES_get_value(in_prop)->len > 0) {
			out_prop->value = metautils_gba_dup(PROPERTIES_get_value(in_prop));
		}
		out_prop->version = PROPERTIES_get_alias_version(in_prop);
	}
	return out_prop;
}

static gpointer
_generate_m2v2_alias_from_raw_content_v2(GByteArray *id, meta2_raw_content_v2_t *rc)
{
	gpointer alias = _bean_create(&descr_struct_ALIASES);

	ALIASES_set2_alias(alias, rc->header.path);
	ALIASES_set_version(alias, rc->header.version);
	ALIASES_set_deleted(alias, rc->header.deleted);
	ALIASES_set_container_version(alias, 1);
	if (id != NULL)
		ALIASES_set_content_id(alias, id);
	ALIASES_set_ctime(alias, time(0));

	char *tmp;
	if (!rc->header.system_metadata)
		tmp = g_strdup("");
	else
		tmp = g_strndup((const char *)rc->header.system_metadata->data, rc->header.system_metadata->len);
	ALIASES_set2_mdsys(alias, tmp);
	g_free(tmp);

	return alias;
}

static gpointer
_generate_alias(GByteArray *id, const char *alias_name, GString *mdsys)
{
	gpointer alias = _bean_create(&descr_struct_ALIASES);
	ALIASES_set2_alias(alias, alias_name);
	if (id != NULL)
		ALIASES_set_content_id(alias, id);
	ALIASES_set_version(alias, 1);
	ALIASES_set_container_version(alias, 1);
	ALIASES_set_mdsys(alias, mdsys);
	ALIASES_set_ctime(alias, time(0));
	ALIASES_set_deleted(alias, FALSE);
	return alias;
}

static gpointer
_generate_m2v2_headers(GByteArray *id, gint64 size, GByteArray *sysmd)
{
	gpointer headers = _bean_create(&descr_struct_CONTENTS_HEADERS);
	GError *err = NULL;

	if (id != NULL)
		CONTENTS_HEADERS_set_id(headers, id);
	CONTENTS_HEADERS_nullify_hash(headers);
	CONTENTS_HEADERS_set_size(headers, size);

	gchar *polname = NULL;
	if(NULL != (err = storage_policy_from_metadata(sysmd, &polname))) {
		WARN("Possible bad content state, cannot extract correctly storage policy from mdsys (%d) : %s",
			err->code, err->message);
		g_clear_error(&err);
	}
	if(NULL != polname)
		CONTENTS_HEADERS_set2_policy(headers, polname);

	g_free(polname);

	return headers;
}

static GSList *
_generate_beans_from_raw_chunk_custom(GByteArray *id, meta2_raw_chunk_t *rc,
		char* (*make_pos)(guint32, void*), void *udata)
{
	GSList * result = NULL;
	gpointer content = _bean_create(&descr_struct_CONTENTS);
	gpointer chunk = _bean_create(&descr_struct_CHUNKS);
	GString *chunkid = _forge_chunk_id_v2(&(rc->id));
	char *pos = NULL;

	if (make_pos) {
		pos = make_pos(rc->position, udata);
	} else {
		pos = g_malloc0(32);
		g_snprintf(pos, 32, "%"G_GUINT32_FORMAT, rc->position);
	}

	if (id != NULL)
		CONTENTS_set_content_id(content, id);
	CONTENTS_set_chunk_id(content, chunkid);
	CONTENTS_set2_position(content, pos);

	CHUNKS_set_id(chunk, chunkid);
	CHUNKS_set2_hash(chunk, rc->hash, sizeof(rc->hash));
	CHUNKS_set_size(chunk, rc->size);
	CHUNKS_set_ctime(chunk, time(0));

	result = g_slist_prepend(result, content);
	result = g_slist_prepend(result, chunk);

	g_free(pos);
	g_string_free(chunkid, TRUE);
	return result;
}

static GSList *
_generate_beans_from_raw_chunk(GByteArray *id, meta2_raw_chunk_t *rc)
{
	return _generate_beans_from_raw_chunk_custom(id, rc, NULL, NULL);
}

/* -- RawContent -- */

GSList *
m2v2_beans_from_raw_content_custom(const char *id, meta2_raw_content_t *rc,
		char* (*make_pos) (guint32, void*), void *udata)
{
	GSList *l = NULL;
	GSList *beans = NULL;
	GByteArray *id_gba = NULL;

	/* sanity check */
	if (!rc) {
		return NULL;
	}

	if (id && strlen(id))
		id_gba = _hex_string_to_byte_array(id);

	/* headers */
	beans = g_slist_prepend(beans,
			_generate_m2v2_headers(id_gba, rc->size, rc->system_metadata));

	for(l = rc->raw_chunks; l && l->data; l = l->next) {
		beans = g_slist_concat(beans, _generate_beans_from_raw_chunk_custom(
				id_gba, (meta2_raw_chunk_t*) l->data, make_pos, udata));
	}

	/*alias */
	beans = g_slist_prepend(beans, _generate_m2v2_alias_from_raw_content(id_gba, rc));

	/* properties from user_metadata */
	gpointer prop = _generate_property_from_mdusr(rc->path, rc->metadata);

	if (NULL != prop)
		beans = g_slist_prepend(beans, prop);
	if (id_gba)
		g_byte_array_unref(id_gba);

	return beans;
}

GSList *
m2v2_beans_from_raw_content(const gchar *id, meta2_raw_content_t *rc)
{
	return m2v2_beans_from_raw_content_custom(id, rc, NULL, NULL);
}

meta2_raw_content_t *
raw_content_from_m2v2_beans(const container_id_t cid, GSList *l)
{
	GSList *chunk_beans = NULL;
	GSList *content_beans = NULL;
	GSList *prop_beans = NULL;

	meta2_raw_content_t *rc = g_malloc0(sizeof(meta2_raw_content_t));
	rc->system_metadata = g_byte_array_new();

	for(; l ; l = l->next) {
		if (!l->data)
			continue;
		if (DESCR(l->data) == &descr_struct_ALIASES)
			_fill_raw_content_with_alias(rc, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			_fill_raw_content_with_headers(rc, l->data);
		else if (DESCR(l->data) == &descr_struct_CHUNKS)
			chunk_beans = g_slist_prepend(chunk_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS)
			content_beans = g_slist_prepend(content_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_PROPERTIES)
			prop_beans = g_slist_prepend(prop_beans, l->data);
	}

	memcpy(&(rc->container_id), cid, sizeof(container_id_t));
	rc->nb_chunks = _build_raw_chunks_list(chunk_beans, content_beans,&(rc->raw_chunks));
	rc->metadata = _extract_mdusr_from_props(prop_beans);

	g_slist_free(chunk_beans);
	g_slist_free(content_beans);
	g_slist_free(prop_beans);
	return rc;
}

/* -- RawContent v2 -- */

GSList *
m2v2_beans_from_raw_content_v2(const char *id, meta2_raw_content_v2_t *rc)
{
	GSList *beans = NULL;
	GSList *l = NULL;
	GByteArray *id_gba = NULL;

	/* sanity check */
	if (!rc) {
		return NULL;
	}
	if (id != NULL && strlen(id) > 0) {
		id_gba = _hex_string_to_byte_array(id);
	}

	/* headers */
	beans = g_slist_prepend(beans,
			_generate_m2v2_headers(id_gba, rc->header.size, rc->header.system_metadata));

	for(l = rc->raw_chunks; l && l->data; l = l->next) {
		beans = g_slist_concat(beans, _generate_beans_from_raw_chunk(id_gba,
				(meta2_raw_chunk_t*) l->data));
	}

	/*alias */
	beans = g_slist_prepend(beans, _generate_m2v2_alias_from_raw_content_v2(id_gba, rc));

	/* mdusr to props */
	gpointer prop = _generate_property_from_mdusr(rc->header.path, rc->header.metadata);

	if(NULL != prop)
		beans = g_slist_prepend(beans, prop);

	l = NULL;
	for( l = rc->properties; l && l->data; l = l->next) {
		beans = g_slist_prepend(beans,
			_generate_bean_from_meta2_prop(rc->header.path, rc->header.version,
				(meta2_property_t*)l->data));
	}

	if (id_gba != NULL)
		g_byte_array_unref(id_gba);

	return beans;
}

meta2_raw_content_v2_t *
raw_content_v2_from_m2v2_beans(const container_id_t cid, GSList *l)
{
	GSList *chunk_beans = NULL;
	GSList *content_beans = NULL;
	GSList *prop_beans = NULL;
	meta2_raw_content_v2_t *rc;

	rc = g_malloc0(sizeof(meta2_raw_content_v2_t));
	rc->header.system_metadata = g_byte_array_new();

	for(; l ; l = l->next) {
		if (!l->data)
			continue;
		if (DESCR(l->data) == &descr_struct_ALIASES)
			_fill_raw_content_v2_with_alias(rc, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			_fill_raw_content_v2_with_headers(rc, l->data);
		else if (DESCR(l->data) == &descr_struct_CHUNKS)
			chunk_beans = g_slist_prepend(chunk_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS)
			content_beans = g_slist_prepend(content_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_PROPERTIES) {
			prop_beans = g_slist_prepend(prop_beans, l->data);
		}
	}

	GSList *m = NULL;
	for (m=prop_beans; m && m->data; m=m->next) {
		if(DESCR(m->data) == &descr_struct_PROPERTIES) {
			struct bean_PROPERTIES_s *bp = (struct bean_PROPERTIES_s *)m->data;
			if ( PROPERTIES_get_deleted(bp) )
				continue;
			meta2_property_t *prop = g_malloc0(sizeof(meta2_property_t));

			prop->name = g_strdup(PROPERTIES_get_key(bp)->str);
			prop->version = PROPERTIES_get_alias_version(bp);
			GByteArray *value = PROPERTIES_get_value(bp);
			prop->value = g_byte_array_sized_new (value->len);
			g_byte_array_append (prop->value, value->data, value->len);

			rc->properties = g_slist_prepend(rc->properties,prop);
		}
	}


	memcpy(&(rc->header.container_id), cid, sizeof(container_id_t));
	rc->header.metadata = _extract_mdusr_from_props(prop_beans);
	rc->header.nb_chunks = _build_raw_chunks_list(chunk_beans, content_beans,&(rc->raw_chunks));

	g_slist_free(chunk_beans);
	g_slist_free(content_beans);
	g_slist_free(prop_beans);
	return rc;
}

GSList *
chunk_info_list_from_m2v2_beans(GSList *l, char **mdsys)
{
	GSList *chunk_beans = NULL;
	GSList *content_beans = NULL;

	for(; l ; l = l->next) {
		if (!l->data)
			continue;
		if (DESCR(l->data) == &descr_struct_CHUNKS)
			chunk_beans = g_slist_prepend(chunk_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS)
			content_beans = g_slist_prepend(content_beans, l->data);
		else if (DESCR(l->data) == &descr_struct_ALIASES) {
			if(NULL != mdsys) {
				*mdsys = g_strdup(ALIASES_get_mdsys(l->data)->str);
			}
		}
	}

	return _build_chunk_info_list(chunk_beans, content_beans);
}

GSList *
m2v2_beans_from_chunk_info_list(GByteArray *id,
		const char *content_path, GSList *chunks)
{
	GSList * result = NULL;
	GSList * l = NULL;
	uint nb_chunks = 0;
	gint64 content_size = 0;
	gpointer header = NULL;
	gpointer alias = NULL;

	if(NULL == chunks || 0 >= (nb_chunks = g_slist_length(chunks)))  {
		GRID_DEBUG("Invalid list of chunk_info, cannot convert to beans");
		return NULL;
	}

	gint64 sizes[nb_chunks];
	gint64 ct = time(0);

	for(l = chunks; l && l->data; l = l->next) {
		/* generate chunk / content from chunks_info */
		chunk_info_t *ci = (chunk_info_t*)l->data;

		gpointer content = _bean_create(&descr_struct_CONTENTS);
		gpointer chunk = _bean_create(&descr_struct_CHUNKS);

		GString *chunkid = _forge_chunk_id_v2(&(ci->id));
		char pos[32];
		memset(pos,'\0', 32);
		g_snprintf(pos, 32, "%"G_GUINT32_FORMAT, ci->position);

		if (id != NULL)
			CONTENTS_set_content_id(content, id);
		CONTENTS_set_chunk_id(content, chunkid);
		CONTENTS_set2_position(content, pos);

		CHUNKS_set_id(chunk, chunkid);
		CHUNKS_set2_hash(chunk, ci->hash, sizeof(ci->hash));
		CHUNKS_set_size(chunk, ci->size);
		CHUNKS_set_ctime(chunk, ct);

		result = g_slist_prepend(result, chunk);
		result = g_slist_prepend(result, content);

		sizes[ci->position] = ci->size;
		g_string_free(chunkid, TRUE);
	}

	for (uint i = 0; i < nb_chunks; i++) {
		content_size += sizes[i];
	}

	/* TODO : forge mdsys like in add */
	GString *mdsys = g_string_new("");
	g_string_append_printf(mdsys, "creation-date=%"G_GINT64_FORMAT";"
			"mime-type=octet/stream;chunk-method=chunk-size;", ct);

	alias = _generate_alias(id, content_path, mdsys);
	do {
		GByteArray *gba = metautils_gba_from_string(mdsys->str);
		header = _generate_m2v2_headers(id, content_size, gba);
		g_byte_array_free(gba, TRUE);
	} while (0);

	result = g_slist_prepend(result, header);
	result = g_slist_prepend(result, alias);

	g_string_free(mdsys, TRUE);
	return result;
}

