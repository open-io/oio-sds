/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <json-c/json.h>

#include <metautils/metautils.h>
#include <metautils/metautils_errors.h>

#include <glib.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_json.h>

typedef GError* (*jbean_mapper) (struct json_object*, gpointer*);

GError*
m2v2_json_load_single_alias (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hid = NULL;
	struct bean_ALIAS_s *alias = NULL;
	struct json_object *jname, *jversion, *jctime, *jheader;
	struct metautils_json_mapping_s m[] = {
		{"name",   &jname,    json_type_string, 1},
		{"ver",    &jversion, json_type_int,    1},
		{"ctime",  &jctime,   json_type_int,    1},
		{"header", &jheader,  json_type_string, 1},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = metautils_extract_json(j, m)))
		goto exit;

	hid = metautils_gba_from_hexstring(json_object_get_string(jheader));
	if (!hid) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid alias, not hexadecimal header_id");
		goto exit;
	}

	alias = _bean_create (&descr_struct_ALIAS);
	ALIAS_set2_alias (alias, json_object_get_string(jname));
	ALIAS_set_version (alias, json_object_get_int64(jversion));
	ALIAS_set2_content (alias, hid->data, hid->len);
	ALIAS_set_ctime (alias, 0);
	ALIAS_set_deleted (alias, FALSE);
	*pbean = alias;
	alias = NULL;

exit:
	metautils_gba_unref (hid);
	_bean_clean (alias);
	return err;
}

GError*
m2v2_json_load_single_content (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *id = NULL, *hash = NULL;
	struct bean_CONTENT_s *content = NULL;
	struct json_object *jid, *jhash, *jsize, *jmime, *jmethod, *jpol;
	struct metautils_json_mapping_s mapping[] = {
		{"id",    &jid,   json_type_string, 1},
		{"hash",  &jhash, json_type_string, 1},
		{"size",  &jsize, json_type_int, 1},
		{"mime-type",     &jmime,   json_type_string, 0},
		{"chunk-method",  &jmethod, json_type_string, 0},
		{"policy",        &jpol,    json_type_string, 0},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = metautils_extract_json (j, mapping)))
		return err;

	id = metautils_gba_from_hexstring(json_object_get_string(jid));
	if (!id) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid content, not hexa id");
		goto exit;
	}
	hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
	if (!hash || hash->len != 16) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid content, not hexa16 hash");
		goto exit;
	}

	content = _bean_create (&descr_struct_CONTENT);
	CONTENT_set2_id (content, id->data, id->len);
	CONTENT_set2_hash (content, hash->data, hash->len);
	CONTENT_set_size (content, json_object_get_int64(jsize));
	if (jmethod)
		CONTENT_set2_chunk_method (content, json_object_get_string (jmethod));
	if (jmime)
		CONTENT_set2_mime_type (content, json_object_get_string (jmime));
	if (jpol)
		CONTENT_set2_policy (content, json_object_get_string (jpol));
	*pbean = content;
	content = NULL;

exit:
	metautils_gba_unref (id);
	metautils_gba_unref (hash);
	_bean_clean (content);
	return err;
}

GError*
m2v2_json_load_single_chunk (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hash = NULL, *content = NULL;
	struct bean_CHUNK_s *chunk = NULL;
	struct json_object *jid, *jhash, *jsize, *jpos, *jcontent;
	struct metautils_json_mapping_s mapping[] = {
		{"id",      &jid,      json_type_string, 1},
		{"content", &jcontent, json_type_string, 1},
		{"hash",    &jhash,    json_type_string, 1},
		{"size",    &jsize,    json_type_int, 1},
		{"pos",     &jpos,     json_type_string, 1},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = metautils_extract_json (j, mapping)))
		return err;

	hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
	if (!hash) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid chunk, not hexa hash");
		goto exit;
	}
	content = metautils_gba_from_hexstring(json_object_get_string(jcontent));
	if (!content) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid chunk, not hexa content id");
		goto exit;
	}

	chunk = _bean_create (&descr_struct_CHUNK);
	CHUNK_set2_content (chunk, content->data, content->len);
	CHUNK_set2_id (chunk, json_object_get_string(jid));
	CHUNK_set2_hash (chunk, hash->data, hash->len);
	CHUNK_set_size (chunk, json_object_get_int64(jsize));
	CHUNK_set_ctime (chunk, 0);
	*pbean = chunk;
	chunk = NULL;

exit:
	metautils_gba_unref (content);
	metautils_gba_unref (hash);
	_bean_clean (chunk);
	return err;
}

static GError *
_jarray_to_beans (GSList **out, struct json_object *jv, jbean_mapper map)
{
	if (!json_object_is_type(jv, json_type_array))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid JSON, exepecting array of beans");

	GSList *l = NULL;
	int vlen = json_object_array_length (jv);
	for (int i=0; i<vlen ;++i) {
		struct json_object *j = json_object_array_get_idx (jv, i);
		if (!json_object_is_type (j, json_type_object))
			return NEWERROR(CODE_BAD_REQUEST, "Invalid JSON for a bean");
		gpointer bean = NULL;
		GError *err = map(j, &bean);
		EXTRA_ASSERT((bean != NULL) ^ (err != NULL));
		if (err) {
			_bean_cleanl2 (l);
			return err;
		}
		l = g_slist_prepend(l, bean);
	}

	*out = g_slist_reverse (l);
	return NULL;
}

GError *
m2v2_json_load_single_xbean (struct json_object *j, gpointer *pbean)
{
	if (!json_object_is_type (j, json_type_object))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid object type");
	struct json_object *jtype = NULL;
	if (!json_object_object_get_ex (j, "type", &jtype))
		return NEWERROR(CODE_BAD_REQUEST, "Missing 'type' field");
	if (!json_object_is_type (jtype, json_type_string))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid 'type' field");

	const char *stype = json_object_get_string (jtype);
	if (!g_ascii_strcasecmp(stype, "alias"))
		return m2v2_json_load_single_alias (j, pbean);
	if (!g_ascii_strcasecmp(stype, "content"))
		return m2v2_json_load_single_content (j, pbean);
	if (!g_ascii_strcasecmp(stype, "chunk"))
		return m2v2_json_load_single_chunk (j, pbean);

	return NEWERROR(CODE_BAD_REQUEST, "Unexpected 'type' field");
}

GError *
m2v2_json_load_setof_xbean (struct json_object *jv, GSList **out)
{
	if (!json_object_is_type(jv, json_type_array))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid JSON, exepecting array of beans");

	GSList *l = NULL;
	int vlen = json_object_array_length (jv);
	for (int i=0; i<vlen ;++i) {
		struct json_object *j = json_object_array_get_idx (jv, i);
		gpointer bean = NULL;
		GError *err = m2v2_json_load_single_xbean(j, &bean);
		EXTRA_ASSERT((bean != NULL) ^ (err != NULL));
		if (err) {
			_bean_cleanl2 (l);
			return err;
		}
		l = g_slist_prepend(l, bean);
	}

	*out = g_slist_reverse(l); // Serve the beans in the same order!
	return NULL;
}

GError *
meta2_json_load_setof_beans(struct json_object *jbeans, GSList **beans)
{
	static gchar* title[] = { "aliases", "contents", "chunks", NULL };
	static jbean_mapper mapper[] = {
		m2v2_json_load_single_alias,
		m2v2_json_load_single_content,
		m2v2_json_load_single_chunk
	};

	GError *err = NULL;
	gchar **ptitle;
	jbean_mapper *pmapper;
	for (ptitle=title,pmapper=mapper; *ptitle ;++ptitle,++pmapper) {
		struct json_object *jv = NULL;
		if (!json_object_object_get_ex (jbeans, *ptitle, &jv))
			continue;
		err = _jarray_to_beans(beans, jv, *pmapper);
		if (err != NULL) {
			GRID_WARN("Parsing error : (%d) %s", err->code, err->message);
			break;
		}
	}

	return err;

}

