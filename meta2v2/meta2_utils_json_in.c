#include <glib.h>
#include <json/json.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metautils_errors.h>

#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_json.h>

typedef GError* (*jbean_mapper) (struct json_object*, gpointer*);

static GError*
_alias2bean (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hid = NULL;
	struct bean_ALIASES_s *alias;
	struct json_object *jname, *jversion, *jctime, *jmd, *jheader;

	*pbean = NULL;
	alias = _bean_create (&descr_struct_ALIASES);
	jname = json_object_object_get (j, "name");
	jversion = json_object_object_get (j, "ver");
	jctime = json_object_object_get (j, "ctime");
	jmd = json_object_object_get (j, "system_metadata");
	jheader = json_object_object_get (j, "header");

	if (!jname || !json_object_is_type(jname, json_type_string)) {
		err = NEWERROR(400, "Invalid json name");
		goto exit;
	}
	if (!jversion || !json_object_is_type(jversion, json_type_int)) {
		err = NEWERROR(400, "Invalid json version");
		goto exit;
	}
	if (!jctime || !json_object_is_type(jctime, json_type_int)) {
		err = NEWERROR(400, "Invalid json ctime");
		goto exit;
	}
	if (!jheader || !json_object_is_type(jheader, json_type_string)) {
		err = NEWERROR(400, "Invalid json header");
		goto exit;
	}
	if (!jmd || !json_object_is_type(jmd, json_type_string)) {
		err = NEWERROR(400, "Invalid json metadata");
		goto exit;
	}

	hid = metautils_gba_from_hexstring(json_object_get_string(jheader));
	if (!hid) {
		err = NEWERROR(400, "Invalid alias, not hexadecimal header_id");
		goto exit;
	}

	ALIASES_set_deleted (alias, FALSE);
	ALIASES_set_container_version (alias, 0);
	ALIASES_set_ctime (alias, 0);
	ALIASES_set2_alias (alias, json_object_get_string(jname));
	ALIASES_set_version (alias, json_object_get_int64(jversion));
	ALIASES_set2_mdsys (alias, json_object_get_string(jmd));
	ALIASES_set2_content_id (alias, hid->data, hid->len);
	*pbean = alias;
	alias = NULL;

exit:
	if (hid)
		g_byte_array_unref (hid);
	if (alias) {
		_bean_clean (alias);
		alias = NULL;
	}
	return err;
}

static GError*
_header2bean (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *id = NULL, *hash = NULL;
	struct bean_CONTENTS_HEADERS_s *header;
	struct json_object *jid, *jhash, *jsize;

	*pbean = NULL;
	header = _bean_create (&descr_struct_CONTENTS_HEADERS);

	jid = json_object_object_get (j, "id");
	if (!jid || !json_object_is_type(jid, json_type_string)) {
		err = NEWERROR(400, "Invalid json id");
		goto exit;
	}
	jhash = json_object_object_get (j, "hash");
	if (!jhash || !json_object_is_type(jhash, json_type_string)) {
		err = NEWERROR(400, "Invalid json hash");
		goto exit;
	}
	jsize = json_object_object_get (j, "size");
	if (!jsize || !json_object_is_type(jsize, json_type_int)) {
		err = NEWERROR(400, "Invalid json size");
		goto exit;
	}

	id = metautils_gba_from_hexstring(json_object_get_string(jid));
	if (!id) {
		err = NEWERROR(400, "Invalid header, not hexa id");
		goto exit;
	}
	hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
	if (!hash || hash->len != 16) {
		err = NEWERROR(400, "Invalid header, not hexa16 hash");
		goto exit;
	}

	CONTENTS_HEADERS_set2_id (header, id->data, id->len);
	CONTENTS_HEADERS_set2_hash (header, hash->data, hash->len);
	CONTENTS_HEADERS_set_size (header, json_object_get_int64(jsize));
	*pbean = header;
	header = NULL;

exit:
	if (id)
		g_byte_array_unref (id);
	if (hash)
		g_byte_array_unref (hash);
	if (header) {
		_bean_clean (header);
		header = NULL;
	}
	return err;
}

static GError*
_content2bean (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hid = NULL;
	struct bean_CONTENTS_s *content;
	struct json_object *jhid, *jcid, *jpos;

	*pbean = NULL;
	content = _bean_create (&descr_struct_CONTENTS);

	jhid = json_object_object_get (j, "hdr");
	if (!jhid || !json_object_is_type(jhid, json_type_string)) {
		err = NEWERROR(400, "Invalid json header id");
		goto exit;
	}
	jcid = json_object_object_get (j, "chunk");
	if (!jcid || !json_object_is_type(jcid, json_type_string)) {
		err = NEWERROR(400, "Invalid json chunk id");
		goto exit;
	}
	jpos = json_object_object_get (j, "pos");
	if (!jpos || !json_object_is_type(jpos, json_type_string)) {
		err = NEWERROR(400, "Invalid json position");
		goto exit;
	}

	hid = metautils_gba_from_hexstring(json_object_get_string(jhid));
	if (!hid) {
		err = NEWERROR(400, "Invalid content, not hexa header id");
		goto exit;
	}

	CONTENTS_set2_content_id (content, hid->data, hid->len);
	CONTENTS_set2_chunk_id (content, json_object_get_string (jcid));
	CONTENTS_set2_position (content, json_object_get_string (jpos));
	*pbean = content;
	content = NULL;

exit:
	if (hid)
		g_byte_array_unref (hid);
	if (content) {
		_bean_clean (content);
		content = NULL;
	}
	return err;
}

static GError*
_chunk2bean (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hash = NULL;
	struct bean_CHUNKS_s *chunk;
	struct json_object *jid, *jhash, *jsize;

	*pbean = NULL;
	chunk = _bean_create (&descr_struct_CHUNKS);

	jid = json_object_object_get (j, "id");
	if (!jid || !json_object_is_type(jid, json_type_string)) {
		err = NEWERROR(400, "Invalid json header id");
		goto exit;
	}
	jhash = json_object_object_get (j, "hash");
	if (!jhash || !json_object_is_type(jhash, json_type_string)) {
		err = NEWERROR(400, "Invalid json chunk hash");
		goto exit;
	}
	jsize = json_object_object_get (j, "size");
	if (!jsize || !json_object_is_type(jsize, json_type_int)) {
		err = NEWERROR(400, "Invalid json size");
		goto exit;
	}

	hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
	if (!hash) {
		err = NEWERROR(400, "Invalid chunk, not hexa header id");
		goto exit;
	}

	CHUNKS_set2_id (chunk, json_object_get_string(jid));
	CHUNKS_set2_hash (chunk, hash->data, hash->len);
	CHUNKS_set_size (chunk, json_object_get_int64(jsize));
	CHUNKS_set_ctime (chunk, 0);
	*pbean = chunk;
	chunk = NULL;

exit:
	if (hash)
		g_byte_array_unref (hash);
	if (chunk) {
		_bean_clean (chunk);
		chunk = NULL;
	}
	return err;
}

static GError *
_jarray_to_beans (GSList **out, struct json_object *jv, jbean_mapper map)
{
	if (!json_object_is_type(jv, json_type_array))
		return NEWERROR(400, "Invalid JSON, exepecting array of beans");

	int vlen = json_object_array_length (jv);
	for (int i=0; i<vlen ;++i) {
		struct json_object *j = json_object_array_get_idx (jv, i);
		if (!json_object_is_type (j, json_type_object))
			return NEWERROR(400, "Invalid JSON for a bean");
		gpointer bean = NULL;
		GError *err = map(j, &bean);
		g_assert((bean != NULL) ^ (err != NULL));
		if (err)
			return err;
		*out = g_slist_prepend(*out, bean);
	}

	return NULL;
}

GError *
meta2_json_object_to_beans(GSList **beans, struct json_object *jbeans)
{
	static gchar* title[] = { "aliases", "headers", "contents", "chunks", NULL };
	static jbean_mapper mapper[] = { _alias2bean, _header2bean, _content2bean,
		_chunk2bean };

	GError *err = NULL;
	gchar **ptitle;
	jbean_mapper *pmapper;
	for (ptitle=title,pmapper=mapper; *ptitle ;++ptitle,++pmapper) {
		struct json_object *jv = json_object_object_get (jbeans, *ptitle);
		if (!jv)
			continue;
		err = _jarray_to_beans(beans, jv, *pmapper);
		if (err != NULL) {
			GRID_WARN("Parsing error : (%d) %s", err->code, err->message);
			break;
		}
	}

	return err;

}

