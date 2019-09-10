/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/metautils_errors.h>

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
	struct bean_ALIASES_s *alias = NULL;
	struct json_object *jname, *jversion, *jctime, *jmtime, *jheader, *jdel;
	struct oio_ext_json_mapping_s m[] = {
		{"name",    &jname,    json_type_string,  1},
		{"version", &jversion, json_type_int,     1},
		{"ctime",   &jctime,   json_type_int,     0},
		{"mtime",   &jmtime,   json_type_int,     0},
		{"deleted", &jdel,     json_type_boolean, 0},
		{"header",  &jheader,  json_type_string,  1},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = oio_ext_extract_json(j, m)))
		goto exit;

	hid = metautils_gba_from_hexstring(json_object_get_string(jheader));
	if (!hid) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid alias, not hexadecimal header_id");
		goto exit;
	}

	alias = _bean_create (&descr_struct_ALIASES);
	ALIASES_set2_alias(alias, json_object_get_string(jname));
	ALIASES_set_version(alias, json_object_get_int64(jversion));
	ALIASES_set_ctime(alias,
			jctime ? json_object_get_int64(jctime) : oio_ext_real_time()/G_TIME_SPAN_SECOND);
	ALIASES_set_mtime(alias,
			jmtime ? json_object_get_int64(jmtime) : oio_ext_real_time()/G_TIME_SPAN_SECOND);
	ALIASES_set_deleted(alias, json_object_get_boolean(jdel));
	ALIASES_set2_content(alias, hid->data, hid->len);
	*pbean = alias;
	alias = NULL;

exit:
	metautils_gba_unref (hid);
	_bean_clean (alias);
	return err;
}

GError*
m2v2_json_load_single_header (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *id = NULL, *hash = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	struct json_object *jid, *jhash, *jsize, *jctime, *jmtime, *jpolicy,
			*jmethod, *jtype;
	struct oio_ext_json_mapping_s mapping[] = {
		{"id",           &jid,     json_type_string, 1},
		// Size and hash are not needed to rebuild the object
		// Moreover, they can be calculated a posteriori
		{"hash",         &jhash,   json_type_string, 0},
		{"size",         &jsize,   json_type_int,    0},
		{"ctime",        &jctime,  json_type_int,    0},
		{"mtime",        &jmtime,  json_type_int,    0},
		{"policy",       &jpolicy, json_type_string, 0},
		{"chunk-method", &jmethod, json_type_string, 1},
		{"mime-type",    &jtype,   json_type_string, 1},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = oio_ext_extract_json (j, mapping)))
		return err;

	id = metautils_gba_from_hexstring(json_object_get_string(jid));
	if (!id) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid header, not hexa id");
		goto exit;
	}
	if (jhash) {
		hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
		if (!hash || hash->len != 16) {
			err = NEWERROR(CODE_BAD_REQUEST, "Invalid header, not hexa16 hash");
			goto exit;
		}
	}

	header = _bean_create(&descr_struct_CONTENTS_HEADERS);
	CONTENTS_HEADERS_set2_id(header, id->data, id->len);
	if (hash)
		CONTENTS_HEADERS_set2_hash(header, hash->data, hash->len);
	CONTENTS_HEADERS_set_size(header,
			jsize ? json_object_get_int64(jsize) : 0);
	CONTENTS_HEADERS_set_ctime(header,
			jctime ? json_object_get_int64(jctime) : oio_ext_real_time()/G_TIME_SPAN_SECOND);
	CONTENTS_HEADERS_set_mtime(header,
			jmtime ? json_object_get_int64(jmtime) : oio_ext_real_time()/G_TIME_SPAN_SECOND);
	if (jpolicy)
		CONTENTS_HEADERS_set2_policy(header, json_object_get_string(jpolicy));
	CONTENTS_HEADERS_set2_chunk_method(header, json_object_get_string(jmethod));
	CONTENTS_HEADERS_set2_mime_type(header, json_object_get_string(jtype));

	*pbean = header;
	header = NULL;

exit:
	metautils_gba_unref (id);
	metautils_gba_unref (hash);
	_bean_clean (header);
	return err;
}

GError*
m2v2_json_load_single_chunk (struct json_object *j, gpointer *pbean)
{
	GError *err = NULL;
	GByteArray *hid = NULL, *hash = NULL;
	struct bean_CHUNKS_s *chunk = NULL;
	struct json_object *jid, *jcontent, *jhash, *jsize, *jctime, *jpos;
	struct oio_ext_json_mapping_s mapping[] = {
		{"id",      &jid,      json_type_string, 1},
		{"hash",    &jhash,    json_type_string, 1},
		{"size",    &jsize,    json_type_int,    1},
		{"ctime",   &jctime,   json_type_int,    0},
		{"content", &jcontent, json_type_string, 1},
		{"pos",     &jpos,     json_type_string, 1},
		{NULL, NULL, 0, 0}
	};

	*pbean = NULL;
	if (NULL != (err = oio_ext_extract_json (j, mapping)))
		return err;

	hid = metautils_gba_from_hexstring(json_object_get_string(jcontent));
	if (!hid) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid header, not hexa id");
		goto exit;
	}
	hash = metautils_gba_from_hexstring(json_object_get_string(jhash));
	if (!hash) {
		err = NEWERROR(CODE_BAD_REQUEST, "Invalid chunk, not hexa header id");
		goto exit;
	}

	chunk = _bean_create (&descr_struct_CHUNKS);
	CHUNKS_set2_id(chunk, json_object_get_string(jid));
	CHUNKS_set_hash(chunk, hash);
	CHUNKS_set_size(chunk, json_object_get_int64(jsize));
	CHUNKS_set_ctime(chunk,
			jctime ? json_object_get_int64(jctime) : oio_ext_real_time()/G_TIME_SPAN_SECOND);
	CHUNKS_set_content(chunk, hid);
	CHUNKS_set2_position(chunk, json_object_get_string (jpos));
	*pbean = chunk;
	chunk = NULL;

exit:
	metautils_gba_unref (hid);
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
	if (!g_ascii_strcasecmp(stype, "header"))
		return m2v2_json_load_single_header (j, pbean);
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
	static gchar* title[] = { "aliases", "headers", "chunks", NULL };
	static jbean_mapper mapper[] = {
		m2v2_json_load_single_alias,
		m2v2_json_load_single_header,
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
			GRID_WARN("Parsing error: (%d) %s", err->code, err->message);
			break;
		}
	}

	return err;
}

GError *
meta2_json_fill_item_quality(struct json_object *jqual,
		struct oio_lb_selected_item_s *item)
{
	EXTRA_ASSERT(item != NULL);

	struct json_object *jedist = NULL, *jfdist = NULL, *jwdist = NULL,
			*jeslot = NULL, *jfslot = NULL;

	struct oio_ext_json_mapping_s jmap[] = {
		{"expected_dist", &jedist, json_type_int,    TRUE},
		{"final_dist",    &jfdist, json_type_int,    TRUE},
		{"warn_dist",     &jwdist, json_type_int,    TRUE},
		{"expected_slot", &jeslot, json_type_string, TRUE},
		{"final_slot",    &jfslot, json_type_string, TRUE},
		{NULL, NULL, json_type_null, FALSE}
	};

	GError *err = oio_ext_extract_json(jqual, jmap);
	if (!err) {
		item->expected_dist = json_object_get_int(jedist);
		item->final_dist = json_object_get_int(jfdist);
		item->warn_dist = json_object_get_int(jwdist);
		item->expected_slot = g_strdup(json_object_get_string(jeslot));
		item->final_slot = g_strdup(json_object_get_string(jfslot));
	}
	return err;
}
