/*
OpenIO SDS metautils
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

#include <errno.h>

#include "metautils.h"

#include <json.h>

static GHashTable *
_copy_hash(GHashTable *src)
{
	GHashTable *res = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, metautils_gba_unref);
	if (src) {
		GHashTableIter iter;
		gpointer k, v;

		g_hash_table_iter_init(&iter, src);
		while (g_hash_table_iter_next(&iter, &k, &v))
			g_hash_table_insert(res, g_strdup((gchar*)k), metautils_gba_dup(v));
	}

	return res;
}

void
namespace_info_copy(namespace_info_t* src, namespace_info_t* dst)
{
	EXTRA_ASSERT(src != NULL);
	EXTRA_ASSERT(dst != NULL);

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;

#define NSI_COPY_TABLE_REF(SRC, DST) \
	if ((SRC) != NULL) {\
		GHashTable *old = (DST);\
		DST = g_hash_table_ref(SRC);\
		if (old) g_hash_table_unref(old);\
	}

	NSI_COPY_TABLE_REF(src->storage_policy, dst->storage_policy);
	NSI_COPY_TABLE_REF(src->data_security, dst->data_security);
	NSI_COPY_TABLE_REF(src->service_pools, dst->service_pools);

#undef NSI_COPY_TABLE_REF
}

namespace_info_t*
namespace_info_dup(namespace_info_t* src)
{
	namespace_info_t *dst = g_malloc0(sizeof(namespace_info_t));
	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;

	dst->storage_policy = _copy_hash(src->storage_policy);
	dst->data_security = _copy_hash(src->data_security);
	dst->service_pools = _copy_hash(src->service_pools);
	return dst;
}

void
namespace_info_clear(namespace_info_t* ns_info)
{
	if (ns_info == NULL)
		return;
	if (ns_info->storage_policy != NULL)
		g_hash_table_unref(ns_info->storage_policy);
	if (ns_info->data_security != NULL)
		g_hash_table_unref(ns_info->data_security);
	if (ns_info->service_pools != NULL)
		g_hash_table_unref(ns_info->service_pools);

	memset(ns_info, 0, sizeof(namespace_info_t));
}

void
namespace_info_init(namespace_info_t *ni)
{
	if (!ni)
		return;
	ni->chunk_size = 0;
	memset(ni->name, 0, sizeof(ni->name));
	ni->storage_policy = _copy_hash(NULL);
	ni->data_security = _copy_hash(NULL);
	ni->service_pools = _copy_hash(NULL);
}

void
namespace_info_reset(namespace_info_t *ni)
{
	if (ni == NULL)
		return;
	namespace_info_clear(ni);
	namespace_info_init(ni);
}

void
namespace_info_free(namespace_info_t* ns_info)
{
	if (ns_info == NULL)
		return;
	namespace_info_clear(ns_info);
	g_free(ns_info);
}

gchar *
namespace_info_get_data_security(namespace_info_t *ni, const gchar *data_sec_key)
{
	if(NULL != ni->data_security) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->data_security, data_sec_key);
		if(NULL != gba) {
			return g_strndup((gchar*)gba->data, gba->len);
		}
	}

	return NULL;
}

//------------------------------------------------------------------------------

static GError *
_load_hash (struct json_object *obj, const gchar *k, GHashTable *dst)
{
	struct json_object *sub = NULL;

	if (!json_object_object_get_ex(obj, k, &sub))
		return NULL;
	if (!json_object_is_type(sub, json_type_object))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid '%s' field", k);

	json_object_object_foreach(sub,key,val) {
		if (json_object_is_type(val, json_type_string))
			g_hash_table_insert(dst, g_strdup(key), metautils_gba_from_string(
					json_object_get_string(val)));
	}
	return NULL;
}

GError *
namespace_info_init_json_object(struct json_object *obj,
		struct namespace_info_s *ni)
{
	EXTRA_ASSERT(ni != NULL);

	struct json_object *ns=NULL, *sz=NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"ns",        &ns, json_type_string, 1},
		{"chunksize", &sz, json_type_int,    1},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json (obj, mapping);
	if (err) return err;

	g_strlcpy(ni->name, json_object_get_string(ns), sizeof(ni->name));
	ni->chunk_size = json_object_get_int64(sz);

	if (NULL != (err = _load_hash(obj, "storage_policy", ni->storage_policy))
			|| NULL != (err = _load_hash(obj, "data_security", ni->data_security))
			|| NULL != (err = _load_hash(obj, "service_pools", ni->service_pools)))
		return err;

	return NULL;
}

GError *
namespace_info_init_json(const gchar *encoded, struct namespace_info_s *ni)
{
	EXTRA_ASSERT(ni != NULL);

	if (!encoded || !*encoded)
		return NEWERROR(CODE_BAD_REQUEST, "Empty data");

	struct json_tokener *tok = json_tokener_new();
	if (!tok)
		return NEWERROR(CODE_INTERNAL_ERROR, "Memory error");

	GError *err = NULL;
	struct json_object *obj = json_tokener_parse_ex(tok, encoded, strlen(encoded));
	if (!obj)
		err = NEWERROR(CODE_BAD_REQUEST, "JSON parsing error");
	else {
		err = namespace_info_init_json_object(obj, ni);
		json_object_put(obj);
	}
	json_tokener_free(tok);
	return err;
}

//------------------------------------------------------------------------------

static void
_encode_json_properties (GString *out, GHashTable *ht, const gchar *tag)
{
	g_string_append_c(out, '"');
	g_string_append(out, tag);
	g_string_append_static(out, "\":{");
	if (ht && g_hash_table_size(ht) > 0) {
		GHashTableIter iter;
		gpointer k, v;
		gboolean first = TRUE;
		g_hash_table_iter_init(&iter, ht);
		while (g_hash_table_iter_next(&iter, &k, &v)) {
			GByteArray *gba = v;
			if (!first)
				g_string_append_c(out, ',');
			first = FALSE;
			oio_str_gstring_append_json_quote(out, (gchar*)k);
			g_string_append_static(out, ":\"");
			/* If we do not trust 'by default' what has been configured
			 * for the namespace, we cannot encode the values as is because
			 * they often contain a final '\0' that has been added in earlier
			 * times for more robustness */
			guint len = gba->len;
			while (len && !gba->data[len-1]) { len --; }
			oio_str_gstring_append_json_blob(out, (gchar*)(gba->data), len);
			g_string_append_c(out, '"');
		}
	}
	g_string_append_c(out, '}');
}

void
namespace_info_encode_json(GString *out, struct namespace_info_s *ni)
{
	g_string_append_c(out, '{');
	OIO_JSON_append_str(out, "ns", ni->name);
	g_string_append_c(out, ',');
	OIO_JSON_append_int(out, "chunksize", ni->chunk_size);
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->storage_policy, "storage_policy");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->service_pools, "service_pools");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->data_security, "data_security");
	g_string_append_c(out, '}');
}

