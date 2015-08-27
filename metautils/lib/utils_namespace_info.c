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

gpointer
namespace_hash_table_lookup(GHashTable *table, const char *ns_name,
		const char *param_name)
{
	gchar key[LIMIT_LENGTH_NSNAME+64] = {0};
	gchar parent_ns[LIMIT_LENGTH_NSNAME] = {0};
	gpointer *value = NULL;

	g_strlcpy(parent_ns, ns_name, sizeof(parent_ns));

	gchar *end = parent_ns;
	end += strlen(parent_ns);

	/* Check if a parameter was specified for the namespace, or its parents */
	do {
		*end = '\0';
		if (param_name && *param_name) {
			g_snprintf(key, sizeof(key), "%*s_%s", (int)(end - parent_ns),
					parent_ns, param_name);
		} else {
			strncpy(key, parent_ns, (int)(end - parent_ns));
		}
		value = g_hash_table_lookup(table, key);
	} while (!value && (end = strrchr(parent_ns, '.')) != NULL);

	/* Fall back to the general parameter */
	if (!value && param_name && *param_name) {
		value = g_hash_table_lookup(table, param_name);
	}

	return value;
}

gboolean
namespace_info_copy(namespace_info_t* src, namespace_info_t* dst, GError **error)
{
	if (src == NULL || dst == NULL) {
		GSETCODE(error, ERRCODE_PARAM, "Argument src or dst should not be NULL");
		errno = EINVAL;
		return FALSE;
	}

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;

#define NSI_COPY_TABLE_REF(SRC, DST) \
	if ((SRC) != NULL) {\
		GHashTable *old = (DST);\
		DST = g_hash_table_ref(SRC);\
		if (old)\
			 g_hash_table_unref(old);\
	}

	NSI_COPY_TABLE_REF(src->options, dst->options);
	NSI_COPY_TABLE_REF(src->storage_policy, dst->storage_policy);
	NSI_COPY_TABLE_REF(src->data_security, dst->data_security);
	NSI_COPY_TABLE_REF(src->data_treatments, dst->data_treatments);
	NSI_COPY_TABLE_REF(src->storage_class, dst->storage_class);

#undef NSI_COPY_TABLE_REF

	errno = 0;
	return TRUE;
}

namespace_info_t*
namespace_info_dup(namespace_info_t* src)
{
	namespace_info_t *dst = g_malloc0(sizeof(namespace_info_t));
	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;

	dst->options = _copy_hash(src->options);
	dst->storage_policy = _copy_hash(src->storage_policy);
	dst->data_security = _copy_hash(src->data_security);
	dst->data_treatments = _copy_hash(src->data_treatments);
	dst->storage_class = _copy_hash(src->storage_class);
	return dst;
}

void
namespace_info_clear(namespace_info_t* ns_info)
{
	if (ns_info == NULL)
		return;
	if (ns_info->options != NULL)
		g_hash_table_unref(ns_info->options);
	if (ns_info->storage_policy != NULL)
		g_hash_table_unref(ns_info->storage_policy);
	if (ns_info->data_security != NULL)
		g_hash_table_unref(ns_info->data_security);
	if (ns_info->data_treatments != NULL)
		g_hash_table_unref(ns_info->data_treatments);
	if (ns_info->storage_class != NULL)
		g_hash_table_unref(ns_info->storage_class);

	memset(ns_info, 0, sizeof(namespace_info_t));
}

void
namespace_info_init(namespace_info_t *ni)
{
	if (!ni)
		return;
	ni->chunk_size = 0;
	memset(ni->name, 0, sizeof(ni->name));
	ni->options = _copy_hash(NULL);
	ni->storage_policy = _copy_hash(NULL);
	ni->storage_class = _copy_hash(NULL);
	ni->data_security = _copy_hash(NULL);
	ni->data_treatments = _copy_hash(NULL);
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

void
namespace_info_gclean(gpointer p1, gpointer p2)
{
	(void) p2;
	if (p1)
		namespace_info_free((struct namespace_info_s*)p1);
}

GHashTable*
namespace_info_list2map(GSList *list_nsinfo, gboolean auto_free)
{
	GSList *l;
	GHashTable *ht;

	ht = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, auto_free ? (GDestroyNotify)namespace_info_free : NULL);
	for (l=list_nsinfo; l ;l=l->next) {
		if (l->data)
			g_hash_table_insert(ht, ((struct namespace_info_s*)l->data)->name, l->data);
	}
	return ht;
}

GSList*
namespace_info_extract_name(GSList *list_nsinfo, gboolean copy)
{
	GSList *l, *result;

	result = NULL;
	for (l=list_nsinfo; l ;l=l->next) {
		if (l->data)
			result = g_slist_prepend(result, (copy ? g_strndup((gchar*)l->data, LIMIT_LENGTH_NSNAME) : l->data));
	}
	return result;
}

gchar *
namespace_info_get_data_security(namespace_info_t *ni, const char *data_sec_key)
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

gchar *
namespace_info_get_data_treatments(namespace_info_t *ni, const char *data_treat_key)
{
	if(NULL != ni->data_treatments) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->data_treatments, data_treat_key);
		if(NULL != gba) {
			return g_strndup((gchar*)gba->data, gba->len);
		}
	}

	return NULL;
}

gchar *
namespace_info_get_storage_class(namespace_info_t *ni, const char *stgclass_key)
{
	if (ni->storage_class != NULL) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->storage_class, stgclass_key);
		if (gba != NULL) {
			if (!gba->data || gba->len <= 0)
				return g_strdup("");
			return g_strndup((gchar*)gba->data, gba->len);
		}
	}
	return NULL;
}

GByteArray *
namespace_info_get_srv_param_gba(const namespace_info_t *ni,
		const char *ns_name, const char *srv_type, const char *param_name)
{
	gchar key[128] = {0};
	GByteArray *res = NULL;

	if (!ni || !ni->options)
		return NULL;

	if (!ns_name)
		ns_name = ni->name;

	if (srv_type != NULL) {
		// Prefix the param name with the service type
		g_snprintf(key, sizeof(key), "%s_%s", srv_type, param_name);
		res = namespace_hash_table_lookup(ni->options, ns_name, key);
	}

	if (!res) {
		// Try with unprefixed param name
		res = namespace_hash_table_lookup(ni->options, ns_name, param_name);
	}

	return res;
}

gint64
namespace_info_get_srv_param_i64(const namespace_info_t *ni,
		const char *ns_name, const char *srv_type,
		const char *param_name, gint64 def)
{
	gint64 res;
	gchar *end = NULL;
	GByteArray *value;

	if (!ni || !ni->options)
		return def;

	value = namespace_info_get_srv_param_gba(ni, ns_name, srv_type, param_name);
	if (!value)
		return def;

	gchar *v = g_strndup((gchar*)value->data, value->len);
	res = g_ascii_strtoll(v, &end, 10);
	if (end == v) // Conversion failed
		res = def;
	g_free(v);

	return res;
}

//------------------------------------------------------------------------------

static GError *
_load_hash (struct json_object *obj, const char *k, GHashTable *dst)
{
	struct json_object *sub = NULL;

	if (!json_object_object_get_ex(obj, k, &sub))
		return NULL;
	if (!json_object_is_type(sub, json_type_object))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid '%s' field", k);

	json_object_object_foreach(sub,key,val) {
		if (!json_object_is_type(val, json_type_string))
			continue;
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
	struct metautils_json_mapping_s mapping[] = {
		{"ns",        &ns, json_type_string, 1},
		{"chunksize", &sz, json_type_int,    1},
		{NULL, NULL, 0, 0}
	};
	GError *err = metautils_extract_json (obj, mapping);
	if (err) return err;

	metautils_strlcpy_physical_ns(ni->name, json_object_get_string(ns), sizeof(ni->name));
	ni->chunk_size = json_object_get_int64(sz);

	if (NULL != (err = _load_hash(obj, "options", ni->options))
			|| NULL != (err = _load_hash(obj, "storage_policy", ni->storage_policy))
			|| NULL != (err = _load_hash(obj, "data_security", ni->data_security))
			|| NULL != (err = _load_hash(obj, "data_treatments", ni->data_treatments))
			|| NULL != (err = _load_hash(obj, "storage_class", ni->storage_class)))
		return err;

	return NULL;
}

GError *
namespace_info_init_json(const char *encoded, struct namespace_info_s *ni)
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
_encode_json_properties (GString *out, GHashTable *ht, const char *tag)
{
	g_string_append_printf(out, "\"%s\":{", tag);
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
			g_string_append_printf(out, "\"%s\":\"%.*s\"", (gchar*)k,
					gba->len, (gchar*)(gba->data));
		}
	}
	g_string_append(out, "}");
}

void
namespace_info_encode_json(GString *out, struct namespace_info_s *ni)
{
	g_string_append_c(out, '{');
	g_string_append_printf(out, "\"ns\":\"%s\",", ni->name);
	g_string_append_printf(out, "\"chunksize\":\"%"G_GINT64_FORMAT"\",",
			ni->chunk_size);

	_encode_json_properties(out, ni->options, "options");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->storage_policy, "storage_policy");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->storage_class, "storage_class");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->data_security, "data_security");
	g_string_append_c(out, ',');
	_encode_json_properties(out, ni->data_treatments, "data_treatments");
	g_string_append_c(out, '}');
}

