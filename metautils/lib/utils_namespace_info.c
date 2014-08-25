#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include <errno.h>

#include <json/json.h>

#include "metautils.h"

static void
_copy_list_element(gpointer _elem, gpointer _p_dst_list)
{
	gchar *elem = _elem;
	GSList **p_dst_list = _p_dst_list;
	*p_dst_list = g_slist_prepend(*p_dst_list, g_strdup(elem));
}

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

gboolean
namespace_info_copy(namespace_info_t* src, namespace_info_t* dst, GError **error)
{
	if (src == NULL || dst == NULL) {
		GSETCODE(error, 500+EINVAL, "Argument src or dst should not be NULL");
		errno = EINVAL;
		return FALSE;
	}

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;
	memcpy(&(dst->addr), &(src->addr), sizeof(addr_info_t));
	memcpy(&(dst->versions), &(src->versions), sizeof(struct ns_versions_s));

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

	if (src->writable_vns != NULL) {
		GSList *old = dst->writable_vns;
		dst->writable_vns = NULL;
		g_slist_foreach (src->writable_vns, _copy_list_element, &(dst->writable_vns));
		if (old)
			g_slist_free_full(old, g_free);
	}

	errno = 0;
	return TRUE;
}

namespace_info_t*
namespace_info_dup(namespace_info_t* src, GError **error)
{
	namespace_info_t *dst;

	dst = g_try_malloc0(sizeof(namespace_info_t));
	if (!dst) {
		GSETERROR(error, "Memory allocation failure");
		return NULL;
	}

	memcpy(dst->name, src->name, sizeof(src->name));
	dst->chunk_size = src->chunk_size;
	memcpy(&(dst->addr), &(src->addr), sizeof(addr_info_t));
	memcpy(&(dst->versions), &(src->versions), sizeof(struct ns_versions_s));

	dst->options = _copy_hash(src->options);
	dst->storage_policy = _copy_hash(src->storage_policy);
	dst->data_security = _copy_hash(src->data_security);
	dst->data_treatments = _copy_hash(src->data_treatments);
	dst->storage_class = _copy_hash(src->storage_class);
	if (src->writable_vns) {
		g_slist_foreach (src->writable_vns, _copy_list_element, &(dst->writable_vns));
	}

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
	if (ns_info->writable_vns != NULL)
		g_slist_free_full(ns_info->writable_vns, g_free);
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
	memset(&ni->addr, 0, sizeof(ni->addr));
	memset(&ni->versions, 0, sizeof(ni->versions));
	ni->options = _copy_hash(NULL);
	ni->storage_policy = _copy_hash(NULL);
	ni->data_security = _copy_hash(NULL);
	ni->data_treatments = _copy_hash(NULL);
	ni->storage_class = _copy_hash(NULL);
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

// TODO: factorize 3 following functions
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

gchar *
namespace_info_get_data_treatments(namespace_info_t *ni, const gchar *data_treat_key)
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

gboolean
namespace_info_is_vns_writable(namespace_info_t *ni, const gchar *vns)
{
	if (ni && ni->writable_vns && vns) {
		return NULL != g_slist_find_custom(ni->writable_vns, vns, (GCompareFunc) g_strcmp0);
	}
	return FALSE;
}

gchar *
namespace_info_get_storage_class(namespace_info_t *ni, const gchar *stgclass_key)
{
	if (ni->storage_class != NULL) {
		GByteArray *gba = NULL;
		gba = g_hash_table_lookup(ni->storage_class, stgclass_key);
		if (gba != NULL) {
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

	if (!obj || !json_object_is_type(obj, json_type_object))
		return NEWERROR(CODE_BAD_REQUEST, "Not a JSON object");

	struct json_object *sub = NULL;
	// Mandatory fields
	if (!json_object_object_get_ex(obj, "ns", &sub))
		return NEWERROR(CODE_BAD_REQUEST, "Missing 'ns' field");
	if (!json_object_is_type(sub, json_type_string))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid 'ns' field");
	metautils_strlcpy_physical_ns(ni->name, json_object_get_string(sub),
			sizeof(ni->name));

	if (!json_object_object_get_ex(obj, "chunksize", &sub))
		return NEWERROR(CODE_BAD_REQUEST, "Missing 'chunksize' field");
	if (!json_object_is_type(sub, json_type_int))
		return NEWERROR(CODE_BAD_REQUEST, "Invalid 'chunksize' field");
	ni->chunk_size = json_object_get_int64(sub);

	// Optional fields
	if (json_object_object_get_ex(obj, "writable_vns", &sub)) {
		if (!json_object_is_type(sub, json_type_array))
			return NEWERROR(CODE_BAD_REQUEST, "Invalid 'writable_vns' field");
		for (int i=json_object_array_length(sub)-1; i>=0 ;--i) {
			struct json_object *item = json_object_array_get_idx(sub, i);
			g_assert(item != NULL);
			g_assert(json_object_is_type(item, json_type_string));
			ni->writable_vns = g_slist_prepend(ni->writable_vns,
					g_strdup(json_object_get_string(item)));
		}
	}

	GError *err;
	if (NULL != (err = _load_hash(obj, "options", ni->options))
			|| NULL != (err = _load_hash(obj, "storage_policy", ni->storage_policy))
			|| NULL != (err = _load_hash(obj, "data_security", ni->data_security))
			|| NULL != (err = _load_hash(obj, "data_treatments", ni->data_treatments))
			|| NULL != (err = _load_hash(obj, "storage_class", ni->storage_class)))
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

	g_string_append(out, "\"writable_vns\":[");
	for (GSList *l=ni->writable_vns; l ;l=l->next) {
		if (l != ni->writable_vns)
			g_string_append_c(out, ',');
		g_string_append_printf(out, "\"%s\"", (gchar*)(l->data));
	}
	g_string_append(out, "],");

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

