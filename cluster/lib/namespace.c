/*
OpenIO SDS cluster
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

#define NS_WORM_OPT_NAME "worm"
#define NS_CONTAINER_MAX_SIZE_NAME "container_max_size"
#define NS_STORAGE_POLICY_NAME "storage_policy"
#define NS_CHUNK_SIZE_NAME "chunk_size"
#define NS_WORM_OPT_VALUE_ON "on"
#define NS_COMPRESS_OPT_NAME "compression"
#define NS_COMPRESS_OPT_VALUE_ON "on"

#include <glib.h>
#include <metautils/lib/metautils.h>
#include "gridcluster.h"

static gint64
_gba_to_int64(GByteArray *gba, gboolean def)
{
	if (!gba)
		return def;
	gchar *str = g_alloca(gba->len + 1);
	memset(str, 0, gba->len + 1);
	memcpy(str, gba->data, gba->len);
	return g_ascii_strtoll(str, NULL, 10);
}

static gboolean
_gba_to_bool(GByteArray *gba, gboolean def)
{
	if (!gba || !gba->data || !gba->len)
		return def;
	if (!gba->data[ gba->len - 1 ])
		return metautils_cfg_get_bool((gchar*)gba->data, def);
	gchar *str = g_alloca(gba->len + 1);
	memset(str, 0, gba->len + 1);
	memcpy(str, gba->data, gba->len);
	return metautils_cfg_get_bool(str, def);
}

static GByteArray *
namespace_param_gba(const namespace_info_t* ni, const char *ns,
		const char *param_name)
{
	return namespace_info_get_srv_param_gba(ni, ns, NULL, param_name);
}

gchar*
namespace_get_strvalue(const namespace_info_t *ni,
		const char *key, const char *def)
{
	GByteArray *value;

	if (!ni || !ni->options)
		return g_strdup(def);

	value = g_hash_table_lookup(ni->options, key);
	if (!value)
		return g_strdup(def);

	return g_strndup((gchar*)value->data, value->len);
}

gint64
namespace_get_int64(const namespace_info_t *ni, const char* key, gint64 def)
{
	return namespace_info_get_srv_param_i64(ni, NULL, NULL, key, def);
}

static gsize
namespace_get_size(const namespace_info_t *ni, const char *name, gsize def)
{
	return (gsize) namespace_get_int64(ni, name, def);
}

gboolean
namespace_in_worm_mode(const namespace_info_t* ni)
{
	GByteArray *val = namespace_param_gba(ni, NULL, NS_WORM_OPT_NAME);
	return _gba_to_bool(val, FALSE);
}

gint64
namespace_container_max_size(const namespace_info_t* ni)
{
	GByteArray *val = namespace_param_gba(ni, NULL, NS_CONTAINER_MAX_SIZE_NAME);
	return _gba_to_int64(val, -1);
}

gint64
namespace_chunk_size(const namespace_info_t* ni, const char *ns_name)
{
	GByteArray *val = namespace_param_gba(ni, ns_name,
			NS_CHUNK_SIZE_NAME);
	return _gba_to_int64(val, ni->chunk_size);
}

gchar *
namespace_storage_policy(const namespace_info_t* ni, const char *ns_name)
{
	GByteArray *gba = namespace_param_gba(ni, ns_name,
			NS_STORAGE_POLICY_NAME);
	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

gchar*
namespace_storage_policy_value(const namespace_info_t *ni, const char *wanted_policy)
{
	const char *policy_to_lookup = wanted_policy ?
			wanted_policy : namespace_storage_policy(ni, ni->name);

	if (!ni || ni->storage_policy)
		return NULL;

	GByteArray *gba = g_hash_table_lookup(ni->storage_policy, policy_to_lookup);

	if (!wanted_policy)
		g_free((gpointer)policy_to_lookup);

	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

static gchar*
_get_token(const char *colon_separated_tokens, const guint token_rank)
{
	gchar **tokens = g_strsplit(colon_separated_tokens, ":", 0);
	gchar *token_wanted = NULL;

	if (g_strv_length(tokens) < token_rank) {
		ERROR("Cannot split string [%s] into %i ':'-separated tokens.", colon_separated_tokens, token_rank);
		goto end;
	}

	token_wanted = g_strdup(tokens[token_rank]);

end:
	if (tokens)
		g_strfreev(tokens);

	return token_wanted;
}

static gchar*
_get_data_security_id(const char *storage_policy_value)
{
	gchar *data_sec_id = _get_token(storage_policy_value, 1);

	if (!data_sec_id) {
		WARN("Storage policy configuration seems to be wrong: [%s]"
				" Correct pattern is STG_CLASS:DATA_SEC:DATA_THREAT",
				storage_policy_value ? storage_policy_value : "NULL");
	}

	return data_sec_id;
}

gchar*
namespace_data_security_value(const namespace_info_t *ni, const char *wanted_policy)
{
	gchar *storage_policy_value = namespace_storage_policy_value(ni, wanted_policy);
	gchar *data_sec_id = _get_data_security_id(storage_policy_value);
	GByteArray *data_sec_val = NULL;
	gchar str_data_sec_val[LIMIT_LENGTH_STGPOLICY];

	if (storage_policy_value && data_sec_id) {
		data_sec_val = g_hash_table_lookup(ni->data_security, data_sec_id);
	}

	if (!data_sec_val) {
		WARN("Cannot find data security with id [%s] (namespace [%s], wanted policy [%s])",
				data_sec_id, ni->name, wanted_policy);
	}

	if (data_sec_id)
		g_free(data_sec_id);
	if (storage_policy_value)
		g_free(storage_policy_value);

	metautils_gba_data_to_string(data_sec_val, str_data_sec_val, LIMIT_LENGTH_STGPOLICY);
	return g_strdup(str_data_sec_val);
}

gboolean
namespace_is_storage_policy_valid(const namespace_info_t* ni,
		const char *storage_policy)
{
	if (!ni || !ni->storage_policy || !storage_policy)
		return FALSE;
	if (!g_hash_table_lookup(ni->storage_policy, storage_policy))
		return FALSE;
	return TRUE;
}

gboolean
namespace_in_compression_mode(const namespace_info_t* ni)
{
	if (!ni || !ni->options)
		return FALSE;
	GByteArray *val = namespace_param_gba(ni, NULL, NS_COMPRESS_OPT_NAME);
	gboolean res = _gba_to_bool(val, FALSE);
	return res;
}

gsize
namespace_get_autocontainer_src_offset(const namespace_info_t* ni)
{
	return namespace_get_size(ni, "FLATNS_hash_offset", 0);
}

gsize
namespace_get_autocontainer_src_size(const namespace_info_t* ni)
{
	return namespace_get_size(ni, "FLATNS_hash_size", 0);
}

gsize
namespace_get_autocontainer_dst_bits(const namespace_info_t* ni)
{
	return namespace_get_size(ni, "FLATNS_hash_bitlength", 17);
}

gint64
namespace_get_container_max_versions(const namespace_info_t *ni)
{
	/* For backward compatibility, versioning is disabled by default */
	return namespace_get_int64(ni, "meta2_max_versions", 0);
}

gint64
namespace_get_keep_deleted_delay(const namespace_info_t *ni)
{
	return namespace_get_int64(ni, "meta2_keep_deleted_delay", -1);
}

gchar *
namespace_get_service_update_policy (const namespace_info_t *ni)
{
	const char *def = "meta2=KEEP|1|1|;sqlx=KEEP|3|1|";

	if (!ni || !ni->options)
		return g_strdup(def);

	return namespace_get_strvalue (ni, "service_update_policy", def);
}

