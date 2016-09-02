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

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <curl/curl.h>

#include <metautils/lib/metautils.h>
#include <cluster/module/module.h>
#include <core/http_internals.h>

#include "gridcluster.h"

#define MAX_REQ_LENGTH 1024
#define CONNECT_TIMEOUT 5000
#define SOCKET_TIMEOUT 5000
#define BUF (wrkParam+writen)
#define LEN (sizeof(wrkParam)-writen-1)
#define MANAGE_ERROR(Req,Resp,Error) do {\
	if (Resp.data_size > 0 && Resp.data)\
		GSETERROR(Error, "Error from agent : %.*s", Resp.data_size, (char*)(Resp.data));\
	else\
		GSETERROR(Error, "Error from agent : (no response)");\
} while (0)
#define NS_WORM_OPT_NAME "worm"
#define NS_CONTAINER_MAX_SIZE_NAME "container_max_size"
#define NS_STORAGE_POLICY_NAME "storage_policy"
#define NS_CHUNK_SIZE_NAME "chunk_size"
#define NS_STATE_NAME "state"
#define NS_WORM_OPT_VALUE_ON "on"
#define NS_COMPRESS_OPT_NAME "compression"
#define NS_COMPRESS_OPT_VALUE_ON "on"

/* -------------------------------------------------------------------------- */

GError *
conscience_get_namespace (const char *ns, struct namespace_info_s **out)
{
	g_assert (ns != NULL);
	g_assert (out != NULL);
	*out = NULL;

	GString *body = g_string_new ("");
	CURL *h = _curl_get_handle_proxy ();
	GError *err = oio_proxy_call_conscience_info (h, ns, body);
	curl_easy_cleanup (h);

	if (!err) {
		struct namespace_info_s *ni = g_malloc0 (sizeof(*ni));
		namespace_info_init (ni);
		if (!(err = namespace_info_init_json (body->str, ni))) {
			*out = ni;
		} else {
			namespace_info_free (ni);
			ni = NULL;
		}
	}
	g_string_free (body, TRUE);
	return err;
}

GError *
conscience_get_types (const char *ns, GSList **out)
{
	g_assert (ns != NULL);
	g_assert (out != NULL);
	*out = NULL;

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	GSList *l = NULL;
	void _on_type (const char *srvtype) {
		l = g_slist_prepend (l, g_strdup (srvtype));
	}
	GError *err = oio_cs_client__list_types (cs, _on_type);
	oio_cs_client__destroy (cs);
	if (err) {
		g_assert (l == NULL);
		return err;
	}
	*out = l;
	return NULL;
}

GError *
conscience_get_services (const char *ns, const char *type, gboolean full,
		GSList **out)
{
	g_assert (ns != NULL);
	g_assert (type != NULL);
	g_assert (out != NULL);
	*out = NULL;

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	GSList *l = NULL;
	void _on_reg (const struct oio_cs_registration_s *reg, int score) {
		struct service_info_s *si = g_malloc0 (sizeof(struct service_info_s));
		g_strlcpy (si->ns_name, ns, sizeof(si->ns_name));
		g_strlcpy (si->type, type, sizeof(si->type));
		si->tags = g_ptr_array_new ();
		si->score.value = score;
		service_tag_set_value_string (service_info_ensure_tag (
					si->tags, "tag.id"), reg->id);
		grid_string_to_addrinfo (reg->url, &si->addr);
		for (const char * const *pp = reg->kv_tags;
				pp && *pp && *(pp+1);
				pp += 2) {
			service_tag_set_value_string (service_info_ensure_tag(
						si->tags, *pp), *(pp+1));
		}
		l = g_slist_prepend (l, si);
	}
	GError *err = oio_cs_client__list_services (cs, type, full, _on_reg);
	oio_cs_client__destroy (cs);
	if (err) {
		g_assert (l == NULL);
		return err;
	}
	*out = l;
	return NULL;
}

GError *
conscience_push_service (const char *ns, struct service_info_s *si)
{
	g_assert (ns != NULL);
	g_assert (si != NULL);

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);

	/* convert the <service_info_t> into a <struct oio_cs_registration_s> */
	gchar strurl[STRLEN_ADDRINFO], *srvkey, **kv;
	GPtrArray *tmp = g_ptr_array_new ();
	if (si->tags) for (guint i=0; i<si->tags->len ;++i) {
		struct service_tag_s *tag = si->tags->pdata[i];
		gchar v[256];
		service_tag_to_string (tag, v, sizeof(v));
		g_ptr_array_add (tmp, g_strdup(tag->name));
		g_ptr_array_add (tmp, g_strdup(v));
	}
	g_ptr_array_add (tmp, NULL);
	kv = (gchar**) g_ptr_array_free (tmp, FALSE);
	grid_addrinfo_to_string (&si->addr, strurl, sizeof(strurl));
	srvkey = service_info_key (si);
	struct oio_cs_registration_s reg = {
		.id = srvkey, .url = strurl, .kv_tags = (const char * const *)kv,
	};

	GError *err;
	if (si->score.value == SCORE_UNSET)
		err = oio_cs_client__register_service (cs, si->type, &reg);
	else if (si->score.value == SCORE_UNLOCK)
		err = oio_cs_client__unlock_service (cs, si->type, &reg);
	else
		err = oio_cs_client__lock_service (cs, si->type, &reg,
				si->score.value);

	g_free (srvkey);
	g_strfreev (kv);
	oio_cs_client__destroy (cs);
	return err;
}

GError *
conscience_remove_services(const char *ns, const char *type)
{
	g_assert (ns != NULL);
	g_assert (type != NULL);

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	GError *err = oio_cs_client__flush_services (cs, type);
	oio_cs_client__destroy (cs);
	return err;
}

/* -------------------------------------------------------------------------- */

GError *
register_namespace_service(const struct service_info_s *si)
{
	struct service_info_s *si_copy = service_info_dup(si);
	si_copy->score.value = SCORE_UNSET;
	si_copy->score.timestamp = oio_ext_real_time () / G_TIME_SPAN_SECOND;
	metautils_srvinfo_ensure_tags (si_copy);
	GError *err = conscience_push_service (si->ns_name, si_copy);
	service_info_clean(si_copy);
	return err;
}

/* -------------------------------------------------------------------------- */

void
metautils_srvinfo_ensure_tags (struct service_info_s *si)
{
	if (!si->tags)
		return ;

	if (!service_info_get_tag (si->tags, "stat.cpu"))
		service_tag_set_value_float(service_info_ensure_tag (
					si->tags, "stat.cpu"), 100.0 * oio_sys_cpu_idle ());

	gchar vol[512];
	struct service_tag_s *tag = service_info_get_tag (si->tags, "tag.vol");
	if (tag) {
		if (service_tag_get_value_string (tag, vol, sizeof(vol), NULL)) {
			if (!service_info_get_tag(si->tags, "stat.io"))
				service_tag_set_value_float (service_info_ensure_tag(
							si->tags, "stat.io"), 100.0 * oio_sys_io_idle (vol));
			if (!service_info_get_tag(si->tags, "stat.space"))
				service_tag_set_value_float (service_info_ensure_tag (
							si->tags, "stat.space"), 100.0 * oio_sys_space_idle (vol));
		}
	}
}

/* -------------------------------------------------------------------------- */

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
		return oio_str_parse_bool((gchar*)gba->data, def);
	gchar *str = g_alloca(gba->len + 1);
	memset(str, 0, gba->len + 1);
	memcpy(str, gba->data, gba->len);
	return oio_str_parse_bool(str, def);
}

static GByteArray *
namespace_param_gba(const namespace_info_t* ns_info, const gchar *ns_name,
		const gchar *param_name)
{
	return namespace_info_get_srv_param_gba(ns_info, ns_name, NULL, param_name);
}

gchar*
gridcluster_get_nsinfo_strvalue(struct namespace_info_s *nsinfo,
		const gchar *key, const gchar *def)
{
	GByteArray *value;

	if (!nsinfo || !nsinfo->options)
		return g_strdup(def);

	value = g_hash_table_lookup(nsinfo->options, key);
	if (!value)
		return g_strdup(def);

	return g_strndup((gchar*)value->data, value->len);
}

gint64
gridcluster_get_nsinfo_int64(struct namespace_info_s *nsinfo,
		const gchar* key, gint64 def)
{
	return namespace_info_get_srv_param_i64(nsinfo, NULL, NULL, key, def);
}

static gsize
namespace_get_size(namespace_info_t *ns_info, const gchar *name, gsize def)
{
	return (gsize) gridcluster_get_nsinfo_int64(ns_info, name, def);
}

gboolean
namespace_in_worm_mode(namespace_info_t* ns_info)
{
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_WORM_OPT_NAME);
	return _gba_to_bool(val, FALSE);
}

gchar *
namespace_get_state(namespace_info_t* ns_info)
{
	return gridcluster_get_nsinfo_strvalue(ns_info, NS_STATE_NAME,
					       NS_STATE_VALUE_STAND_ALONE);
}

gint64
namespace_container_max_size(namespace_info_t* ns_info)
{
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_CONTAINER_MAX_SIZE_NAME);
	return _gba_to_int64(val, -1);
}

gint64
namespace_chunk_size(const namespace_info_t* ns_info, const char *ns_name)
{
	GByteArray *val = namespace_param_gba(ns_info, ns_name,
			NS_CHUNK_SIZE_NAME);
	return _gba_to_int64(val, ns_info->chunk_size);
}

gchar *
namespace_storage_policy(const namespace_info_t* ns_info, const char *ns_name)
{
	GByteArray *gba = namespace_param_gba(ns_info, ns_name,
			NS_STORAGE_POLICY_NAME);
	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

gchar*
namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy)
{
	const gchar *policy_to_lookup = wanted_policy ?
			wanted_policy : namespace_storage_policy(ns_info, ns_info->name);

	if (!ns_info || ns_info->storage_policy)
		return NULL;

	GByteArray *gba = g_hash_table_lookup(ns_info->storage_policy, policy_to_lookup);

	if (!wanted_policy)
		g_free((gpointer)policy_to_lookup);

	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

static gchar*
_get_token(const gchar *colon_separated_tokens, const guint token_rank)
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
_get_data_security_id(const gchar *storage_policy_value)
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
namespace_data_security_value(const namespace_info_t *ns_info, const gchar *wanted_policy)
{
	gchar *storage_policy_value = namespace_storage_policy_value(ns_info, wanted_policy);
	gchar *data_sec_id = _get_data_security_id(storage_policy_value);
	GByteArray *data_sec_val = NULL;
	gchar str_data_sec_val[LIMIT_LENGTH_STGPOLICY];

	if (storage_policy_value && data_sec_id) {
		data_sec_val = g_hash_table_lookup(ns_info->data_security, data_sec_id);
	}

	if (!data_sec_val) {
		WARN("Cannot find data security with id [%s] (namespace [%s], wanted policy [%s])",
				data_sec_id, ns_info->name, wanted_policy);
	}

	if (data_sec_id)
		g_free(data_sec_id);
	if (storage_policy_value)
		g_free(storage_policy_value);

	metautils_gba_data_to_string(data_sec_val, str_data_sec_val, LIMIT_LENGTH_STGPOLICY);
	return g_strdup(str_data_sec_val);
}

gboolean
namespace_is_storage_policy_valid(const namespace_info_t* ns_info, const gchar *storage_policy)
{
	if (!ns_info || !ns_info->storage_policy || !storage_policy)
		return FALSE;
	if (!g_hash_table_lookup(ns_info->storage_policy, storage_policy))
		return FALSE;
	return TRUE;
}

gboolean
namespace_in_compression_mode(namespace_info_t* ns_info)
{
	if (!ns_info || !ns_info->options)
		return FALSE;
	GByteArray *val = namespace_param_gba(ns_info, NULL, NS_COMPRESS_OPT_NAME);
	gboolean res = _gba_to_bool(val, FALSE);
	return res;
}

gsize
namespace_get_autocontainer_src_offset(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_offset", 0);
}

gsize
namespace_get_autocontainer_src_size(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_size", 0);
}

gsize
namespace_get_autocontainer_dst_bits(namespace_info_t* ns_info)
{
	return namespace_get_size(ns_info, "FLATNS_hash_bitlength", 17);
}

gint64
gridcluster_get_container_max_versions(struct namespace_info_s *nsinfo)
{
	/* For backward compatibility, versioning is disabled by default */
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_max_versions", 0);
}

gint64
gridcluster_get_keep_deleted_delay(struct namespace_info_s *nsinfo)
{
	return gridcluster_get_nsinfo_int64(nsinfo, "meta2_keep_deleted_delay", -1);
}

gchar *
gridcluster_get_service_update_policy (struct namespace_info_s *nsinfo)
{
	const gchar *def = "meta2=KEEP|1|1|;sqlx=KEEP|1|1|";

	if (!nsinfo || !nsinfo->options)
		return g_strdup(def);

	return gridcluster_get_nsinfo_strvalue (nsinfo, "service_update_policy", def);
}
