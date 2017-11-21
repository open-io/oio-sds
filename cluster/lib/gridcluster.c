/*
OpenIO SDS cluster
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
#include <metautils/lib/common_variables.h>
#include <core/http_internals.h>

#include "gridcluster.h"

GError *
conscience_get_namespace (const char *ns, struct namespace_info_s **out)
{
	g_assert (ns != NULL);
	g_assert (out != NULL);
	*out = NULL;

	GString *body = g_string_sized_new (2048);
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
		GSList **out, gint64 deadline UNUSED)
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
				reg->kv_tags && *pp && *(pp+1);
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

	if (!*ns || !si->type[0] || !metautils_addr_valid_for_connect(&si->addr))
		return BADREQ("Invalid service ns, type or address");

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
	if (!*ns || !*type)
		return BADREQ("Invalid type or NS");

	struct oio_cs_client_s *cs = oio_cs_client__create_proxied (ns);
	GError *err = oio_cs_client__flush_services (cs, type);
	oio_cs_client__destroy (cs);
	return err;
}

/* -------------------------------------------------------------------------- */

GError *
register_namespace_service(const struct service_info_s *si)
{
	g_assert(si != NULL);

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
	if (!si || !si->tags)
		return;

	if (!service_info_get_tag (si->tags, "stat.cpu"))
		service_tag_set_value_float(service_info_ensure_tag (
					si->tags, "stat.cpu"), 100.0 * oio_sys_cpu_idle ());

	gchar vol[512] = "";
	struct service_tag_s *tag = service_info_get_tag (si->tags, "tag.vol");
	if (!tag || !service_tag_get_value_string (tag, vol, sizeof(vol), NULL))
		return;

	if (!service_info_get_tag(si->tags, "stat.io"))
		service_tag_set_value_float (service_info_ensure_tag(
					si->tags, "stat.io"), 100.0 * oio_sys_io_idle (vol));
	if (!service_info_get_tag(si->tags, "stat.space"))
		service_tag_set_value_float (service_info_ensure_tag (
					si->tags, "stat.space"), 100.0 * oio_sys_space_idle (vol));
}

/* -------------------------------------------------------------------------- */

gchar*
namespace_storage_policy_value(const namespace_info_t *ns_info, const gchar *wanted_policy)
{
	gchar *policy_to_lookup = wanted_policy
		?  g_strdup(wanted_policy) : oio_var_get_string(oio_ns_storage_policy);
	STRING_STACKIFY(policy_to_lookup);

	if (!ns_info || ns_info->storage_policy)
		return NULL;

	GByteArray *gba = g_hash_table_lookup(ns_info->storage_policy, policy_to_lookup);
	return !gba ? NULL : g_strndup((gchar*)gba->data, gba->len);
}

static gchar*
_get_token(const gchar *colon_separated_tokens, const guint token_rank)
{
	gchar **tokens = g_strsplit(colon_separated_tokens, ":", 0);
	gchar *token_wanted = NULL;

	if (g_strv_length(tokens) < token_rank) {
		GRID_ERROR("Cannot split string [%s] into %i ':'-separated tokens.", colon_separated_tokens, token_rank);
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
		GRID_WARN("Storage policy configuration seems to be wrong: [%s]"
				" Correct pattern is STG_CLASS:DATA_SEC:DATA_THREAT",
				storage_policy_value ? storage_policy_value : "NULL");
	}

	return data_sec_id;
}

static gsize
metautils_gba_data_to_string(const GByteArray *gba, gchar *dst,
		gsize dst_size)
{
	gsize i, imax, idst;

	if (unlikely(NULL == gba || NULL == dst || 0 == dst_size))
		return 0;
	if (!gba->data || !gba->len)
		return 0;

	memset(dst, 0, dst_size);
	imax = MIN(gba->len,dst_size);
	for (i=0,idst=0; i<imax && idst<dst_size-5 ;i++) {
		gchar c = (gchar)(gba->data[i]);
		if (g_ascii_isprint(c) && c != '\\')
			dst[ idst++ ] = c;
		else
			idst += g_snprintf(dst+idst, dst_size-idst, "\\x%02X", c);
	}

	return idst;
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
		GRID_WARN("Cannot find data security with id [%s] (namespace [%s], wanted policy [%s])",
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

