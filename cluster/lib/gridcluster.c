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
conscience_locate_meta0(const char *ns, gchar ***result, gint64 dl)
{
	GSList *out = NULL;
	GError *err = conscience_get_services (ns, NAME_SRVTYPE_META0, FALSE, &out, dl);
	if (err)
		return err;
	*result = metautils_service_list_to_urlv(out);
	g_slist_free_full(out, (GDestroyNotify)service_info_clean);
	return NULL;
}
