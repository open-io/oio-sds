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

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metautils.tools"
#endif

#include <json.h>

#include "metautils.h"

struct meta1_service_url_s*
meta1_unpack_url(const gchar *url)
{
	gchar *type = NULL, *host = NULL, *args = NULL;

	EXTRA_ASSERT(url != NULL);

	int len = strlen(url);
	gchar *tmp = g_alloca(len+1);
	g_strlcpy(tmp, url, len+1);

	if (!(type = strchr(tmp, '|')))
		return NULL;
	*(type++) = '\0';

	if (!(host = strchr(type, '|')))
		return NULL;
	*(host++) = '\0';

	if (!(args = strchr(host, '|')))
		return NULL;
	*(args++) = '\0';
	if (strlen(args) >= LIMIT_LENGTH_SRVARGS)
		return NULL;

	struct meta1_service_url_s *result;
	result = g_malloc0(sizeof(*result) + strlen(args) + 1);
	result->seq = g_ascii_strtoll(url, NULL, 10);
	g_strlcpy(result->srvtype, type, sizeof(result->srvtype));
	g_strlcpy(result->host, host, sizeof(result->host));
	strcpy(result->args, args);

	return result;
}

void
meta1_service_url_clean(struct meta1_service_url_s *u)
{
	if (u) {
		u->seq = 0;
		u->srvtype[0] = u->host[0] = u->args[0] = 0;
		g_free(u);
	}
}

void
meta1_service_url_cleanv(struct meta1_service_url_s **uv)
{
	struct meta1_service_url_s **p;

	if (!uv)
		return;
	for (p=uv; *p ;p++)
		meta1_service_url_clean(*p);
	g_free(uv);
}

gchar*
meta1_pack_url(struct meta1_service_url_s *u)
{
	return (NULL == u) ? NULL : g_strdup_printf(
			"%"G_GINT64_FORMAT"|%s|%s|%s",
			u->seq, u->srvtype, u->host, u->args);
}

gboolean
meta1_url_get_address(struct meta1_service_url_s *u,
		struct addr_info_s *dst)
{
	return l4_address_init_with_url(dst, u->host, NULL);
}

gboolean
meta1_strurl_get_address(const gchar *str, struct addr_info_s *dst)
{
	gboolean rc;
	struct meta1_service_url_s *u;

	u = meta1_unpack_url(str);
	rc = meta1_url_get_address(u, dst);
	g_free(u);

	return rc;
}

GError *
meta1_service_url_load_json_object(struct json_object *obj,
		struct meta1_service_url_s **out)
{
	EXTRA_ASSERT(out != NULL); *out = NULL;

	struct json_object *s=NULL, *t=NULL, *h=NULL, *a=NULL;
	struct metautils_json_mapping_s mapping[] = {
		{"seq",  &s, json_type_int,    1},
		{"type", &t, json_type_string, 1},
		{"host", &h, json_type_string, 1},
		{"args", &a, json_type_string, 1},
		{NULL, NULL, 0, 0}
	};
	GError *err = metautils_extract_json (obj, mapping);
	if (err) return err;

	struct meta1_service_url_s *m1u;
	size_t argslen = strlen(json_object_get_string(a));
	m1u = g_malloc0(sizeof(struct meta1_service_url_s) + 1 + argslen),
	m1u->seq = json_object_get_int64(s);
	g_strlcpy(m1u->srvtype, json_object_get_string(t), sizeof(m1u->srvtype));
	g_strlcpy(m1u->host, json_object_get_string(h), sizeof(m1u->host));
	g_strlcpy(m1u->args, json_object_get_string(a), argslen+1);
	*out = m1u;
	return NULL;
}

void
meta1_service_url_encode_json (GString *gstr, struct meta1_service_url_s *m1u)
{
	if (!m1u) {
		g_string_append(gstr, "null");
	} else {
		g_string_append_printf(gstr, "{\"seq\":%"G_GINT64_FORMAT",", m1u->seq);
		g_string_append_printf(gstr, "\"type\":\"%.*s\",", (int)sizeof(m1u->srvtype), m1u->srvtype);
		g_string_append_printf(gstr, "\"host\":\"%.*s\",", (int)sizeof(m1u->host), m1u->host);
		g_string_append_printf(gstr, "\"args\":\"%.*s\"}",
				LIMIT_LENGTH_SRVARGS, m1u->args);
	}
}

