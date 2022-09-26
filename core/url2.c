/*
OpenIO SDS core library
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2022 OVH SAS

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

#include <core/oiourl.h>

#include <string.h>

#include <core/oiostr.h>
#include <core/url_ext.h>
#include <core/client_variables.h>
#include <core/oiolog.h>
#include <core/url_internals.h>

gboolean
oio_url_check(const struct oio_url_s *u, const char *namespace,
		const gchar **err)
{
#define _ERR(v)  \
	if (err) { \
		*err = v; \
	}

	_ERR(NULL);
	if (namespace && u->ns[0] && 0 != strcmp(namespace, u->ns)) {
		_ERR("'namespace'");
		return FALSE;
	}
	if (u->version[0] && !oio_str_is_number(u->version, NULL)) {
		_ERR("'version', not a number");
		return FALSE;
	}

	if (u->user[0] && !g_utf8_validate(u->user, -1, NULL)) {
		if (oio_url_must_be_unicode) {
			_ERR("'user', not UTF-8");
			return FALSE;
		}
#if GLIB_CHECK_VERSION(2,52,0)
		else {
			gchar *tmp = g_utf8_make_valid(u->user, -1);
			GRID_WARN("Non UTF-8 'user' received: %s", tmp);
			g_free(tmp);
		}
#endif
	}
	if (u->path && !g_utf8_validate(u->path, -1, NULL)) {
		if (oio_url_must_be_unicode) {
			_ERR("'path', not UTF-8");
			return FALSE;
		}
#if GLIB_CHECK_VERSION(2,52,0)
		else {
			gchar *tmp = g_utf8_make_valid(u->path, -1);
			GRID_WARN("Non UTF-8 'path' received: %s", tmp);
			g_free(tmp);
		}
#endif
	}
	return TRUE;

#undef _ERR
}

void
oio_url_to_json(GString *out, struct oio_url_s *u, gboolean root_url)
{
	gsize len = out->len;
	gsize starting_len = len;

	oio_str_gstring_append_json_pair(out, "ns", u->ns[0] ? u->ns : NULL);
	if (root_url && oio_str_is_set(u->root_hexid)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "id", u->root_hexid);
		g_string_append_static(out, ",\"shard\":{");
		len = out->len;
	}
	if (oio_str_is_set(u->account)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "account", u->account);
	}
	if (oio_str_is_set(u->user)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "user", u->user);
	}
	if (oio_url_get_id(u)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "id", u->hexid);
	}
	if (root_url && oio_str_is_set(u->root_hexid)) {
		g_string_append_static(out, "}");
		len = starting_len;
	}
	if (oio_str_is_set(u->path)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "path", u->path);
	}
	if (oio_str_is_set(u->content)) {
		if (len != out->len) g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "content", u->content);
	}
	if (oio_str_is_set(u->version)) {
		if (len != out->len)
			g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "version", u->version);
	}
}

void
oio_url_set_id (struct oio_url_s *u, const void *id)
{
	if (!u)
		return;
	u->hexid[0] = 0;
	oio_str_clean(&(u->whole));
	if (id) {
		memcpy (u->id, id, 32);
		oio_str_bin2hex (u->id, sizeof(u->id), u->hexid, sizeof(u->hexid));
	}
}

int
oio_url_has_fq_path (const struct oio_url_s *u)
{
	return oio_url_has (u, OIOURL_PATH) && oio_url_has_fq_container (u);
}

int
oio_url_has_fq_container (const struct oio_url_s *u)
{
	return oio_url_has (u, OIOURL_NS) && oio_url_has (u, OIOURL_ACCOUNT) && oio_url_has (u, OIOURL_USER);
}

void
oio_url_pclean(struct oio_url_s **pu)
{
	if (!pu)
		return;
	oio_url_clean(*pu);
	*pu = (void*)0;
}

gboolean
oio_requri_parse (const char *str, struct oio_requri_s *uri)
{
	if (!str || !uri)
		return FALSE;

	gchar *pq = strchr (str, '?');
	gchar *pa = pq ? strchr (pq, '#') : strchr (str, '#');

	// Extract the main components
	if (pq || pa)
		uri->path = g_strndup (str, (pq ? pq : pa) - str);
	else
		uri->path = g_strdup (str);

	if (pq) {
		if (pa)
			uri->query = g_strndup (pq + 1, pa - pq);
		else
			uri->query = g_strdup (pq + 1);
	} else
		uri->query = g_strdup("");

	if (pa)
		uri->fragment = g_strdup (pa + 1);
	else
		uri->fragment = g_strdup("");

	// Split and unescape the query components
	if (uri->query)
		uri->query_tokens = g_strsplit(uri->query, "&", -1);
	else
		uri->query_tokens = g_malloc0(sizeof(void*));
	for (gchar **p = uri->query_tokens; *p; ++p) {
		if (*p) for (gchar *q=*p; *q ;++q)
			if (*q == '+') *q = ' ';
		oio_str_reuse (p, g_uri_unescape_string (*p, NULL));
	}

	return TRUE;
}

void
oio_requri_clear (struct oio_requri_s *uri)
{
	oio_str_clean (&uri->path);
	oio_str_clean (&uri->query);
	oio_str_clean (&uri->fragment);
	g_strfreev(uri->query_tokens);
}

