/*
OpenIO SDS core library
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

#include <string.h>

#include "oio_core.h"
#include "url_ext.h"

struct oio_url_s
{
	/* primary */
	gchar *ns; 
	gchar *account; 
	gchar *user;
	gchar *type;
	gchar *path;

	gchar *version;

	/* secondary */
	gchar *whole;
	guint8 id[32];
	gchar hexid[65];
	guint8 flags;
};

/* ------------------------------------------------------------------------- */

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

	for (gchar **p=uri->query_tokens; p && *p ;++p)
		oio_str_reuse (p, g_uri_unescape_string (*p, NULL));

	return TRUE;
}

void
oio_requri_clear (struct oio_requri_s *uri)
{
	if (uri->path) g_free (uri->path);
	if (uri->query) g_free (uri->query);
	if (uri->fragment) g_free (uri->fragment);
	g_strfreev(uri->query_tokens);
}

/* ------------------------------------------------------------------------- */

static int
_check_parsed_url (struct oio_url_s *u)
{
	if (!u->ns || !u->ns[0]) return 0;
	if (!u->user || !u->user[0]) return 0;
	if (u->path && !u->path[0]) return 0;
	return 1;
}

static int
_parse_oldurl(struct oio_url_s *url, const char *str)
{
	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};

	// Purify the url
	size_t len = strlen (str);
	char *tmp = g_alloca (len+1);

	do {
		char *p = tmp;
		for (; *str && *str == '/' ;++str) {} // skip the leading slashes
		if (*str) { // Copy the NS
			for (; *str && *str != '/' ;++str)
				*(p++) = *str;
		}
		if (*str) *(p++) = '/'; // Copy a single separator
		for (; *str && *str == '/' ;++str) {} // skip separators
		if (*str) strcpy(p, str); // Copy what remains
	} while (0);

	if (oio_requri_parse (tmp, &ruri)) { // Parse the path

		gchar **path_tokens = g_strsplit (ruri.path, "/", 3);
		if (path_tokens) {
			if (path_tokens[0]) {
				oio_str_reuse (&url->ns, path_tokens[0]);
				oio_str_replace (&url->account, HCURL_DEFAULT_ACCOUNT);
				if (path_tokens[1]) {
					oio_str_reuse (&url->user, path_tokens[1]);
					oio_str_replace (&url->type, HCURL_DEFAULT_TYPE);
					if (path_tokens[2])
						oio_str_reuse (&url->path, path_tokens[2]);
				}
			}
			g_free (path_tokens);
		}

	}

	oio_requri_clear (&ruri);
	return _check_parsed_url (url);
}

static int
_parse_url(struct oio_url_s *url, const char *str)
{
	inline void _replace (gchar **pp, const char *s) {
		oio_str_reuse (pp, g_uri_unescape_string (s, NULL));
	}

	struct oio_requri_s ruri = {NULL, NULL, NULL, NULL};

	for (; *str && *str == '/' ;++str) {} // skip the leading slashes

	if (!oio_requri_parse (str, &ruri)) {
		oio_requri_clear (&ruri);
		return 0;
	}

	gchar **path_tokens = g_strsplit (ruri.path, "/", 5);
	do {
		if (!path_tokens) break;

		if (!path_tokens[0]) break;
		_replace (&url->ns, path_tokens[0]);

		if (!path_tokens[1]) break;
		_replace (&url->account, path_tokens[1]);

		if (!path_tokens[2]) break;
		_replace (&url->user, path_tokens[2]);

		if (!path_tokens[3]) break;
		_replace (&url->type, path_tokens[3]);

		if (!path_tokens[4]) break;
		_replace (&url->path, path_tokens[4]);
	} while (0);

	if (path_tokens) g_strfreev (path_tokens);

	oio_requri_clear (&ruri);
	return _check_parsed_url (url);
}

static void
_clean_url (struct oio_url_s *u)
{
	oio_str_clean(&u->ns);
	oio_str_clean(&u->account);
	oio_str_clean(&u->user);
	oio_str_clean(&u->type);
	oio_str_clean(&u->path);
	oio_str_clean(&u->version);
	oio_str_clean(&u->whole);
	memset (u->id, 0, sizeof(u->id));
	memset (u->hexid, 0, sizeof(u->hexid));
	u->flags = 0;
}

static int
_compute_id (struct oio_url_s *url)
{
	if (!url->ns || !*url->ns || !url->user || !*url->user)
		return 0;

	memset(url->hexid, 0, sizeof(url->hexid));
	memset(url->id, 0, sizeof(url->id));
	oio_str_hash_name(url->id, url->ns, url->account, url->user);
	oio_str_bin2hex(url->id, sizeof(url->id), url->hexid, sizeof(url->hexid));
	return 1;
}

/* ------------------------------------------------------------------------- */

struct oio_url_s *
oio_url_oldinit(const char *url)
{
	if (!url)
		return NULL;
	struct oio_url_s *result = g_slice_new0(struct oio_url_s);
	if (_parse_oldurl(result, url))
		return result;
	oio_url_clean(result);
	return NULL;
}

struct oio_url_s *
oio_url_init(const char *url)
{
	if (!url)
		return NULL;
	struct oio_url_s *result = g_slice_new0(struct oio_url_s);
	if (_parse_url(result, url))
		return result;
	oio_url_clean(result);
	return NULL;
}

struct oio_url_s *
oio_url_empty(void)
{
	return g_slice_new0(struct oio_url_s);
}

void
oio_url_clean(struct oio_url_s *u)
{
	if (!u)
		return;
	_clean_url (u);
	g_slice_free (struct oio_url_s, u);
}

void
oio_url_cleanv (struct oio_url_s **tab)
{
	if (!tab)
		return ;
	for (struct oio_url_s **p=tab; *p ;++p)
		oio_url_pclean (p);
	g_free(tab);
}

void
oio_url_pclean(struct oio_url_s **pu)
{
	if (!pu)
		return;
	oio_url_clean(*pu);
	*pu = (void*)0;
}

#define STRDUP(Dst,Src,Field) do { \
	if (Src->Field) \
		Dst->Field = g_strdup(Src->Field); \
} while (0)

struct oio_url_s *
oio_url_dup(struct oio_url_s *u)
{
	if (!u)
		return NULL;

	struct oio_url_s *result = g_memdup(u, sizeof(struct oio_url_s));
	STRDUP(result, u, ns);
	STRDUP(result, u, account);
	STRDUP(result, u, user);
	STRDUP(result, u, type);
	STRDUP(result, u, path);
	STRDUP(result, u, whole);
	STRDUP(result, u, version);
	return result;
}

struct oio_url_s*
oio_url_set(struct oio_url_s *u, enum oio_url_field_e f, const char *v)
{
	if (!u || !v)
		return NULL;

	oio_str_clean(&(u->whole));

	switch (f) {
		case HCURL_NS:
			oio_str_replace(&(u->ns), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_ACCOUNT:
			oio_str_replace(&(u->account), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_USER:
			oio_str_replace(&(u->user), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_TYPE:
			oio_str_replace(&(u->type), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_PATH:
			oio_str_replace(&(u->path), v);
			return u;

		case HCURL_VERSION:
			oio_str_replace(&(u->version), v);
			return u;

		case HCURL_WHOLE:
			return NULL;

		case HCURL_HEXID:
			u->hexid[0] = 0;
			if (!oio_str_ishexa(v,64) || !oio_str_hex2bin(v, u->id, 32))
				return NULL;
			memcpy(u->hexid, v, 64);
			return u;
	}

	g_assert_not_reached();
	return NULL;
}

int
oio_url_has(struct oio_url_s *u, enum oio_url_field_e f)
{
	if (!f || !u)
		return 0;

	switch (f) {
		case HCURL_NS:
			return NULL != u->ns;
		case HCURL_ACCOUNT:
			// the account has a default value
			return TRUE;
		case HCURL_USER:
			return NULL != u->user;
		case HCURL_TYPE:
			// the type has a default value
			return TRUE;
		case HCURL_PATH:
			return NULL != u->path;
		case HCURL_VERSION:
			return NULL != u->version;
		case HCURL_WHOLE:
			return TRUE;
		case HCURL_HEXID:
			return (u->ns && u->hexid[0]) || (u->ns && u->user);
	}

	g_assert_not_reached();
	return 0;
}

int
oio_url_has_fq_path (struct oio_url_s *u)
{
	return oio_url_has (u, HCURL_PATH) && oio_url_has_fq_container (u);
}

int
oio_url_has_fq_container (struct oio_url_s *u)
{
	return oio_url_has (u, HCURL_NS) && oio_url_has (u, HCURL_ACCOUNT) && oio_url_has (u, HCURL_USER);
}

static GString *
_pack_url(struct oio_url_s *u)
{
	inline void _append (GString *gs, const char *s) {
		gchar *v = g_uri_escape_string (s, NULL, FALSE);
		g_string_append (gs, v);
		g_free (v);
	}

	GString *gs = g_string_new ("");
	if (u->ns) _append (gs, u->ns);
	g_string_append_c (gs, '/');
	if (u->account) _append (gs, u->account);
	g_string_append_c (gs, '/');
	if (u->user) _append (gs, u->user);
	g_string_append_c (gs, '/');
	if (u->type) _append (gs, u->type);
	if (oio_url_has (u, HCURL_PATH)) {
		g_string_append_c (gs, '/');
		_append (gs, oio_url_get(u, HCURL_PATH));
	}
	return gs;
}

const char*
oio_url_get(struct oio_url_s *u, enum oio_url_field_e f)
{
	if (!u || !f)
		return NULL;

	switch (f) {
		case HCURL_NS:
			return u->ns;
		case HCURL_ACCOUNT:
			return u->account ? u->account : HCURL_DEFAULT_ACCOUNT;
		case HCURL_USER:
			return u->user;
		case HCURL_TYPE:
			return u->type ? u->type : HCURL_DEFAULT_TYPE;
		case HCURL_PATH:
			return u->path;

		case HCURL_VERSION:
			return u->version;

		case HCURL_WHOLE:
			if (!u->whole)
				u->whole = g_string_free(_pack_url(u), FALSE);
			return u->whole;

		case HCURL_HEXID:
			if (!u->hexid[0]) {
				if (!_compute_id(u))
					return NULL;
				oio_str_bin2hex(u->id, sizeof(u->id), u->hexid, sizeof(u->hexid));
				u->hexid[sizeof(u->hexid)-1] = '\0';
			}
			return u->hexid;
	}

	g_assert_not_reached();
	return NULL;
}

const void*
oio_url_get_id(struct oio_url_s *u)
{
	if (!u)
		return NULL;
	if (!u->hexid[0] && !_compute_id(u))
		return NULL;
	return u->id;
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

size_t
oio_url_get_id_size(struct oio_url_s *u)
{
	return u ? sizeof(u->id) : 0;
}

void
oio_url_set_oldns(struct oio_url_s *u, const char *ns)
{
	gchar **tokens = g_strsplit(ns, ".", 2);
	if (!tokens) return;
	if (tokens[0]) {
		oio_url_set (u, HCURL_NS, tokens[0]);
		if (tokens[1]) 
			oio_url_set (u, HCURL_ACCOUNT, tokens[1]);
	}
	g_strfreev(tokens);
}

void
oio_url_to_json (GString *out, struct oio_url_s *u)
{
	gboolean first = TRUE;

	g_string_append_printf (out, "\"ns\":\"%s\"", oio_url_get (u, HCURL_NS));

	first = FALSE;
	if (oio_url_has (u, HCURL_ACCOUNT)) {
		if (!first) g_string_append_c (out, ',');
		g_string_append_printf (out, "\"account\":\"%s\"", oio_url_get (u, HCURL_ACCOUNT));
		first = FALSE;
	}
	if (oio_url_has (u, HCURL_USER)) {
		if (!first) g_string_append_c (out, ',');
		g_string_append_printf (out, "\"user\":\"%s\"", oio_url_get (u, HCURL_USER));
		first = FALSE;
	}
	if (oio_url_has (u, HCURL_TYPE)) {
		if (!first) g_string_append_c (out, ',');
		g_string_append_printf (out, "\"type\":\"%s\"", oio_url_get (u, HCURL_TYPE));
		first = FALSE;
	}
	if (oio_url_has (u, HCURL_PATH)) {
		if (!first) g_string_append_c (out, ',');
		g_string_append_printf (out, "\"path\":\"%s\"", oio_url_get (u, HCURL_PATH));
	}
}

