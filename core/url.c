/*
OpenIO SDS core library
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2018 OpenIO SAS, as part of OpenIO SDS

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
#include <core/oioext.h>
#include <core/url_ext.h>
#include <core/client_variables.h>
#include <core/oiolog.h>

struct oio_url_s
{
	/* primary */
	gchar ns[LIMIT_LENGTH_NSNAME];
	gchar account[LIMIT_LENGTH_ACCOUNTNAME];
	gchar user[LIMIT_LENGTH_USER];
	gchar version[LIMIT_LENGTH_VERSION];

	gchar *path;
	gchar *content;

	/* secondary */
	gchar *whole;
	gchar *fullpath;
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

/* ------------------------------------------------------------------------- */

static int
_check_parsed_url (struct oio_url_s *u)
{
	if (!oio_url_has_fq_container (u))
		return 0;
	return !u->path || u->path[0];
}

static void
_replace (gchar **pp, const char *s, const gboolean unescape)
{
  if (unescape)
    oio_str_reuse(pp, g_uri_unescape_string (s, NULL));
  else
    oio_str_reuse(pp, g_strdup(s));
}

static void
_copy(gchar *dst, gsize dstlen, const char *src, const gboolean unescape)
{
  if (!unescape) {
    g_strlcpy(dst, src, dstlen);
  } else {
    gchar *tmp = g_uri_unescape_string (src, NULL);
    g_strlcpy(dst, tmp, dstlen);
    g_free(tmp);
  }
}

static int
_parse_url(struct oio_url_s *url, const char *str, gboolean unescape)
{
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
		_copy(url->ns, sizeof(url->ns), path_tokens[0], unescape);

		if (!path_tokens[1]) break;
		_copy(url->account, sizeof(url->account), path_tokens[1], unescape);

		if (!path_tokens[2]) break;
		_copy (url->user, sizeof(url->user), path_tokens[2], unescape);

		if (!path_tokens[3]) break;
		_copy (url->version, sizeof(url->version), path_tokens[3], unescape);

		if (!path_tokens[4]) break;
		_replace (&url->path, path_tokens[4], unescape);
	} while (0);

	if (path_tokens)
		g_strfreev (path_tokens);

	oio_requri_clear (&ruri);
	return _check_parsed_url (url);
}

static void
_clean_url (struct oio_url_s *u)
{
	u->ns[0] = '\0';
	u->account[0] = '\0';
	u->user[0] = '\0';
	u->version[0] = '\0';
	oio_str_clean(&u->path);
	oio_str_clean(&u->content);
	oio_str_clean(&u->whole);
	oio_str_clean(&u->fullpath);
	u->hexid[0] = '\0';
	u->flags = 0;
}

static int
_compute_id (struct oio_url_s *url)
{
	if (!url->account[0] || !url->user[0])
		return 0;

	url->hexid[0] = '\0';
	oio_str_hash_name(url->id, NULL, url->account, url->user);
	oio_str_bin2hex(url->id, sizeof(url->id), url->hexid, sizeof(url->hexid));
	return 1;
}

static gchar *
_pack_fullpath(struct oio_url_s *u)
{
	if (!u->account[0] || !u->user[0] || !u->path || !u->version[0] || !u->content)
		return NULL;

	GString *gs = g_string_new("");
	g_string_append_uri_escaped(gs, u->account, NULL, TRUE);
	g_string_append_c(gs, '/');
	g_string_append_uri_escaped(gs, u->user, NULL, TRUE);
	g_string_append_c(gs, '/');
	g_string_append_uri_escaped(gs, u->path, NULL, TRUE);
	g_string_append_c(gs, '/');
	g_string_append_uri_escaped(gs, u->version, NULL, TRUE);
	g_string_append_c(gs, '/');
	g_string_append_uri_escaped(gs, u->content, NULL, TRUE);
	return g_string_free(gs, FALSE);
}

static gboolean
_unpack_fullpath(struct oio_url_s *u, const gchar *strfullpath)
{
	gboolean rc = FALSE;
	gchar **fullpath = g_strsplit(strfullpath, "/", -1);
	if (g_strv_length(fullpath) == 5) {
		char *account = g_uri_unescape_string(fullpath[0], NULL);
		oio_url_set(u, OIOURL_ACCOUNT, account);
		g_free(account);
		char *container = g_uri_unescape_string(fullpath[1], NULL);
		oio_url_set(u, OIOURL_USER, container);
		g_free(container);
		char *path = g_uri_unescape_string(fullpath[2], NULL);
		oio_url_set(u, OIOURL_PATH, path);
		g_free(path);
		char *version = g_uri_unescape_string(fullpath[3], NULL);
		oio_url_set(u, OIOURL_VERSION, version);
		g_free(version);
		char *content = g_uri_unescape_string(fullpath[4], NULL);
		oio_url_set(u, OIOURL_CONTENTID, content);
		g_free(content);
		rc = TRUE;
	}
	g_strfreev(fullpath);
	return rc;
}

/* ------------------------------------------------------------------------- */

struct oio_url_s *
oio_url_init(const char *url)
{
	if (!url)
		return NULL;
	struct oio_url_s *result = g_slice_new0(struct oio_url_s);
	if (_parse_url(result, url, TRUE))
		return result;
	oio_url_clean(result);
	return NULL;
}

struct oio_url_s *
oio_url_init_raw(const char *url)
{
	if (!url)
		return NULL;
	struct oio_url_s *result = g_slice_new0(struct oio_url_s);
	if (_parse_url(result, url, FALSE))
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
oio_url_dup(const struct oio_url_s *u)
{
	if (!u)
		return NULL;

	struct oio_url_s *result = g_slice_new0(struct oio_url_s);
	memcpy (result, u, sizeof(struct oio_url_s));

	STRDUP(result, u, path);
	STRDUP(result, u, whole);
	STRDUP(result, u, content);
	STRDUP(result, u, fullpath);
	return result;
}

struct oio_url_s*
oio_url_set(struct oio_url_s *u, enum oio_url_field_e f, const char *v)
{
	if (!u || !v)
		return NULL;

	oio_str_clean(&(u->whole));

	switch (f) {
		case OIOURL_NS:
			g_strlcpy(u->ns, v, sizeof(u->ns));
			u->hexid[0] = 0;
			return u;

		case OIOURL_ACCOUNT:
			g_strlcpy(u->account, v, sizeof(u->account));
			u->hexid[0] = 0;
			oio_str_clean(&u->fullpath);
			return u;

		case OIOURL_USER:
			g_strlcpy(u->user, v, sizeof(u->user));
			u->hexid[0] = 0;
			oio_str_clean(&u->fullpath);
			return u;

		case OIOURL_PATH:
			oio_str_replace(&(u->path), v);
			oio_str_clean(&u->fullpath);
			return u;

		case OIOURL_VERSION:
			g_strlcpy(u->version, v, sizeof(u->version));
			oio_str_clean(&u->fullpath);
			return u;

		case OIOURL_WHOLE:
			return NULL;

		case OIOURL_FULLPATH:
			if (_unpack_fullpath(u, v))
				return u;
			return NULL;

		case OIOURL_HEXID:
			u->hexid[0] = 0;
			if (oio_str_ishexa(v, 64) && oio_str_hex2bin(v, u->id, 32)) {
				memcpy(u->hexid, v, 64);
				return u;
			}
			return NULL;

		case OIOURL_CONTENTID:
			if (!oio_str_ishexa1(v))
				return NULL;
			oio_str_replace(&(u->content), v);
			oio_str_clean(&u->fullpath);
			return u;
	}

	g_assert_not_reached();
	return NULL;
}

void
oio_url_unset(struct oio_url_s *u, enum oio_url_field_e f)
{
	if (!u)
		return;

	switch (f) {
		case OIOURL_NS:
			u->ns[0] = u->hexid[0] = 0;
			return;

		case OIOURL_ACCOUNT:
			u->account[0] = u->hexid[0] = 0;
			oio_str_clean(&u->fullpath);
			return;

		case OIOURL_USER:
			u->user[0] = u->hexid[0] = 0;
			oio_str_clean(&u->fullpath);
			return;

		case OIOURL_PATH:
			oio_str_clean(&u->path);
			oio_str_clean(&u->fullpath);
			return;

		case OIOURL_VERSION:
			u->version[0] = '\0';
			oio_str_clean(&u->fullpath);
			return;

		case OIOURL_WHOLE:
			oio_str_clean(&u->whole);
			return;

		case OIOURL_FULLPATH:
			oio_str_clean(&u->fullpath);
			return;

		case OIOURL_HEXID:
			u->hexid[0] = 0;
			return;

		case OIOURL_CONTENTID:
			oio_str_clean(&u->content);
			oio_str_clean(&u->fullpath);
			return;
	}

	g_assert_not_reached();
}

int
oio_url_has(const struct oio_url_s *u, enum oio_url_field_e f)
{
	if (!f || !u)
		return 0;

	switch (f) {
		case OIOURL_NS:
			return u->ns[0];
		case OIOURL_ACCOUNT:
			return u->account[0];
		case OIOURL_USER:
			return u->user[0];
		case OIOURL_PATH:
			return oio_str_is_set(u->path);
		case OIOURL_VERSION:
			return oio_str_is_set(u->version);
		case OIOURL_WHOLE:
			return TRUE;
		case OIOURL_FULLPATH:
			return TRUE;
		case OIOURL_HEXID:
			return (u->ns[0] && u->hexid[0]) || (u->ns[0] && u->user[0]);
		case OIOURL_CONTENTID:
			return NULL != u->content;
	}

	g_assert_not_reached();
	return 0;
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

static GString *
_pack_url(struct oio_url_s *u)
{
	GString *gs = g_string_new ("");
	if (u->ns[0]) {
		g_string_append_uri_escaped (gs, u->ns, NULL, TRUE);
		if (u->account[0]) {
			g_string_append_c (gs, '/');
			g_string_append_uri_escaped (gs, u->account, NULL, TRUE);
			if (u->user[0]) {
				g_string_append_c (gs, '/');
				g_string_append_uri_escaped (gs, u->user, NULL, TRUE);
				g_string_append_c (gs, '/');
				if (u->path) {
					/* TODO(jfs): once there is no type anywhere, we can use the version here */
					if (u->version[0])
						g_string_append_uri_escaped (gs, u->version, NULL, TRUE);
					g_string_append_c (gs, '/');
					g_string_append_uri_escaped (gs, u->path, NULL, TRUE);
				}
				gboolean anyopt = FALSE;
				if (u->content) {
					g_string_append_c (gs, anyopt ? '&' : '?');
					g_string_append_len (gs, "id=", 3);
					g_string_append_uri_escaped (gs, u->content, NULL, TRUE);
					anyopt = TRUE;
				}
				if (u->version[0]) {
					g_string_append_c (gs, anyopt ? '&' : '?');
					g_string_append_len (gs, "v=", 2);
					g_string_append_uri_escaped (gs, u->version, NULL, TRUE);
					anyopt = TRUE;
				}
			}
		}
	}
	return gs;
}

const char*
oio_url_get(struct oio_url_s *u, enum oio_url_field_e f)
{
	if (!u || !f)
		return NULL;

	switch (f) {
		case OIOURL_NS:
			return u->ns[0] ? u->ns : NULL;
		case OIOURL_ACCOUNT:
			return u->account[0] ? u->account : NULL;
		case OIOURL_USER:
			return u->user[0] ? u->user : NULL;
		case OIOURL_PATH:
			return u->path;

		case OIOURL_VERSION:
			return u->version[0] ? u->version : NULL;

		case OIOURL_WHOLE:
			if (!u->whole)
				u->whole = g_string_free(_pack_url(u), FALSE);
			return u->whole;

		case OIOURL_HEXID:
			if (!u->hexid[0]) {
				if (!_compute_id(u))
					return NULL;
				oio_str_bin2hex(u->id, sizeof(u->id), u->hexid, sizeof(u->hexid));
				u->hexid[sizeof(u->hexid)-1] = '\0';
			}
			return u->hexid;

		case OIOURL_CONTENTID:
			return u->content;

		case OIOURL_FULLPATH:
			if (!u->fullpath)
				u->fullpath = _pack_fullpath(u);
			return u->fullpath;
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
oio_url_to_json (GString *out, struct oio_url_s *u)
{
	gsize len = out->len;

	oio_str_gstring_append_json_pair (out, "ns", u->ns[0] ? u->ns : NULL);
	if (oio_str_is_set(u->account)) {
		if (len != out->len) g_string_append_c (out, ',');
		oio_str_gstring_append_json_pair (out, "account", u->account);
	}
	if (oio_str_is_set(u->user)) {
		if (len != out->len) g_string_append_c (out, ',');
		oio_str_gstring_append_json_pair (out, "user", u->user);
	}
	if (oio_str_is_set(u->path)) {
		if (len != out->len) g_string_append_c (out, ',');
		oio_str_gstring_append_json_pair (out, "path", u->path);
	}
	if (oio_str_is_set(u->content)) {
		if (len != out->len) g_string_append_c (out, ',');
		oio_str_gstring_append_json_pair (out, "content", u->content);
	}
	if (oio_url_get_id(u)) {
		if (len != out->len) g_string_append_c (out, ',');
		oio_str_gstring_append_json_pair (out, "id", u->hexid);
	}
	if (oio_str_is_set(u->version)) {
		if (len != out->len)
			g_string_append_c(out, ',');
		oio_str_gstring_append_json_pair(out, "version", u->version);
	}
}

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
