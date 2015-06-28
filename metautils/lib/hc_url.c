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
# define G_LOG_DOMAIN "grid.url"
#endif

#include <errno.h>
#include <string.h>

#include "./metautils.h"
#include "./hc_url.h"
#include "./hc_url_ext.h"
#include "./url.h"

#define HCURL_OPTION_KEY_VERSION "version"
#define HCURL_OPTION_KEY_SNAPSHOT "snapshot"

enum {
	FLAG_DIRTY_ID    = 0x01,
	FLAG_DIRTY_NS    = 0X02,
	FLAG_DIRTY_WHOLE = 0x04
};

// format: hc://namespace/container/content?option1=val1&option2=val2...
struct hc_url_s
{
	/* primary */
	gchar *ns; 
	gchar *account; 
	gchar *user;
	gchar *type;
	gchar *path;
	GSList *options;
	/* secondary */
	gchar *whole;
	guint8 id[32];
	gchar hexid[65];
	guint8 flags;
};

/* ------------------------------------------------------------------------- */

static void
_options_reset (struct hc_url_s *u)
{
	g_slist_free_full(u->options, g_free);
	u->options = NULL;
}

static gchar **
_options_get(struct hc_url_s *u, const gchar *k)
{
	for (GSList *l = u->options; l ;l=l->next) {
		gchar *packed = l->data;
		gchar *sep = strchr(packed, '=');
		int kl = strlen(k);
		if ((kl == (sep-packed)) && (0 == memcmp(k,packed,kl)))
			return (gchar**)(&(l->data));
	}
	return NULL;
}

static void
_add_option(struct hc_url_s *u, const char *option_str)
{
	char *k, *cursor;
	if (option_str) {
		if (NULL != (cursor = strchr(option_str, '='))) {
			k = g_strndup(option_str, cursor - option_str);
			hc_url_set_option(u, k, cursor+1);
			g_free(k);
		} else {
			if (*option_str)
				GRID_WARN("wrong url option syntax for token [%s]", option_str);
			else
				GRID_WARN("empty option in url");
		}
	}
}

static int
_parse_oldurl(struct hc_url_s *url, const char *str)
{
	struct req_uri_s ruri = {NULL, NULL, NULL, NULL};

	if (metautils_requri_parse (str, &ruri)) { // Parse the path

		gchar **path_tokens = g_strsplit (ruri.path, "/", 3);
		if (path_tokens) {
			if (path_tokens[0]) {
				metautils_str_reuse (&url->ns, path_tokens[0]);
				metautils_str_replace (&url->account, HCURL_DEFAULT_ACCOUNT);
				if (path_tokens[1]) {
					metautils_str_reuse (&url->user, path_tokens[1]);
					metautils_str_replace (&url->type, HCURL_DEFAULT_TYPE);
					if (path_tokens[2])
						metautils_str_reuse (&url->path, path_tokens[2]);
				}
			}
			g_free (path_tokens);
		}

		if (ruri.query_tokens) { // Parse the options
			for (gchar **p=ruri.query_tokens; *p ;++p)
				_add_option(url, *p);
		}
	}

	metautils_requri_clear (&ruri);
	return 1;
}

static void
_replace (gchar **pp, const char *s)
{
	metautils_str_reuse (pp, g_uri_unescape_string (s, NULL));
}

static int
_parse_url(struct hc_url_s *url, const char *str)
{
	struct req_uri_s ruri = {NULL, NULL, NULL, NULL};

	if (!metautils_requri_parse (str, &ruri)) {
		metautils_requri_clear (&ruri);
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

	if (ruri.query_tokens) { // Parse the options
		for (gchar **p=ruri.query_tokens; *p ;++p)
			_add_option(url, *p);
	}

	metautils_requri_clear (&ruri);
	return 1;
}

static void
_clean_url (struct hc_url_s *u)
{
	metautils_str_clean(&u->ns);
	metautils_str_clean(&u->account);
	metautils_str_clean(&u->user);
	metautils_str_clean(&u->type);
	metautils_str_clean(&u->path);
	metautils_str_clean(&u->whole);
	memset (u->id, 0, sizeof(u->id));
	memset (u->hexid, 0, sizeof(u->hexid));
	u->flags = 0;
	_options_reset(u);
}

static int
_compute_id (struct hc_url_s *url)
{
	if (!url->ns || !url->user) {
		errno = EINVAL;
		return 0;
	}

	memset(url->hexid, 0, sizeof(url->hexid));
	memset(url->id, 0, sizeof(url->id));
	meta1_name2hash(url->id, url->ns, url->account, url->user);
	buffer2str(url->id, sizeof(url->id), url->hexid, sizeof(url->hexid));
	return 1;
}

/* ------------------------------------------------------------------------- */

struct hc_url_s *
hc_url_oldinit(const char *url)
{
	if (!url)
		return NULL;
	struct hc_url_s *result = SLICE_NEW0(struct hc_url_s);
	if (_parse_oldurl(result, url))
		return result;
	hc_url_clean(result);
	return NULL;
}

struct hc_url_s *
hc_url_init(const char *url)
{
	if (!url)
		return NULL;
	struct hc_url_s *result = SLICE_NEW0(struct hc_url_s);
	if (_parse_url(result, url))
		return result;
	hc_url_clean(result);
	return NULL;
}

struct hc_url_s *
hc_url_empty(void)
{
	return SLICE_NEW0(struct hc_url_s);
}

void
hc_url_clean(struct hc_url_s *u)
{
	if (!u)
		return;
	_clean_url (u);
	SLICE_FREE (struct hc_url_s, u);
}

void
hc_url_cleanv (struct hc_url_s **tab)
{
	if (!tab)
		return ;
	for (struct hc_url_s **p=tab; *p ;++p)
		hc_url_pclean (p);
	g_free(tab);
}

#define STRDUP(Dst,Src,Field) do { if (Src->Field) Dst->Field = g_strdup(Src->Field); } while (0)

struct hc_url_s *
hc_url_dup(struct hc_url_s *u)
{
	if (!u)
		return NULL;

	struct hc_url_s *result = g_memdup(u, sizeof(struct hc_url_s));
	STRDUP(result, u, ns);
	STRDUP(result, u, account);
	STRDUP(result, u, user);
	STRDUP(result, u, type);
	STRDUP(result, u, path);
	STRDUP(result, u, whole);

	result->options = NULL;
	for (GSList *l=u->options; l ;l=l->next) {
		gchar *packed = l->data;
		result->options = g_slist_prepend(result->options, g_strdup(packed));
	}
	result->options = g_slist_reverse(result->options);

	return result;
}

struct hc_url_s*
hc_url_set(struct hc_url_s *u, enum hc_url_field_e f, const char *v)
{
	if (!u || !v || strchr(v, '/')) {
		errno = EINVAL;
		return NULL;
	}

	metautils_str_clean(&(u->whole));

	switch (f) {
		case HCURL_NS:
			metautils_str_replace(&(u->ns), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_ACCOUNT:
			metautils_str_replace(&(u->account), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_USER:
			metautils_str_replace(&(u->user), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_TYPE:
			metautils_str_replace(&(u->type), v);
			u->hexid[0] = 0;
			return u;

		case HCURL_PATH:
			metautils_str_replace(&(u->path), v);
			return u;

		case HCURL_VERSION:
			hc_url_set_option(u, HCURL_OPTION_KEY_VERSION, v);
			return u;

		case HCURL_WHOLE:
			errno = ENOTSUP;
			return NULL;

		case HCURL_HEXID:
			u->hexid[0] = 0;
			if (!metautils_str_ishexa(v,64) || !hex2bin(v, u->id, sizeof(u->id), NULL)) {
				errno = EINVAL;
				return NULL;
			}
			memcpy(u->hexid, v, 64);
			return u;
	}

	g_assert_not_reached();
	return NULL;
}

int
hc_url_has(struct hc_url_s *u, enum hc_url_field_e f)
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
			return NULL != _options_get(u, HCURL_OPTION_KEY_VERSION);
		case HCURL_WHOLE:
			return TRUE;
		case HCURL_HEXID:
			return (u->ns && u->hexid[0]) || (u->ns && u->user);
	}

	g_assert_not_reached();
	return 0;
}

int
hc_url_has_fq_path (struct hc_url_s *u)
{
	return hc_url_has (u, HCURL_PATH) && hc_url_has_fq_container (u);
}

int
hc_url_has_fq_container (struct hc_url_s *u)
{
	return hc_url_has (u, HCURL_NS) && hc_url_has (u, HCURL_ACCOUNT) && hc_url_has (u, HCURL_USER);
}

static void
_append (GString *gs, const char *s)
{
	gchar *v = g_uri_escape_string (s, NULL, FALSE);
	g_string_append (gs, v);
	g_free (v);
}

static GString *
_pack_url(struct hc_url_s *u)
{
	GString *gs = g_string_new ("");
	if (u->ns) _append (gs, u->ns);
	g_string_append_c (gs, '/');
	if (u->account) _append (gs, u->account);
	g_string_append_c (gs, '/');
	if (u->user) _append (gs, u->user);
	g_string_append_c (gs, '/');
	if (u->type) _append (gs, u->type);
	if (hc_url_has (u, HCURL_PATH)) {
		g_string_append_c (gs, '/');
		_append (gs, hc_url_get(u, HCURL_PATH));
	}
	return gs;
}

static GString *
_append_options(GString *gs, struct hc_url_s *u)
{
	gboolean first = TRUE;
	for (GSList *l=u->options; l ;l=l->next) {
		g_string_append_c(gs, first ? '?' : '&');
		// Cool, options have already the good packed form
		g_string_append(gs, (gchar*)(l->data));
		first = FALSE;
	}
	return gs;
}

const char*
hc_url_get(struct hc_url_s *u, enum hc_url_field_e f)
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
			return hc_url_get_option_value(u, HCURL_OPTION_KEY_VERSION);

		case HCURL_WHOLE:
			if (!u->whole)
				u->whole = g_string_free(_append_options(_pack_url(u), u), FALSE);
			return u->whole;

		case HCURL_HEXID:
			if (!u->hexid[0]) {
				if (!_compute_id(u))
					return NULL;
				buffer2str(u->id, sizeof(u->id), u->hexid, sizeof(u->hexid));
				u->hexid[sizeof(u->hexid)-1] = '\0';
			}
			return u->hexid;
	}

	g_assert_not_reached();
	return NULL;
}

const void*
hc_url_get_id(struct hc_url_s *u)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}
	if (!u->hexid[0] && !_compute_id(u)) {
		errno = EAGAIN;
		return NULL;
	}
	return u->id;
}

void
hc_url_set_id (struct hc_url_s *u, const void *id)
{
	if (!u)
		return;
	u->hexid[0] = 0;
	metautils_str_clean(&(u->whole));
	if (id) {
		memcpy (u->id, id, 32);
		buffer2str (u->id, sizeof(u->id), u->hexid, sizeof(u->hexid));
	}
}

const char*
hc_url_get_option_value(struct hc_url_s *u, const char *k)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}
	gchar **pv = _options_get(u, k);
	return pv ? strchr(*pv,'=')+1 : NULL;
}

gchar **
hc_url_get_option_names(struct hc_url_s *u)
{
	EXTRA_ASSERT(u != NULL);
	guint i=0;
	gchar **result = g_malloc(sizeof(gchar*)*(1+g_slist_length(u->options)));
	for (GSList *l = u->options ; l ;l=l->next) {
		gchar *packed = l->data;
		gchar *sep = strchr(packed, '=');
		result[i++] = g_strndup(packed, sep-packed);
	}
	result[i] = NULL;
	return result;
}

void
hc_url_set_option (struct hc_url_s *u,  const char *k, const gchar *v)
{
	EXTRA_ASSERT (u != NULL);
	EXTRA_ASSERT (k != NULL);
	gchar **pv, *packed = g_strdup_printf("%s=%s", k, v);
	if (!(pv = _options_get(u, k)))
		u->options = g_slist_prepend(u->options, packed);
	else {
		g_free(*pv);
		*pv = packed;
	}
	g_free(u->whole);
	u->whole = NULL;
}

size_t
hc_url_get_id_size(struct hc_url_s *u)
{
	return u ? sizeof(u->id) : 0;
}

void
hc_url_set_oldns(struct hc_url_s *u, const char *ns)
{
	char pns[LIMIT_LENGTH_NSNAME];
	gsize s = metautils_strlcpy_physical_ns (pns, ns, sizeof(pns));
	hc_url_set (u, HCURL_NS, pns);
	hc_url_set (u, HCURL_ACCOUNT, ns[s-1] ? ns+s : HCURL_DEFAULT_ACCOUNT);
}

