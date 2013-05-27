/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.url"
#endif

#include <errno.h>
#include <string.h>
#include <glib.h>

#include "./hc_url.h"
#include "./metautils.h"

#define HCURL_OPTION_KEY_VERSION "version"

enum {
	FLAG_DIRTY_ID    = 0x01,
	FLAG_DIRTY_NS    = 0X02,
	FLAG_DIRTY_WHOLE = 0x04
};

// format: hc://namespace/container/content?option1=val1&option2=val2...
struct hc_url_s
{
	gchar *ns;
	gchar *pns; /* secondary */
	gchar *vns; /* secondary */

	gchar *refname;

	gchar *path;

	GHashTable *options;

	gchar *whole; /* secondary */

	guint8 id[32];
	gchar hexid[65];

	guint8 flags;
};

/* ------------------------------------------------------------------------- */

#define PREFIX "hc://"

#define skip_slashes(p) do { for (; *p && *p == '/'; p++) {} } while (0)

static inline void
str_clean(gchar **s)
{
	if (*s)
		g_free(*s);
	*s = NULL;
}

static inline void
str_replace(gchar **dst, const gchar *src)
{
	if (*dst)
		g_free(*dst);
	*dst = src ? g_strdup(src) : NULL;
}

static inline void
_strip_trailing_slashes(gchar *src)
{
	register gchar *s;

	if (!src || !*src)
		return;

	for (s = src + strlen(src) - 1; s>=src && *s == '/' ;s--)
		*s = '\0';
}

static void
_parse_ns(struct hc_url_s *url)
{
	gchar *dot;

	if (!url->ns)
		return;

	if (!(dot = strchr(url->ns, '.')))
		url->pns = g_strdup(url->ns);
	else {
		url->pns = g_strndup(url->ns, dot - url->ns);
		url->vns = g_strdup(dot);
	}

	_strip_trailing_slashes(url->ns);
	_strip_trailing_slashes(url->pns);
	_strip_trailing_slashes(url->vns);
}

static GHashTable*
_options_new()
{
	return g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
}

static void
_options_free(GHashTable *options)
{
	g_hash_table_destroy(options);
}

static void
_options_dump(GHashTable *options)
{
	auto void _show_option(gpointer, gpointer, gpointer);

	void _show_option(gpointer _option_name, gpointer _option_value, gpointer _unused)
	{
		gchar *name = _option_name;
		gchar *value = _option_value;
		(void) _unused;
		GRID_WARN("   %s=%s", name, value);
	}

	if (options)
		g_hash_table_foreach(options, _show_option, NULL);
}

static gboolean
_add_option_value(GHashTable *options_ht, gchar *option_name, gchar *option_value)
{
	gboolean ret;

	if (*option_name) {
		g_hash_table_insert(options_ht, option_name, option_value);
		ret = TRUE;
	} else {
		GRID_WARN("empty option name in url (associated value=[%s])", option_value);
		ret = FALSE;
	}

	return ret;
}

static void
_add_option(GHashTable *options_ht, const gchar *option_str)
{
	gchar *option_name, *option_value, *cursor;
	g_assert(options_ht);
	if (option_str) {
		if (NULL != (cursor = strchr(option_str, '='))) {
			option_name = g_strndup(option_str, cursor - option_str);
			option_value = g_strdup(cursor + 1);
			if (!_add_option_value(options_ht, option_name, option_value)) {
				g_free(option_name);
				g_free(option_value);
			}
		} else {
			if (*option_str)
				GRID_WARN("wrong url option syntax for token [%s]", option_str);
			else
				GRID_WARN("empty option in url");
		}
	}
}

static void
_parse_options(GHashTable *options_ht, const gchar *options)
{
	gchar **strv;
	guint counter;
	g_assert(options_ht);
	if (options && *options)  {
		if (NULL != (strv = g_strsplit(options, "&", 0))) {
			for (counter = 0U; counter < g_strv_length(strv); counter++)
				_add_option(options_ht, strv[counter]);
			g_strfreev(strv);
		}
	}
}

static int
_parse_url(struct hc_url_s *url, const gchar *str)
{
	const gchar *ns, *refname, *path, *options;

	ns = g_str_has_prefix(str, PREFIX) ? str+sizeof(PREFIX)-1 : str;

	skip_slashes(ns);
	if (!*ns)
		return 0;

	refname = strchr(ns, '/');
	if (refname) {
		++ refname;
		skip_slashes(refname);
	}

	path = refname ? strrchr(refname, '/') : NULL;
	if (path) {
		if (!*(++path))
			path = NULL;
	}

	options = path ? strrchr(path, '?') : NULL;
	if (options) {
		if (!*(++options))
			options = NULL;
		if (url->options)
			_options_free(url->options);
		url->options = _options_new();
		_parse_options(url->options, options);
	}

	if (refname) {
		url->ns = g_strndup(ns, (refname-1)-ns);
		if (path) {
			url->refname = g_strndup(refname, (path-1)-refname);
			if (options)
				url->path = g_strndup(path, (options-1)-path);
			else
				url->path = g_strdup(path);
		} else {
			url->refname = g_strdup(refname);
		}
	}
	else {
		url->ns = g_strdup(ns);
	}

	_parse_ns(url);
	_strip_trailing_slashes(url->path);
	_strip_trailing_slashes(url->refname);
	return 1;
}

static int
_compute_id(struct hc_url_s *url)
{
	if (!url->refname) {
		errno = EINVAL;
		return 0;
	}

	memset(url->hexid, 0, sizeof(url->hexid));
	memset(url->id, 0, sizeof(url->id));
	meta1_name2hash(url->id, url->ns, url->refname);
	buffer2str(url->id, sizeof(url->id), url->hexid, sizeof(url->hexid));
	return 1;
}

/* ------------------------------------------------------------------------- */

struct hc_url_s *
hc_url_init(const char *url)
{
	struct hc_url_s *result;

	if (!url)
		return NULL;

	result = g_malloc0(sizeof(*result));
	if (_parse_url(result, url))
		return result;
	hc_url_clean(result);
	return NULL;
}

struct hc_url_s *
hc_url_empty(void)
{
	return g_malloc0(sizeof(struct hc_url_s));
}

void
hc_url_clean(struct hc_url_s *u)
{
	if (!u)
		return;

	if (u->ns)
		g_free(u->ns);
	if (u->vns)
		g_free(u->vns);
	if (u->pns)
		g_free(u->pns);
	if (u->refname)
		g_free(u->refname);
	if (u->path)
		g_free(u->path);
	if (u->options)
		_options_free(u->options);
	if (u->whole)
		g_free(u->whole);

	g_free(u);
}

void
hc_url_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	if (u)
		hc_url_clean(u);
}

struct hc_url_s*
hc_url_set(struct hc_url_s *u, enum hc_url_field_e f,
		const char *v)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}

	switch (f) {
		case HCURL_NS:
			str_replace(&(u->ns), v);
			str_clean(&(u->pns));
			str_clean(&(u->vns));
			str_clean(&(u->whole));
			u->hexid[0] = 0;
			_parse_ns(u);
			return u;

		case HCURL_NSPHYS:
			str_clean(&(u->ns));
			str_replace(&(u->pns), v);
			u->ns = u->vns && u->pns
				? g_strconcat(u->pns, ".", u->vns, NULL)
				: g_strdup(u->pns);
			str_clean(&(u->whole));
			return u;

		case HCURL_NSVIRT:
			str_clean(&(u->ns));
			str_replace(&(u->vns), v);
			u->ns = u->vns && u->pns
				? g_strconcat(u->pns, ".", u->vns, NULL)
				: g_strdup(u->pns);
			str_clean(&(u->whole));
			u->hexid[0] = 0;
			return u;

		case HCURL_REFERENCE:
			str_replace(&(u->refname), v);
			str_clean(&(u->whole));
			u->hexid[0] = 0;
			return u;

		case HCURL_PATH:
			str_replace(&(u->path), v);
			str_clean(&(u->whole));
			return u;

		case HCURL_OPTIONS:
			if (u->options)
				_options_free(u->options);
			u->options = _options_new();
			_parse_options(u->options, v);
			return u;

		case HCURL_VERSION:
			if (!u->options)
				u->options = _options_new();
			_add_option_value(u->options, g_strdup(HCURL_OPTION_KEY_VERSION), g_strdup(v));
			return u;

		case HCURL_WHOLE:
			str_clean(&(u->ns));
			str_clean(&(u->pns));
			str_clean(&(u->vns));
			str_clean(&(u->refname));
			str_clean(&(u->path));
			str_clean(&(u->whole));
			u->hexid[0] = 0;
			if (!_parse_url(u, v))
				return NULL;
			return u;

		case HCURL_HEXID:
			str_clean(&(u->refname));
			str_clean(&(u->whole));
			u->hexid[0] = 0;

			if (strlen(v)!=64) {
				errno = EINVAL;
				return NULL;
			}
			memcpy(u->hexid, v, 64);
			if (!hex2bin(u->hexid, u->id, sizeof(u->id), NULL)) {
				errno = EINVAL;
				return NULL;
			}
			return u;
	}

	g_assert_not_reached();
	return NULL;
}

int
hc_url_has(struct hc_url_s *u, enum hc_url_field_e f)
{
	if (!f)
		return 0;

	switch (f) {
		case HCURL_NS:
			return NULL != u->ns;
		case HCURL_NSPHYS:
			return NULL != u->pns;
		case HCURL_NSVIRT:
			return NULL != u->vns;
		case HCURL_REFERENCE:
			return NULL != u->refname;
		case HCURL_PATH:
			return NULL != u->path;
		case HCURL_OPTIONS:
			return NULL != u->options;
		case HCURL_VERSION:
			if (!u->options)
				return 0;
			return NULL != g_hash_table_lookup(u->options, HCURL_OPTION_KEY_VERSION);

		case HCURL_WHOLE:
			return u->whole || (u->ns && u->refname);
		case HCURL_HEXID:
			return u->hexid[0] != '\0' || u->refname != NULL;
	}

	g_assert_not_reached();
	return 0;
}

static GString *
_append_url(GString *gs, struct hc_url_s *u)
{
	if (!gs)
		return NULL;

	if (u->ns)
		g_string_append(gs, u->ns);

	if (hc_url_has(u, HCURL_REFERENCE)) {
		g_string_append(gs, "/");
		g_string_append(gs, hc_url_get(u, HCURL_REFERENCE));
	}
	else if (hc_url_has(u, HCURL_HEXID)) {
		g_string_append(gs, "/");
		g_string_append(gs, hc_url_get(u, HCURL_HEXID));
	}

	if (u->path) {
		g_string_append(gs, "/");
		g_string_append(gs, u->path);
	}

	return gs;
}

static GString *
_append_options(GString *gs, struct hc_url_s *u)
{
	if (!gs)
		return NULL;

	if (u->options && g_hash_table_size(u->options)) {
		gpointer k, v;
		GHashTableIter iter;
		int first = 1;
		g_hash_table_iter_init(&iter, u->options);
		while (g_hash_table_iter_next(&iter, &k, &v)) {
			g_string_append(gs, first ? "?" : "&");
			g_string_append(gs, (gchar*)k);
			g_string_append(gs, "=");
			g_string_append(gs, (gchar*)v);
		}
	}
	return gs;
}

const char*
hc_url_get(struct hc_url_s *u, enum hc_url_field_e f)
{
	if (!u)
		return NULL;

	switch (f) {
		case HCURL_NS:
			return u->ns;
		case HCURL_NSPHYS:
			return u->pns;
		case HCURL_NSVIRT:
			return u->vns;
		case HCURL_REFERENCE:
			return u->refname;
		case HCURL_PATH:
			return u->path;
		case HCURL_OPTIONS:
			return NULL;
		case HCURL_VERSION:
			return hc_url_get_option_value(u, HCURL_OPTION_KEY_VERSION);

		case HCURL_WHOLE:
			if (!u->whole) {
				if (!hc_url_has(u, HCURL_NS) || (
							!hc_url_has(u, HCURL_REFERENCE) &&
							!hc_url_has(u, HCURL_HEXID)))
					return NULL;
				GString *gs = _append_options(_append_url(g_string_new(""), u), u);
				if (gs)
					u->whole = g_string_free(gs, FALSE);
			}
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

	if (!u->hexid[0] && !_compute_id(u))
		return NULL;

	return u->id;
}

const GHashTable*
hc_url_get_options(struct hc_url_s *u)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}

	return u->options;
}

const gchar*
hc_url_get_option_value(struct hc_url_s *u, const gchar *option_name)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}

	if (u->options)
		return g_hash_table_lookup(u->options, option_name);
	return NULL;
}

size_t
hc_url_get_id_size(struct hc_url_s *u)
{
	return u ? sizeof(u->id) : 0;
}

void
hc_url_dump(struct hc_url_s *u)
{
	GRID_WARN("URL %p", u);
	if (!u)
		return;
	GRID_WARN(" +++++");
	GRID_WARN(" NS   [%s]", u->ns);
	GRID_WARN(" PNS  [%s]", u->pns);
	GRID_WARN(" VNS  [%s]", u->vns);
	GRID_WARN(" REF  [%s]", u->refname);
	GRID_WARN(" PATH [%s]", u->path);
	GRID_WARN(" OPTIONS:");
	_options_dump(u->options);
	GRID_WARN(" WHOLE[%s]", u->whole);
	GRID_WARN(" HEXID[%s]", u->hexid);
	GRID_WARN(" -----");
	GRID_WARN(" NS   [%s]", hc_url_get(u, HCURL_NS));
	GRID_WARN(" PNS  [%s]", hc_url_get(u, HCURL_NSPHYS));
	GRID_WARN(" VNS  [%s]", hc_url_get(u, HCURL_NSVIRT));
	GRID_WARN(" REF  [%s]", hc_url_get(u, HCURL_REFERENCE));
	GRID_WARN(" PATH [%s]", hc_url_get(u, HCURL_PATH));
	GRID_WARN(" WHOLE[%s]", hc_url_get(u, HCURL_WHOLE));
	GRID_WARN(" HEXID[%s]", hc_url_get(u, HCURL_HEXID));
	GRID_WARN(" =====");
}

