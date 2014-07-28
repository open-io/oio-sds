#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.url"
#endif

#include <errno.h>
#include <string.h>
#include <glib.h>

#include "./hc_url.h"
#include "./metautils.h"

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
	gchar *refname;
	gchar *path;
	GSList *options;
	/* secondary */
	gchar *pns;
	gchar *vns;
	gchar *whole;
	guint8 id[32];
	gchar hexid[65];
	guint8 flags;
};

/* ------------------------------------------------------------------------- */

#define GRID_PREFIX "grid://"
#define HC_PREFIX "hc://"
#define REDC_PREFIX "redc://"

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

	metautils_rstrip(url->ns, '/');
	metautils_rstrip(url->pns, '/');
	metautils_rstrip(url->vns, '/');
}

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
_add_option(struct hc_url_s *u, const gchar *option_str)
{
	gchar *k, *cursor;
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

static void
_parse_options(struct hc_url_s *u, const gchar *options)
{
	g_assert(u != NULL);
	_options_reset(u);
	if (!options || ! *options)
		return;
	gchar **strv = g_strsplit(options, "&", 0);
	if (NULL != strv) {
		for (gchar **p = strv; *p ;++p)
			_add_option(u, *p);
		g_strfreev(strv);
	}
}

static int
_parse_url(struct hc_url_s *url, const gchar *str)
{
	const gchar *ns, *refname, *path, *options;

	if(g_str_has_prefix(str, GRID_PREFIX))
		ns = str + sizeof(GRID_PREFIX) - 1;
	else if(g_str_has_prefix(str, HC_PREFIX))
		ns = str + sizeof(HC_PREFIX) - 1;
	else if(g_str_has_prefix(str, REDC_PREFIX))
		ns = str + sizeof(REDC_PREFIX) - 1;
	else
		ns = str;

	ns = metautils_lstrip(ns, '/');
	if (!*ns)
		return 0;

	refname = strchr(ns, '/');
	if (refname)
		refname = metautils_lstrip(refname+1, '/');

	path = refname ? strchr(refname, '/') : NULL;
	if (path) {
		if (!*(++path))
			path = NULL;
	}

	options = path ? strrchr(path, '?') : refname ? strrchr(refname, '?') : NULL;
	if (options) {
		if (!*(++options))
			options = NULL;
		_options_reset(url);
		_parse_options(url, options);
	}

	if (refname) {
		url->ns = g_strndup(ns, (refname-1)-ns);
		if (path) {
			url->refname = g_strndup(refname, (path-1)-refname);
			if (options)
				url->path = g_strndup(path, (options-1)-path);
			else
				url->path = g_strdup(path);
		} else if (options) {
			url->refname = g_strndup(refname, (options-1)-refname);
		} else {
			url->refname = g_strdup(refname);
		}
	}
	else {
		url->ns = g_strdup(ns);
	}

	_parse_ns(url);
	// XXX We want trailing slashes, they are used by S3FS !
	metautils_rstrip(url->refname, '/');
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
	if (!url)
		return NULL;
	struct hc_url_s *result = g_malloc0(sizeof(*result));
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
	if (u->whole)
		g_free(u->whole);

	_options_reset(u);
	memset(u, 0, sizeof(struct hc_url_s));
	g_free(u);
}

#define STRDUP(Dst,Src,Field) \
do { \
	if (Src->Field) \
		Dst->Field = g_strdup(Src->Field); \
} while (0)

struct hc_url_s *
hc_url_dup(struct hc_url_s *u)
{
	if (!u)
		return NULL;

	struct hc_url_s *result = g_memdup(u, sizeof(struct hc_url_s));
	STRDUP(result, u, ns);
	STRDUP(result, u, pns);
	STRDUP(result, u, vns);
	STRDUP(result, u, refname);
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

void
hc_url_gclean(gpointer u, gpointer ignored)
{
	(void) ignored;
	if (u)
		hc_url_clean(u);
}

struct hc_url_s*
hc_url_set(struct hc_url_s *u, enum hc_url_field_e f, const char *v)
{
	if (!u) {
		errno = EINVAL;
		return NULL;
	}

	switch (f) {
		case HCURL_NS:
			metautils_str_replace(&(u->ns), v);
			metautils_str_clean(&(u->pns));
			metautils_str_clean(&(u->vns));
			metautils_str_clean(&(u->whole));
			u->hexid[0] = 0;
			_parse_ns(u);
			return u;

		case HCURL_NSPHYS:
			metautils_str_clean(&(u->ns));
			metautils_str_replace(&(u->pns), v);
			u->ns = u->vns && u->pns
				? g_strconcat(u->pns, ".", u->vns, NULL)
				: g_strdup(u->pns);
			metautils_str_clean(&(u->whole));
			return u;

		case HCURL_NSVIRT:
			metautils_str_clean(&(u->ns));
			metautils_str_replace(&(u->vns), v);
			u->ns = u->vns && u->pns
				? g_strconcat(u->pns, ".", u->vns, NULL)
				: g_strdup(u->pns);
			metautils_str_clean(&(u->whole));
			u->hexid[0] = 0;
			return u;

		case HCURL_REFERENCE:
			metautils_str_replace(&(u->refname), v);
			metautils_str_clean(&(u->whole));
			u->hexid[0] = 0;
			return u;

		case HCURL_PATH:
			metautils_str_replace(&(u->path), v);
			metautils_str_clean(&(u->whole));
			return u;

		case HCURL_OPTIONS:
			_parse_options(u, v);
			return u;

		case HCURL_SNAPORVERS:
		case HCURL_VERSION:
			hc_url_set_option(u, HCURL_OPTION_KEY_VERSION, v);
			return u;

		case HCURL_SNAPSHOT:
			hc_url_set_option(u, HCURL_OPTION_KEY_SNAPSHOT, v);
			return u;

		case HCURL_WHOLE:
			metautils_str_clean(&(u->ns));
			metautils_str_clean(&(u->pns));
			metautils_str_clean(&(u->vns));
			metautils_str_clean(&(u->refname));
			metautils_str_clean(&(u->path));
			metautils_str_clean(&(u->whole));
			u->hexid[0] = 0;
			if (!_parse_url(u, v))
				return NULL;
			return u;

		case HCURL_HEXID:
			metautils_str_clean(&(u->refname));
			metautils_str_clean(&(u->whole));
			u->hexid[0] = 0;

			if (!metautils_str_ishexa(v,64)) {
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
			return NULL != _options_get(u, HCURL_OPTION_KEY_VERSION);
		case HCURL_SNAPSHOT:
			return NULL != _options_get(u, HCURL_OPTION_KEY_SNAPSHOT);

		case HCURL_WHOLE:
			return u->whole || (u->ns && u->refname);
		case HCURL_HEXID:
			return u->hexid[0] != '\0' || u->refname != NULL;
		case HCURL_SNAPORVERS:
			return hc_url_has(u, HCURL_SNAPSHOT) || hc_url_has(u, HCURL_VERSION);
	}

	g_assert_not_reached();
	return 0;
}

static GString *
_append_url(GString *gs, struct hc_url_s *u)
{
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
		case HCURL_SNAPSHOT:
			return hc_url_get_option_value(u, HCURL_OPTION_KEY_SNAPSHOT);

		case HCURL_WHOLE:
			if (!u->whole) {
				if (!hc_url_has(u, HCURL_NS) || (
							!hc_url_has(u, HCURL_REFERENCE) &&
							!hc_url_has(u, HCURL_HEXID)))
					return NULL;
				GString *gs = g_string_new("");
				gs = _append_url(gs, u);
				gs = _append_options(gs, u);
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

		case HCURL_SNAPORVERS:
			if (hc_url_has(u, HCURL_SNAPSHOT))
				return hc_url_get(u, HCURL_SNAPSHOT);
			else if (hc_url_has(u, HCURL_VERSION))
				return hc_url_get(u, HCURL_VERSION);
			else
				return NULL;
	}

	g_assert_not_reached();
	return NULL;
}

const guint8*
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

const gchar*
hc_url_get_option_value(struct hc_url_s *u, const gchar *k)
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
	g_assert(u != NULL);
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
hc_url_set_option (struct hc_url_s *u,  const gchar *k, const gchar *v)
{
	g_assert (u != NULL);
	g_assert (k != NULL);
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

