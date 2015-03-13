/*
OpenIO SDS proxy
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

enum {
	FLAG_NOEMPTY = 0x0001,
};

struct req_uri_s {
	const gchar *original;
	gchar *path;
	gchar *query;
	gchar *fragment;
	gchar **query_tokens;
};

struct req_args_s {
	struct req_uri_s *req_uri; // parsed URI
	struct path_matching_s **matchings; // matched handlers
	struct hc_url_s *url;

	struct http_request_s *rq;
	struct http_reply_ctx_s *rp;
	guint32 flags;
};

typedef enum http_rc_e (*req_handler_f) (struct req_args_s *);

//------------------------------------------------------------------------------

static void
_req_uri_extract_components (const gchar * str, struct req_uri_s *uri)
{
	gchar *pq = strchr (str, '?');
	gchar *pa = pq ? strchr (pq, '#') : strchr (str, '#');

	// Extract the main components
	uri->original = str;
	if (pq || pa)
		uri->path = g_strndup (uri->original, (pq ? pq : pa) - str);
	else
		uri->path = g_strdup (uri->original);

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

	// Split compound components of interest
	if (uri->query)
		uri->query_tokens = g_strsplit(uri->query, "&", -1);
	else
		uri->query_tokens = g_malloc0(sizeof(void*));
}

static void
_req_uri_free_components (struct req_uri_s *uri)
{
	metautils_str_clean (&uri->path);
	metautils_str_clean (&uri->query);
	metautils_str_clean (&uri->fragment);
	g_strfreev(uri->query_tokens);
}

static const gchar *
_req_get_option (struct req_args_s *args, const gchar *name)
{
	gsize namelen = strlen(name);
	gchar *needle = g_alloca(namelen+2);
	memcpy(needle, name, namelen);
	needle[namelen] = '=';
	needle[namelen+1] = 0;

	if (args->req_uri->query_tokens) {
		for (gchar **p=args->req_uri->query_tokens; *p ;++p) {
			if (g_str_has_prefix(*p, needle))
				return (*p) + namelen + 1;
		}
	}
	return NULL;
}

static const gchar *
_req_get_token (struct req_args_s *args, const gchar *name)
{
	return path_matching_get_variable (args->matchings[0], name);
}

