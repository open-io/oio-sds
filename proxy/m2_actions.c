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

#include <errno.h>

#include <metautils/lib/metautils.h>
#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/autogen.h>

#include "common.h"
#include "actions.h"

static void
_get_meta2_realtype (struct req_args_s *args, gchar *d, gsize dlen,
		const char *prefix)
{
	const char *type = oio_url_get (args->url, OIOURL_TYPE);
	if (type && *type) {
		g_snprintf(d, dlen, "%s%s.%s", prefix, NAME_SRVTYPE_META2, type);
	} else {
		g_snprintf(d, dlen, "%s%s", prefix, NAME_SRVTYPE_META2);
	}
}

static GError *
_resolve_meta2 (struct req_args_s *args,
		GError * (*hook) (struct meta1_service_url_s *, gboolean *))
{
	gchar realtype[64];
	_get_meta2_realtype (args, realtype, sizeof(realtype), "");
	return _resolve_service_and_do (realtype, 0, args->url, hook);
}

static void
_json_dump_all_beans (GString * gstr, GSList * beans)
{
	g_string_append_c (gstr, '{');
	meta2_json_dump_all_beans (gstr, beans);
	g_string_append_c (gstr, '}');
}

static enum http_rc_e
_reply_m2_error (struct req_args_s *args, GError * err)
{
	if (!err)
		return _reply_success_json (args, NULL);
	g_prefix_error (&err, "M2 error: ");
	if (err->code == CODE_CONTAINER_NOTEMPTY)
		return _reply_conflict_error (args, err);
	return _reply_common_error (args, err);
}

static void
_purify_header (gchar *k)
{
	for (gchar *p = k; *p ;++p) {
		if (*p != '-' && !g_ascii_isalnum(*p))
			*p = '-';
	}
}

static void
_container_single_prop_to_headers (struct req_args_s *args,
		const char *pk, gchar *v)
{
	if (!g_ascii_strcasecmp(pk, "sys.container_name")) {
		oio_str_reuse (&v, g_uri_escape_string (v, NULL, FALSE));
		args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-name", v);
	} else if (!g_ascii_strcasecmp(pk, "sys.container_size")) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-size", v);
	} else if (!g_ascii_strcasecmp(pk, "sys.m2vers")) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-seq", v);
	} else if (!g_ascii_strcasecmp(pk, "sys.namespace")) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-ns", v);
	} else if (g_str_has_prefix(pk, "sys.")) {
		gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-sys-%s",
				pk + sizeof("sys.") - 1);
		_purify_header(k);
		oio_str_reuse (&v, g_uri_escape_string (v, NULL, FALSE));
		args->rp->add_header(k, v);
		g_free(k);
	} else if (g_str_has_prefix(pk, "user.")) {
		gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-user-%s",
				pk + sizeof("user.") - 1);
		_purify_header(k);
		oio_str_reuse (&v, g_uri_escape_string (v, NULL, FALSE));
		args->rp->add_header(k, v);
		g_free(k);
	} else {
		gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-x-%s", pk);
		_purify_header(k);
		oio_str_reuse (&v, g_uri_escape_string (v, NULL, FALSE));
		args->rp->add_header(k, v);
		g_free(k);
	}
}

static void
_container_old_props_to_headers (struct req_args_s *args, GSList *props)
{
	for (GSList *l = props; l ;l=l->next) {
		const struct key_value_pair_s *kv = l->data;
		GByteArray *gv = kv->value;
		_container_single_prop_to_headers (args, kv->key, g_strndup(
					(gchar*)(gv->data), gv->len));
	}
}

static void
_container_new_props_to_headers (struct req_args_s *args, GTree *props)
{
	gboolean _run (gchar *k, gchar *v, gpointer i) {
		(void) i;
		_container_single_prop_to_headers (args, k, g_strdup(v));
		return FALSE;
	}
	g_tree_foreach (props, (GTraverseFunc)_run, NULL);
}

static gint
_sort_aliases_by_name (struct bean_ALIASES_s *a0, struct bean_ALIASES_s *a1)
{
	return g_strcmp0 (ALIASES_get_alias(a0)->str, ALIASES_get_alias(a1)->str);
}

static enum http_rc_e
_reply_aliases (struct req_args_s *args, GError * err, GSList * beans,
		gchar **prefixes)
{
	if (err)
		return _reply_m2_error (args, err);
	if (!beans && (args->flags & FLAG_NOEMPTY))
		return _reply_notfound_error (args, NEWERROR (CODE_CONTENT_NOTFOUND, "No bean found"));

	GSList *aliases = NULL, *headers = NULL;
	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES)
			aliases = g_slist_prepend (aliases, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			headers = g_slist_prepend (headers, l->data);
	}

	gboolean first;
	GString *gstr = g_string_new ("{");

	// Dump the prefixes
	if (prefixes) {
		g_string_append (gstr, "\"prefixes\":[");
		first = TRUE;
		for (gchar **pp=prefixes; *pp ;++pp) {
			if (!first)
				g_string_append_c(gstr, ',');
			first = FALSE;
			g_string_append_printf (gstr, "\"%s\"", *pp);
		}
		g_string_append (gstr, "],");
	}

	// And now the beans
	g_string_append (gstr, "\"objects\":[");
	first = TRUE;
	aliases = g_slist_sort (aliases, (GCompareFunc)_sort_aliases_by_name);
	for (GSList *la = aliases; la ; la=la->next) {

		if (!first)
			g_string_append_c(gstr, ',');
		first = FALSE;

		struct bean_ALIASES_s *a = la->data;
		// Look for the matching header
		// TODO optimize this with a tree or a hashmap
		struct bean_CONTENTS_HEADERS_s *h = NULL;
		for (GSList *lh=headers; lh ; lh=lh->next) {
			if (0 == metautils_gba_cmp(CONTENTS_HEADERS_get_id(lh->data), ALIASES_get_content(a))) {
				h = lh->data;
				break;
			}
		}

		g_string_append_printf(gstr,
				"{\"name\":\"%s\""
				",\"ver\":%"G_GINT64_FORMAT
				",\"ctime\":%"G_GINT64_FORMAT
				",\"mtime\":%"G_GINT64_FORMAT
				",\"deleted\":%s"
				",\"content\":\"",
				ALIASES_get_alias(a)->str,
				ALIASES_get_version(a),
				ALIASES_get_ctime(a),
				ALIASES_get_mtime(a),
				ALIASES_get_deleted(a) ? "true" : "false");

		metautils_gba_to_hexgstr(gstr, ALIASES_get_content(a));
		g_string_append_c (gstr, '"');

		if (h) {
			g_string_append_c (gstr, ',');
			GString *pol = CONTENTS_HEADERS_get_policy(h);
			GByteArray *hh = CONTENTS_HEADERS_get_hash(h);

			if (pol)
				g_string_append_printf(gstr, "\"policy\":\"%s\",\"hash\":", pol->str);
			else
				g_string_append_printf(gstr, "\"policy\":null,\"hash\":");
			if (hh) {
				g_string_append_c (gstr, '"');
				metautils_gba_to_hexgstr(gstr, hh);
				g_string_append_c (gstr, '"');
			} else {
				g_string_append(gstr, "null");
			}

			g_string_append_printf(gstr, ",\"size\":%"G_GINT64_FORMAT,
					CONTENTS_HEADERS_get_size(h));
			g_string_append_printf(gstr, ",\"mime-type\":\"%s\"",
					CONTENTS_HEADERS_get_mime_type(h)->str);
		}
		g_string_append_c(gstr, '}');
	}
	g_string_append (gstr, "]}");
	_bean_cleanl2 (beans);

	g_slist_free (aliases);
	g_slist_free (headers);
	return _reply_success_json (args, gstr);
}

static enum http_rc_e
_reply_beans (struct req_args_s *args, GError * err, GSList * beans)
{
	if (!err && !beans && (args->flags & FLAG_NOEMPTY))
		err = NEWERROR (CODE_CONTENT_NOTFOUND, "No bean found");
	if (err)
		return _reply_m2_error (args, err);

	GString *gstr = g_string_new ("");
	_json_dump_all_beans (gstr, beans);
	_bean_cleanl2 (beans);
	return _reply_success_json (args, gstr);
}

static void
_populate_headers_with_header (struct req_args_s *args,
		struct bean_CONTENTS_HEADERS_s *header)
{
	if (!header)
		return;

	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-length",
			g_strdup_printf("%"G_GINT64_FORMAT, CONTENTS_HEADERS_get_size(header)));

	if (CONTENTS_HEADERS_get_policy (header)) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-policy",
				g_strdup(CONTENTS_HEADERS_get_policy(header)->str));
	}

	if (CONTENTS_HEADERS_get_hash(header)) {
		args->rp->add_header_gstr(PROXYD_HEADER_PREFIX "content-meta-hash",
				metautils_gba_to_hexgstr(NULL, CONTENTS_HEADERS_get_hash(header)));
	}

	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-hash-method",
			g_strdup("md5"));
	args->rp->add_header (PROXYD_HEADER_PREFIX "content-meta-mime-type",
			g_strdup(CONTENTS_HEADERS_get_mime_type(header)->str));
	args->rp->add_header (PROXYD_HEADER_PREFIX "content-meta-chunk-method",
			g_strdup(CONTENTS_HEADERS_get_chunk_method(header)->str));

	GByteArray *gb = CONTENTS_HEADERS_get_id (header);
	gchar hexid[1+2*gb->len];
	oio_str_bin2hex (gb->data, gb->len, hexid, 1+2*gb->len);
	args->rp->add_header (PROXYD_HEADER_PREFIX "content-meta-id",
			g_strdup_printf ("%s", hexid));
}

static void
_populate_headers_with_alias (struct req_args_s *args, struct bean_ALIASES_s *alias)
{
	if (!alias)
		return;

	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-name",
			g_uri_escape_string(ALIASES_get_alias(alias)->str, NULL, FALSE));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-version",
			g_strdup_printf("%"G_GINT64_FORMAT, ALIASES_get_version(alias)));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-deleted",
			g_strdup(ALIASES_get_deleted(alias) ? "True" : "False"));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-ctime",
			g_strdup_printf("%"G_GINT64_FORMAT, ALIASES_get_ctime(alias)));
}

static enum http_rc_e
_reply_simplified_beans (struct req_args_s *args, GError *err,
		GSList *beans, gboolean body)
{
	if (err)
		return _reply_m2_error(args, err);

	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	gboolean first = TRUE;
	GString *gstr = body ? g_string_new ("[") : NULL;

	beans = g_slist_sort(beans, _bean_compare_kind);

	for (GSList *l0=beans; l0 ;l0=l0->next) {
		if (!l0->data)
			continue;
		if (&descr_struct_ALIASES == DESCR(l0->data)) {
			alias = l0->data;
			if (ALIASES_get_deleted(alias) && !metautils_cfg_get_bool(OPT("deleted"),FALSE)) {
				if (gstr)
					g_string_free (gstr, TRUE);
				_bean_cleanl2(beans);
				return _reply_notfound_error(args, NEWERROR(CODE_CONTENT_DELETED, "Alias deleted"));
			}
			continue;
		}
		if (&descr_struct_CONTENTS_HEADERS == DESCR(l0->data)) {
			header = l0->data;
			continue;
		}
		if (&descr_struct_PROPERTIES == DESCR(l0->data)) {
			struct bean_PROPERTIES_s *prop = l0->data;
			gchar *k = g_strdup_printf (PROXYD_HEADER_PREFIX "content-meta-x-%s",
					PROPERTIES_get_key(prop)->str);
			GByteArray *v = PROPERTIES_get_value (prop);
			args->rp->add_header(k, g_strndup ((gchar*)v->data, v->len));
			g_free (k);
			continue;
		}
		if (&descr_struct_CHUNKS != DESCR(l0->data))
			continue;

		if (gstr) {
			if (!first)
				g_string_append (gstr, ",\n");
			first = FALSE;

			// Serialize the chunk
			struct bean_CHUNKS_s *chunk = l0->data;
			g_string_append_printf (gstr, "{\"url\":\"%s\"", CHUNKS_get_id (chunk)->str);
			g_string_append_printf (gstr, ",\"pos\":\"%s\"", CHUNKS_get_position (chunk)->str);
			g_string_append_printf (gstr, ",\"size\":%"G_GINT64_FORMAT, CHUNKS_get_size (chunk));
			g_string_append (gstr, ",\"hash\":\"");
			metautils_gba_to_hexgstr (gstr, CHUNKS_get_hash (chunk));
			g_string_append (gstr, "\"}");
		}
	}
	if (body)
		g_string_append_c (gstr, ']');

	// Not set all the header
	_populate_headers_with_header (args, header);
	_populate_headers_with_alias (args, alias);

	_bean_cleanl2 (beans);
	if (!body && gstr) {
		g_string_free (gstr, TRUE);
		gstr = NULL;
	}

	return _reply_success_json (args, gstr);
}

static GError *
_get_hash (const char *s, GByteArray **out)
{
	*out = NULL;
	GByteArray *h = metautils_gba_from_hexstring (s);
	if (!h)
		return BADREQ("JSON: invalid hash: not hexa");

	const gssize len = h->len;
	if (len != g_checksum_type_get_length(G_CHECKSUM_MD5)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA256)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA512)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA1)) {
		g_byte_array_free (h, TRUE);
		return BADREQ("JSON: invalid hash: invalid length");
	}

	*out = h;
	return NULL;
}

static GError *
_load_simplified_chunks (struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;

	if (!json_object_is_type(jbody, json_type_array))
		return BADREQ ("JSON: Not an array");

	gint64 now = oio_ext_real_time () / G_TIME_SPAN_SECOND;

	// Load the beans
	for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
		struct json_object *jurl=NULL, *jpos=NULL, *jsize=NULL, *jhash=NULL;
		struct oio_ext_json_mapping_s m[] = {
			{"url",  &jurl,  json_type_string, 1},
			{"pos",  &jpos,  json_type_string, 1},
			{"size", &jsize, json_type_int,    1},
			{"hash", &jhash, json_type_string, 1},
			{NULL, NULL, 0, 0}
		};
		GRID_TRACE("JSON: parsing chunk at %i", i-1);
		err = oio_ext_extract_json (json_object_array_get_idx (jbody, i-1), m);
		if (err) break;

		GByteArray *h = NULL;
		if (!(err = _get_hash (json_object_get_string(jhash), &h))) {
			struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
			CHUNKS_set2_id (chunk, json_object_get_string(jurl));
			CHUNKS_set_hash (chunk, h);
			CHUNKS_set_size (chunk, json_object_get_int64(jsize));
			CHUNKS_set_ctime (chunk, now);
			CHUNKS_set2_position (chunk, json_object_get_string(jpos));
			CHUNKS_set2_content (chunk, (guint8*)"0", 1);
			beans = g_slist_prepend(beans, chunk);
		}
		metautils_gba_clean (h);
	}

	if (err)
		_bean_cleanl2 (beans);
	else
		*out = beans;

	return err;
}

static GError *
_load_simplified_content (struct req_args_s *args, struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;

	if (!json_object_is_type(jbody, json_type_array))
		return BADREQ ("JSON: Not an array");
	if (json_object_array_length(jbody) <= 0)
		return BADREQ ("JSON: Empty array");

	err = _load_simplified_chunks (jbody, &beans);

	struct bean_CONTENTS_HEADERS_s *header = NULL;

	if (!err) {
		header = _bean_create (&descr_struct_CONTENTS_HEADERS);
		beans = g_slist_prepend (beans, header);
		CONTENTS_HEADERS_set2_id (header, (guint8*)"0", 1);

		gchar *s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-policy");
		if (NULL != s)
			CONTENTS_HEADERS_set2_policy (header, s);
	}

	if (!err) { // Content ID
		gchar *s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-id");
		if (NULL != s) {
			GByteArray *h = metautils_gba_from_hexstring (s);
			if (!h)
				err = BADREQ("Invalid content ID (not hexa)");
			else {
				oio_url_set (args->url, OIOURL_CONTENTID, s);
				CONTENTS_HEADERS_set_id (header, h);
				/* XXX JFS: this is clean to have uniform CONTENT ID among all
				 * the beans, but it is a bit useless since this requires more
				 * bytes on the network and can be done in the META2 server */
				for (GSList *l=beans; l ;l=l->next) {
					if (DESCR(l->data) != &descr_struct_CHUNKS)
						continue;
					CHUNKS_set_content(l->data, h);
				}
				g_byte_array_free(h, TRUE);
			}
		}
	}

	if (!err) { // Content hash
		gchar *s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-hash");
		if (NULL != s) {
			GByteArray *h = NULL;
			if (!(err = _get_hash (s, &h)))
				CONTENTS_HEADERS_set_hash (header, h);
			if (h) g_byte_array_free(h, TRUE);
		}
	}

	if (!err) { // Content length
		gchar *s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-length");
		if (!s)
			err = BADREQ("Header: missing content length");
		else {
			errno = 0;
			gchar *end = NULL;
			gint64 s64 = g_ascii_strtoll(s, &end, 10);
			if (s64 < 0)
				err = BADREQ("Header: negative content length");
			else if (s64 == G_MAXINT64)
				err = BADREQ("Header: content length overflow");
			else if (s64 == 0 && end == s)
				err = BADREQ("Header: invalid content length (parsing failed)");
			else if (*end != 0)
				err = BADREQ("Header: invalid content length (trailing characters)");
			else
				CONTENTS_HEADERS_set_size (header, s64);
		}
	}

	if (!err) {
		// Extract the content-type
		gchar *s;
		s = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-mime-type");
		if (s)
			CONTENTS_HEADERS_set2_mime_type (header, s);

		// Extract the chunking method
		s = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-chunk-method");
		if (s)
			CONTENTS_HEADERS_set2_chunk_method (header, s);
	}

	if (!err) {
		struct bean_ALIASES_s *alias = _bean_create (&descr_struct_ALIASES);
		beans = g_slist_prepend (beans, alias);
		ALIASES_set2_alias (alias, PATH());
		ALIASES_set_content (alias, CONTENTS_HEADERS_get_id (header));

		if (!err) { // aliases version
			gchar *s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-version");
			if (s) {
				errno = 0;
				gchar *end = NULL;
				gint64 s64 = g_ascii_strtoll(s, &end, 10);
				if (s64 < 0)
					err = BADREQ("Header: negative content version");
				else if (s64 == G_MAXINT64)
					err = BADREQ("Header: content version overflow");
				else if (s64 == 0 && end == s)
					err = BADREQ("Header: invalid content version (parsing failed)");
				else if (*end != 0)
					err = BADREQ("Header: invalid content version (trailing characters)");
				else
					ALIASES_set_version (alias, s64);
			}
		}

		gboolean run_headers (gpointer k, gpointer v, gpointer u) {
			(void)u;
			if (!metautils_str_has_caseprefix ((gchar*)k, PROXYD_HEADER_PREFIX "content-meta-x-"))
				return FALSE;
			const gchar *rk = ((gchar*)k) + sizeof(PROXYD_HEADER_PREFIX "content-meta-x-") - 1;
			struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
			PROPERTIES_set_alias (prop, ALIASES_get_alias(alias));
			PROPERTIES_set_version (prop, 0); // still unknown
			PROPERTIES_set2_key (prop, rk);
			PROPERTIES_set2_value (prop, (guint8*)v, strlen((gchar*)v));
			beans = g_slist_prepend (beans, prop);
			return FALSE;
		}
		g_tree_foreach (args->rq->tree_headers, run_headers, NULL);
	}

	if (err)
		_bean_cleanl2 (beans);
	else
		*out = beans;

	return err;
}

static gchar **
_container_headers_to_props (struct req_args_s *args)
{
	GPtrArray *tmp;
	gboolean run_headers (char *k, char *v, gpointer u) {
		(void)u;
		if (!metautils_str_has_caseprefix (k, PROXYD_HEADER_PREFIX "container-meta-"))
			return FALSE;
		k += sizeof(PROXYD_HEADER_PREFIX "container-meta-") - 1;
		if (g_str_has_prefix (k, "user-")) {
			k += sizeof("user-") - 1;
			g_ptr_array_add (tmp, g_strconcat ("user.", k, NULL));
			g_ptr_array_add (tmp, g_strdup (v));
		} else if (g_str_has_prefix (k, "sys-")) {
			k += sizeof("sys-") - 1;
			g_ptr_array_add (tmp, g_strconcat ("sys.", k, NULL));
			g_ptr_array_add (tmp, g_strdup (v));
		}
        /* no management here for properties with raw format. there are
         * other requests handlers for that kind of ugly tweaks. */
		return FALSE;
	}
	tmp = g_ptr_array_new ();
	g_tree_foreach (args->rq->tree_headers, (GTraverseFunc)run_headers, NULL);
	return (gchar**) metautils_gpa_to_array (tmp, TRUE);
}

static enum http_rc_e
_reply_properties (struct req_args_s *args, GError * err, GSList * beans)
{
	if (err) {
		if (CODE_IS_NOTFOUND(err->code))
			return _reply_notfound_error (args, err);
		return _reply_system_error (args, err);
	}

	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES)
			_populate_headers_with_alias (args, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			_populate_headers_with_header (args, l->data);
	}

	gboolean first = TRUE;
	GString *gs = g_string_new("{");
	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) != &descr_struct_PROPERTIES)
			continue;
		if (!first)
			g_string_append_c(gs, ',');
		first = FALSE;
		struct bean_PROPERTIES_s *bean = l->data;
		g_string_append_printf(gs, "\"%s\":\"%.*s\"",
				PROPERTIES_get_key(bean)->str,
				PROPERTIES_get_value(bean)->len, PROPERTIES_get_value(bean)->data);
	}
	g_string_append_c(gs, '}');

	_bean_cleanl2 (beans);
	return _reply_success_json (args, gs);
}

/* CONTAINER resources ------------------------------------------------------ */

static char
_delimiter (struct req_args_s *args)
{
	const char *s = OPT("delimiter");
	return s ? *s : 0;
}

static GError *
_max (struct req_args_s *args, gint64 *pmax)
{
	*pmax = 0;
	const char *s = OPT("max");
	if (!s)
		return NULL;
	if (!*s)
		return BADREQ("Invalid max number of items: %s", "empty");

	gchar *end = NULL;
	*pmax = g_ascii_strtoll(s, &end, 10);
	if (!*pmax && errno == EINVAL)
		return BADREQ("Invalid max number of items: %s", "not an integer");
	if (*pmax <= 0)
		return BADREQ("Invalid max number of items: %s", "too small");
	if (*pmax == G_MAXINT64 || *pmax == G_MININT64)
		return BADREQ("Invalid max number of items: %s", "overflow");
	if (end && *end)
		return BADREQ("Invalid max number of items: %s", "trailing characters");
	return NULL;
}

struct filter_ctx_s
{
	GSList *beans;
	GTree *prefixes;
	guint count; // aliases in <beans>
	const char *prefix;
	char delimiter;
};

static void
_filter (struct filter_ctx_s *ctx, GSList *l)
{
	void forget (GSList *p) { if (p->data) _bean_clean (p->data); g_slist_free1 (p); }
	void prepend (GSList *p) { p->next = ctx->beans; ctx->beans = p; }

	gsize prefix_len = ctx->prefix ? strlen(ctx->prefix) : 0;
	for (GSList *tmp; l ;l=tmp) {
		tmp = l->next;
		l->next = NULL;

		if (!l->data) {
			forget (l);
			continue;
		}
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			prepend (l);
			continue;
		}
		if (DESCR(l->data) != &descr_struct_ALIASES) {
			forget (l);
			continue;
		}

		const char *name = ALIASES_get_alias(l->data)->str;
		if (ctx->delimiter) {
			const char *p = strchr(name+prefix_len, ctx->delimiter);
			if (p) {
				g_tree_insert(ctx->prefixes, g_strndup(name, (p-name)+1), GINT_TO_POINTER(1));
				forget (l);
			} else {
				ctx->count ++;
				prepend (l);
			}
		} else {
			ctx->count ++;
			prepend (l);
		}
	}
}

static GError *
_m2_container_create (struct req_args_s *args)
{
	gboolean autocreate = _request_has_flag (args,
			PROXYD_HEADER_MODE, "autocreate");
	gchar **properties = _container_headers_to_props (args);

	GError *hook_m2 (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		struct m2v2_create_params_s param = {
			OPT("stgpol"), OPT("verpol"), properties, FALSE
		};
		return m2v2_remote_execute_CREATE (m2->host, args->url, &param);
	}

	GError *err;
retry:
	GRID_TRACE("Container creation %s", oio_url_get (args->url, OIOURL_WHOLE));
	err = _resolve_meta2 (args, hook_m2);
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					err->code, err->message);
			autocreate = FALSE; /* autocreate just once */
			g_clear_error (&err);
			GError *hook_dir (const gchar *m1) {
				gchar **urlv = NULL;
				gchar realtype[64];
				_get_meta2_realtype (args, realtype, sizeof(realtype), "");
				GError *e = meta1v2_remote_link_service (m1, args->url,
						realtype, FALSE, TRUE, &urlv);
				if (!e && urlv && *urlv) {
					/* Explicitely feeding the meta1 avoids a subsequent
					   call to meta1 to locate the meta2 */
					hc_resolver_tell (resolver, args->url, realtype,
							(const char * const *) urlv);
				}
				if (urlv) g_strfreev (urlv);
				return e;
			}
			err = _m1_locate_and_action (args->url, hook_dir);
			if (!err)
				goto retry;
		}
	}

	g_strfreev (properties);
	return err;
}

static enum http_rc_e
action_m2_container_destroy (struct req_args_s *args)
{
	GError *err = NULL;
	struct sqlx_name_mutable_s n = {NULL,NULL,NULL};
	/* TODO(jfs): manage container subtype */
	sqlx_name_fill (&n, args->url, NAME_SRVTYPE_META2, 1);

	/* 1. FREEZE the base to avoid writings during the operation */
	if (!err) {
		GByteArray* _pack_freeze () {
			return sqlx_pack_FREEZE (sqlx_name_mutable_to_const(&n));
		}
		GError * _freeze (struct meta1_service_url_s *m2, gboolean *next) {
			(void) next;
			GError *e = _gba_request (m2, _pack_freeze, NULL);
			if (!e)
				e = m2v2_remote_execute_FLUSH (m2->host, args->url,
					M2V2_CLIENT_TIMEOUT_HUGE);
			return e;
		}
		err = _resolve_meta2 (args, _freeze);
	}

	/* 2. FLUSH the base on the MASTER, so events are generated for all the
	   contents removed. */
	if (!err) {
		GError * _flush (struct meta1_service_url_s *m2, gboolean *next) {
			(void) next;
			return m2v2_remote_execute_FLUSH (m2->host, args->url,
					M2V2_CLIENT_TIMEOUT_HUGE);
		}
		err = _resolve_meta2 (args, _flush);
	}

	gchar **urlv = NULL;
	err = hc_resolve_reference_service (resolver, args->url, n.type, &urlv);

	/* 3. UNLINK the base in the directory */
	if (!err) {
		GError * _unlink (const char * m1) {
			return meta1v2_remote_unlink_service (m1, args->url, n.type);
		}
		err = _m1_locate_and_action (args->url, _unlink);
	}

	hc_decache_reference_service (resolver, args->url, n.type);

	/* 4. DESTROY each local base */
	if (!err && urlv && *urlv) {
		meta1_urlv_shift_addr(urlv);
		err = m2v2_remote_execute_DESTROY_many(urlv, args->url, M2V2_DESTROY_LOCAL);
	}

	if (urlv) g_strfreev (urlv);
	sqlx_name_clean (&n);
	if (NULL != err)
		return _reply_m2_error(args, err);
	return _reply_nocontent (args);
}

/* CONTAINER action resources ----------------------------------------------- */

static enum http_rc_e
action_m2_container_purge (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_PURGE (m2->host, args->url,
				M2V2_CLIENT_TIMEOUT_HUGE);
	}
	GError *err = _resolve_meta2 (args, hook);
	return _reply_beans (args, err, beans);
}

static enum http_rc_e
action_m2_container_flush (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_FLUSH (m2->host, args->url,
				M2V2_CLIENT_TIMEOUT_HUGE);
	}
	GError *err = _resolve_meta2 (args, hook);
	return _reply_beans (args, err, beans);
}

static enum http_rc_e
action_m2_container_dedup (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	GError *err;
	gboolean first = TRUE;
	GString *gstr = g_string_new ("{\"msg\":[");
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		gchar *msg = NULL;
		GError *e = m2v2_remote_execute_DEDUP (m2->host, args->url,
				M2V2_CLIENT_TIMEOUT_HUGE);
		if (msg) {
			if (!first)
				g_string_append_c (gstr, ',');
			first = FALSE;
			g_string_append_c (gstr, '"');
			g_string_append (gstr, msg);	// TODO escape this!
			g_string_append_c (gstr, '"');
			g_free (msg);
		}
		return e;
	}
	err = _resolve_meta2 (args, hook);
	if (NULL != err) {
		g_string_free (gstr, TRUE);
		g_prefix_error (&err, "M2 error: ");
		return _reply_common_error (args, err);
	}

	g_string_append (gstr, "]}");
	return _reply_success_json (args, gstr);
}

static enum http_rc_e
action_m2_container_touch (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_touch_container_ex (m2->host, args->url, 0);
	}
	GError *err = _resolve_meta2 (args, hook);
	if (NULL != err) {
		if (CODE_IS_NOTFOUND(err->code))
			return _reply_forbidden_error (args, err);
		return _reply_m2_error (args, err);
	}

	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_raw_insert (struct req_args_s *args, struct json_object *jargs)
{
	GSList *beans = NULL;
	GError *err = m2v2_json_load_setof_xbean (jargs, &beans);
	if (err)
		return _reply_format_error (args, err);
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	GError * hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_RAW_ADD (m2->host, args->url, beans);
	}
	err = _resolve_meta2 (args, hook);
	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_raw_delete (struct req_args_s *args, struct json_object *jargs)
{
	GSList *beans = NULL;
	GError *err = m2v2_json_load_setof_xbean (jargs, &beans);
	if (err)
		return _reply_format_error (args, err);
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	GError * hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_RAW_DEL (m2->host, args->url, beans);
	}
	err = _resolve_meta2 (args, hook);
	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_raw_update (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type (jargs, json_type_object))
		return _reply_format_error (args, BADREQ("JSON object expected"));

	GError *err = NULL;
	GSList *beans_old = NULL, *beans_new = NULL;
	struct json_object *jold = NULL, *jnew = NULL;

	if (!err && !json_object_object_get_ex (jargs, "old", &jold))
		err = BADREQ("No 'old' set of beans");
	if (!err && !json_object_object_get_ex (jargs, "new", &jnew))
		err = BADREQ("No 'new' set of beans");
	if (!err)
		err = m2v2_json_load_setof_xbean (jold, &beans_old);
	if (!err)
		err = m2v2_json_load_setof_xbean (jnew, &beans_new);
	if (!err && !beans_old)
		err = BADREQ("No bean to update");
	if (!err && (g_slist_length(beans_new) != g_slist_length(beans_old)))
		err = BADREQ("Length mismatch for bean sets");

	GError * hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_RAW_SUBST (m2->host, args->url, beans_new, beans_old);
	}
	if (!err)
		err = _resolve_meta2 (args, hook);
	_bean_cleanl2 (beans_old);
	_bean_cleanl2 (beans_new);

	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

/* XXX JFS: You talk to a meta2 with its subtype, because it is a "high level"
 * interaction with the DB, while sqlx access are quiet raw and "low level"
 * DB calls. So that they do not consider the same kind of type. SQLX want to
 * a fully qualified type, not just the subtype. */
static void
_add_meta2_type (struct req_args_s *args)
{
	gchar realtype[64];
	_get_meta2_realtype (args, realtype, sizeof(realtype), "type=");
	OIO_STRV_APPEND_COPY (args->req_uri->query_tokens, realtype);
	OIO_STRV_APPEND_COPY (args->req_uri->query_tokens, "seq=1");
}

static enum http_rc_e
action_m2_container_propget (struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type (args);
	return action_sqlx_propget(args, jargs);
}

static enum http_rc_e
action_m2_container_propset (struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type (args);
	return action_sqlx_propset(args, jargs);
}

static enum http_rc_e
action_m2_container_propdel (struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type (args);
	return action_sqlx_propdel(args, jargs);
}

enum http_rc_e
action_m2_container_stgpol (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_string))
		return _reply_format_error (args, BADREQ ("Storage policy must be a string"));

	struct json_object *fake_jargs = json_object_new_object();
	json_object_object_add (fake_jargs, M2V2_ADMIN_STORAGE_POLICY, jargs);

	enum http_rc_e rc = action_m2_container_propset (args, fake_jargs);
	json_object_put (fake_jargs);
	return rc;
}

enum http_rc_e
action_m2_container_setvers (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_int))
		return _reply_format_error (args, BADREQ ("Versioning policy must be an integer"));

	struct json_object *fake_jargs = json_object_new_object();
	json_object_object_add (fake_jargs, M2V2_ADMIN_STORAGE_POLICY, jargs);

	enum http_rc_e rc = action_m2_container_propset (args, fake_jargs);
	json_object_put (fake_jargs);
	return rc;
}

enum http_rc_e
action_container_create (struct req_args_s *args)
{
	GError *err = _m2_container_create (args);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	if (err && err->code == CODE_CONTAINER_EXISTS) {
		g_clear_error (&err);
		return _reply_created(args);
	}
	return _reply_m2_error (args, err);
}

enum http_rc_e
action_container_destroy (struct req_args_s *args)
{
   return action_m2_container_destroy (args);
}

enum http_rc_e
action_container_list (struct req_args_s *args)
{
	struct list_result_s list_out = {0};
	struct list_params_s list_in = {0};
	GError *err = NULL;
	guint count = 0;
	char delimiter = 0;
	GTree *tree_prefixes = NULL;
	GTree *tree_properties = NULL;

	/* Triggers special listings */
	const char *chunk_id = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "list-chunk-id");
	const char *content_hash_hex = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "list-content-hash");
	GBytes *content_hash = NULL;
	if (content_hash_hex) {
		GByteArray *gba = NULL;
		if (NULL != (err = _get_hash (content_hash_hex, &gba)))
			return _reply_format_error (args, BADREQ("Invalid content hash"));
		content_hash = g_byte_array_free_to_bytes (gba);
	}

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		GError *e = NULL;
		struct list_params_s in = list_in;
		struct list_result_s out = {NULL,NULL,FALSE};
		while (grid_main_is_running()) {

			// patch the input parameters
			if (list_in.maxkeys > 0)
				in.maxkeys = list_in.maxkeys - (count + g_tree_nnodes(tree_prefixes));
			if (list_out.next_marker)
				in.marker_start = list_out.next_marker;

			// Action
			gchar **props = NULL;
			if (chunk_id)
				e = m2v2_remote_execute_LIST_BY_CHUNKID (m2->host, args->url, chunk_id, &in, &out);
			else if (content_hash)
				e = m2v2_remote_execute_LIST_BY_HEADERHASH (m2->host, args->url, content_hash, &in, &out);
			else
				e = m2v2_remote_execute_LIST (m2->host, args->url, &in, &out, &props);

			// Manage the output
			if (NULL != e)
				return e;
			if (props && tree_properties) {
				for (gchar **p=props; *p && *(p+1) ;p+=2)
					g_tree_replace (tree_properties, g_strdup(*p), g_strdup(*(p+1)));
			}
			if (props) g_strfreev (props);
			props = NULL;

			// transmit the output
			oio_str_reuse (&list_out.next_marker, out.next_marker);
			out.next_marker = NULL;
			if (out.beans) {
				struct filter_ctx_s ctx;
				ctx.beans = list_out.beans;
				ctx.prefixes = tree_prefixes;
				ctx.count = count;
				ctx.prefix = list_in.prefix;
				ctx.delimiter = delimiter;
				_filter (&ctx, out.beans);
				out.beans = NULL;
				count = ctx.count;
				list_out.beans = ctx.beans;
			}

			// enough elements received
			if (list_in.maxkeys > 0 && list_in.maxkeys <= (count + g_tree_nnodes(tree_prefixes))) {
				list_out.truncated = out.truncated;
				return NULL;
			}
			// no more elements expected, the meta2 told us
			if (!out.truncated) {
				list_out.truncated = FALSE;
				return NULL;
			}
			if (out.truncated && !list_out.next_marker) {
				GRID_ERROR("BUG : meta2 must return a ");
				return NEWERROR(CODE_PLATFORM_ERROR, "BUG in meta2 : list truncated but no marker returned");
			}
		}

		return e;
	}

	list_in.flag_headers = ~0;
	list_in.flag_nodeleted = ~0;
	list_in.prefix = OPT("prefix");
	list_in.marker_start = OPT("marker");
	list_in.marker_end = OPT("marker_end");
	delimiter = _delimiter (args);
	if (OPT("deleted"))
		list_in.flag_nodeleted = 0;
	if (OPT("all"))
		list_in.flag_allversion = ~0;
	if (!err)
		err = _max (args, &list_in.maxkeys);
	if (!err) {
		tree_properties = g_tree_new_full (metautils_strcmp3, NULL, g_free, g_free);
		tree_prefixes = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
	}

	GRID_DEBUG("Listing [%s] max=%"G_GINT64_FORMAT" delim=%c prefix=%s marker=%s end=%s",
			oio_url_get(args->url, OIOURL_WHOLE), list_in.maxkeys, delimiter,
			list_in.prefix, list_in.marker_start, list_in.marker_end);

	if (!err)
		err = _resolve_meta2 (args, hook);
	if (!err) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "list-truncated",
				g_strdup(list_out.truncated ? "true" : "false"));
		if (list_out.next_marker) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "list-marker",
					g_uri_escape_string(list_out.next_marker, NULL, FALSE));
		}
	}

	gchar **keys_prefixes = NULL;
	if (!err)
		keys_prefixes = gtree_string_keys (tree_prefixes);
	if (!err)
		_container_new_props_to_headers (args, tree_properties);
	enum http_rc_e rc = _reply_aliases (args, err, list_out.beans, keys_prefixes);
	if (keys_prefixes) g_free (keys_prefixes);
	if (tree_prefixes) g_tree_destroy (tree_prefixes);
	if (tree_properties) g_tree_destroy (tree_properties);
	if (content_hash) g_bytes_unref (content_hash);
	oio_str_clean (&list_out.next_marker);
	return rc;
}

enum http_rc_e
action_container_show (struct req_args_s *args)
{
	GError *err = NULL;
	GByteArray **bodies = NULL;

	struct sqlx_name_mutable_s n = {NULL,NULL,NULL};
	sqlx_name_fill (&n, args->url, NAME_SRVTYPE_META2, 1);
	GByteArray* packer () {
		return sqlx_pack_PROPGET (sqlx_name_mutable_to_const(&n));
	}
	err = _gbav_request (n.type, 0, args->url, packer, NULL, &bodies);
	sqlx_name_clean(&n);

	if (err) {
		metautils_gba_cleanv (bodies);
		return _reply_m2_error (args, err);
	}

	GSList *pairs = NULL;
	err = metautils_unpack_bodyv (bodies, &pairs, key_value_pairs_unmarshall);
	metautils_gba_cleanv (bodies);
	if (err) {
		g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
		return _reply_system_error(args, err);
	}

	_container_old_props_to_headers (args, pairs);
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return _reply_success_json (args, NULL);
}

enum http_rc_e
action_container_touch (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_touch);
}

enum http_rc_e
action_container_dedup (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_dedup);
}

enum http_rc_e
action_container_purge (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_purge);
}

enum http_rc_e
action_container_flush (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_flush);
}

enum http_rc_e
action_container_prop_get (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_propget);
}

enum http_rc_e
action_container_prop_set (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_propset);
}

enum http_rc_e
action_container_prop_del (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_propdel);
}

enum http_rc_e
action_container_raw_insert (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_raw_insert);
}

enum http_rc_e
action_container_raw_update (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_raw_update);
}

enum http_rc_e
action_container_raw_delete (struct req_args_s *args)
{
    return rest_action (args, action_m2_container_raw_delete);
}


/* CONTENT action resource -------------------------------------------------- */


static enum http_rc_e
action_m2_content_beans (struct req_args_s *args, struct json_object *jargs)
{
	struct json_object *jsize = NULL, *jpol = NULL;
	json_object_object_get_ex(jargs, "size", &jsize);
	json_object_object_get_ex(jargs, "policy", &jpol);
	const gchar *strsize = !jsize ? NULL : json_object_get_string (jsize);
	const gchar *stgpol = !jpol ? NULL : json_object_get_string (jpol);

	if (!strsize)
		return _reply_format_error (args, BADREQ("Missing size estimation"));

	errno = 0;
	gchar *end = NULL;
	gint64 size = g_ascii_strtoll (strsize, &end, 10);
	if ((end && *end) || errno == ERANGE || errno == EINVAL)
		return _reply_format_error (args, BADREQ("Invalid size format"));

	gboolean autocreate = _request_has_flag (args, PROXYD_HEADER_MODE, "autocreate");
	GError *err = NULL;
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_BEANS (m2->host, args->url, stgpol, size, 0, &beans);
	}

retry:
	GRID_TRACE("Content preparation %s", oio_url_get (args->url, OIOURL_WHOLE));
	err = _resolve_meta2 (args, hook);

	// Maybe manage autocreation
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					err->code, err->message);
			autocreate = FALSE;
			g_clear_error (&err);
			if (!(err = _m2_container_create (args)))
				goto retry;
		}
	}

	// Patch the chunk size to ease putting contents with unknown size.
	if (!err) {
		gint64 chunk_size = 0;
		NSINFO_DO(chunk_size = nsinfo.chunk_size);
		chunk_size = MAX(chunk_size,1);
		for (GSList *l=beans; l ;l=l->next) {
			if (l->data && (DESCR(l->data) == &descr_struct_CHUNKS)) {
				struct bean_CHUNKS_s *bean = l->data;
				CHUNKS_set_size(bean, chunk_size);
			}
		}
		args->rp->add_header(PROXYD_HEADER_PREFIX "ns-chunk-size",
				g_strdup_printf("%"G_GINT64_FORMAT, chunk_size));
	}

	return _reply_simplified_beans (args, err, beans, TRUE);
}

static GError *
_m2_json_spare (struct req_args_s *args, struct json_object *jbody, GSList ** out)
{
	GSList *notin = NULL, *broken = NULL;
	json_object *jnotin = NULL, *jbroken = NULL;
	GError *err;

	if (!json_object_is_type (jbody, json_type_object))
		return BADREQ ("Body is not a valid JSON object");

	if (!json_object_object_get_ex (jbody, "notin", &jnotin))
		return BADREQ("'notin' field missing");
	if (!json_object_object_get_ex (jbody, "broken", &jbroken))
		return BADREQ("'broken' field missing");

	if (NULL != (err = _load_simplified_chunks (jnotin, &notin))
		|| NULL != (err = _load_simplified_chunks (jbroken, &broken))) {
		_bean_cleanl2 (notin);
		_bean_cleanl2 (broken);
		return err;
	}
	if (!notin && !broken)
		return BADREQ("Empty beans sets");

	GSList *obeans = NULL;
	GError *hook (struct meta1_service_url_s * m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_SPARE (m2->host, args->url,
				OPT("stgpol"), notin, broken, &obeans);
	}
	err = _resolve_meta2 (args, hook);
	_bean_cleanl2 (broken);
	_bean_cleanl2 (notin);
	EXTRA_ASSERT ((err != NULL) ^ (obeans != NULL));
	if (!err)
		*out = obeans;
	else
		_bean_cleanl2 (obeans);
	return err;
}

static enum http_rc_e
action_m2_content_spare (struct req_args_s *args, struct json_object *jargs)
{
	GSList *beans = NULL;
	GError *err = _m2_json_spare (args, jargs, &beans);
	return _reply_beans (args, err, beans);
}

static enum http_rc_e
action_m2_content_touch (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_touch_content (m2->host, args->url);
	}
	GError *err = _resolve_meta2 (args, hook);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_link (struct req_args_s *args, struct json_object *jargs)
{
	if (NULL != CONTENT())
		return _reply_m2_error (args, BADREQ("No content allowed in the URL"));

	if (!jargs || !json_object_is_type (jargs, json_type_object))
		return _reply_m2_error (args, BADREQ("Expected: json object"));

	struct json_object *jid = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"id",  &jid,  json_type_string, 1},
		{NULL, NULL, 0, 0}
	};
	GError *err = oio_ext_extract_json (jargs, m);
	if (err)
		return _reply_m2_error (args, BADREQ("Expected: id (string)"));

	const char *id = json_object_get_string (jid);
	if (!oio_url_set (args->url, OIOURL_CONTENTID, id))
		return _reply_m2_error (args, BADREQ("Expected: id (hexa string)"));

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_LINK (m2->host, args->url);
	}
	err = _resolve_meta2 (args, hook);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_propset (struct req_args_s *args, struct json_object *jargs)
{
	if (CONTENT())
		return _reply_m2_error (args, BADREQ("Content. not allowed in the URL"));

	// TODO manage the version of the content
	gint64 version = 0;
	GSList *beans = NULL;

	if (jargs) {
		if (!json_object_is_type(jargs, json_type_object))
			return _reply_format_error (args, BADREQ("Object argument expected"));
		json_object_object_foreach(jargs,sk,jv) {
			struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
			PROPERTIES_set2_key (prop, sk);
			if (json_object_is_type (jv, json_type_null)) {
				PROPERTIES_set2_value (prop, (guint8*)"", 0);
			} else {
				const char *sv = json_object_get_string (jv);
				PROPERTIES_set2_value (prop, (guint8*)sv, strlen(sv));
			}
			PROPERTIES_set2_alias (prop, oio_url_get (args->url, OIOURL_PATH));
			PROPERTIES_set_version (prop, version);
			beans = g_slist_prepend (beans, prop);
		}
	}

	guint32 flags = 0;
	if (OPT("flush"))
		flags |= M2V2_FLAG_FLUSH;

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_PROP_SET (m2->host, args->url, flags, beans);
	}
	GError *err = _resolve_meta2 (args, hook);
	_bean_cleanl2 (beans);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_propdel (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_array))
		return _reply_format_error (args, BADREQ("Array argument expected"));

	// TODO manage the version of the content
	gint64 version = 0;
	(void) version;

	// build the payload
	for (int i=json_object_array_length(jargs); i>0 ;i--) {
		json_object *item = json_object_array_get_idx (jargs, i-1);
		if (!json_object_is_type(item, json_type_string))
			return _reply_format_error(args, BADREQ ("string expected as property name"));
	}
	GSList *names = NULL;
	for (int i=json_object_array_length(jargs); i>0 ;i--) {
		json_object *item = json_object_array_get_idx (jargs, i-1);
		names = g_slist_prepend (names, g_strdup(json_object_get_string(item)));
	}

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_PROP_DEL (m2->host, args->url, names);
	}
	GError *err = _resolve_meta2 (args, hook);
	g_slist_free_full (names, g_free0);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_propget (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	// TODO manage the version of the content
	gint64 version = 0;
	(void) version;

	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_PROP_GET (m2->host, args->url,
				M2V2_FLAG_ALLPROPS|M2V2_FLAG_NOFORMATCHECK, &beans);
	}
	GError *err = _resolve_meta2 (args, hook);
	return _reply_properties (args, err, beans);
}

/* CONTENT resources ------------------------------------------------------- */

static GError *
_m2_json_put (struct req_args_s *args, struct json_object *jbody)
{
	if (!jbody)
		return BADREQ("Invalid JSON body");

	gboolean append = _request_has_flag (args, PROXYD_HEADER_MODE, "append");
	gboolean force = _request_has_flag (args, PROXYD_HEADER_MODE, "force");
	GSList *ibeans = NULL;
	GError *err;

	if (NULL != (err = _load_simplified_content (args, jbody, &ibeans))) {
		_bean_cleanl2 (ibeans);
		return err;
	}

	GError *hook (struct meta1_service_url_s * m2, gboolean *next) {
		(void) next;
		GSList *obeans = NULL;
		GError *e = NULL;
		if (force)
			e = m2v2_remote_execute_OVERWRITE (m2->host, args->url, ibeans);
		else if (append)
			e = m2v2_remote_execute_APPEND (m2->host, args->url, ibeans, &obeans);
		else
			e = m2v2_remote_execute_PUT (m2->host, args->url, ibeans, &obeans);
		_bean_cleanl2 (obeans);
		return e;
	}
	err = _resolve_meta2 (args, hook);
	_bean_cleanl2 (ibeans);
	return err;
}

enum http_rc_e
action_content_put (struct req_args_s *args)
{
	GError *err = NULL;
	json_tokener *parser = json_tokener_new ();
	json_object *jbody = NULL;
	if (args->rq->body->len)
		jbody = json_tokener_parse_ex (parser,
				(char *) args->rq->body->data, args->rq->body->len);

	if (json_tokener_success != json_tokener_get_error (parser))
		err = BADREQ("Invalid JSON");
	else {
		gboolean autocreate = _request_has_flag (args,
				PROXYD_HEADER_MODE, "autocreate");
retry:
		err = _m2_json_put (args, jbody);
		if (err && CODE_IS_NOTFOUND(err->code)) {
			if (autocreate) {
				GRID_DEBUG("Resource not found, autocreation");
				autocreate = FALSE;
				g_clear_error (&err);
				if (!(err = _m2_container_create (args)))
					goto retry;
			}
		}
	}

	if (jbody)
		json_object_put (jbody);
	json_tokener_free (parser);
	return _reply_m2_error (args, err);
}

enum http_rc_e
action_content_prepare (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_beans);
}

enum http_rc_e
action_content_show (struct req_args_s *args)
{
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_GET (m2->host, args->url, 0, &beans);
	}
	GError *err = _resolve_meta2 (args, hook);
	return _reply_simplified_beans (args, err, beans, TRUE);
}

enum http_rc_e
action_content_delete (struct req_args_s *args)
{
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_DEL (m2->host, args->url);
	}
	GError *err = _resolve_meta2 (args, hook);
	return _reply_m2_error (args, err);
}

enum http_rc_e
action_content_touch (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_touch);
}

enum http_rc_e
action_content_link (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_link);
}

enum http_rc_e
action_content_spare (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_spare);
}

enum http_rc_e
action_content_prop_get (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_propget);
}

enum http_rc_e
action_content_prop_set (struct req_args_s *args)
{
    return rest_action (args, action_m2_content_propset);
}

enum http_rc_e
action_content_prop_del (struct req_args_s *args)
{
	return rest_action (args, action_m2_content_propdel);
}

enum http_rc_e
action_content_copy (struct req_args_s *args)
{
	const gchar *target = g_tree_lookup (args->rq->tree_headers, "destination");
	if (!target)
		return _reply_format_error(args, BADREQ("Missing target header"));

	struct oio_url_s *target_url = oio_url_init(target);
	if (!target_url)
		return _reply_format_error(args, BADREQ("Invalid URL in target header"));

	// Check the namespace and container match between both URLs
	if (!oio_url_has(target_url, OIOURL_HEXID)
			|| !oio_url_has(target_url, OIOURL_NS)
			|| !oio_url_has(target_url, OIOURL_PATH)
			|| !oio_url_has(args->url, OIOURL_HEXID)
			|| !oio_url_has(args->url, OIOURL_NS)
			|| strcmp(oio_url_get(target_url, OIOURL_HEXID), oio_url_get(args->url, OIOURL_HEXID))
			|| strcmp(oio_url_get(target_url, OIOURL_HEXID), oio_url_get(args->url, OIOURL_HEXID))) {
		oio_url_pclean(&target_url);
		return _reply_format_error(args, BADREQ("Invalid source/target URL"));
	}

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_COPY (m2->host, target_url, oio_url_get(args->url, OIOURL_PATH));
	}
	GError *err = _resolve_meta2 (args, hook);
	oio_url_pclean(&target_url);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}
