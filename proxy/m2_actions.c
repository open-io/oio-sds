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
#include <meta2v2/meta2_bean.h>
#include <meta2v2/autogen.h>

#include "common.h"
#include "actions.h"

static void
_get_meta2_realtype (struct req_args_s *args, gchar *d, gsize dlen)
{
	const char *type = oio_url_get (args->url, OIOURL_TYPE);
	if (type && *type) {
		g_snprintf(d, dlen, "%s.%s", NAME_SRVTYPE_META2, type);
	} else {
		g_strlcpy(d, NAME_SRVTYPE_META2, dlen);
	}
}

static GError *
_resolve_meta2 (struct req_args_s *args, enum preference_e how,
		request_packer_f pack, GSList **out)
{
	if (out) *out = NULL;

	gchar realtype[64];
	_get_meta2_realtype (args, realtype, sizeof(realtype));
	CLIENT_CTX(ctx, args, realtype, 1);
	ctx.which = how;

	GError *err = gridd_request_replicated (&ctx, pack);

	if (err) {
		GRID_DEBUG("M2V2 call failed: %d %s", err->code, err->message);
	} else if (out) {
		g_assert (ctx.bodyv != NULL);
		for (guint i=0; i<ctx.count ;++i) {
			GByteArray *b = ctx.bodyv[i];
			if (b) {
				GSList *l = bean_sequence_unmarshall (b->data, b->len);
				if (l) {
					*out = metautils_gslist_precat (*out, l);
				}
			}
		}
	}

	client_clean (&ctx);
	return err;
}

static GError *
_resolve_meta2_for_list (struct req_args_s *args, request_packer_f pack,
		struct list_result_s *out)
{
	gchar realtype[64];
	_get_meta2_realtype (args, realtype, sizeof(realtype));
	CLIENT_CTX_SLAVE(ctx, args, realtype, 1);
	ctx.decoder_data = out;
	ctx.decoder = m2v2_list_result_extract;

	GError *err = gridd_request_replicated (&ctx, pack);

	if (err)
		GRID_DEBUG("M2V2 call failed: %d %s", err->code, err->message);

	client_clean (&ctx);
	return err;
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

static void
_dump_json_aliases_and_headers (GString *gstr, GSList *aliases, GTree *headers)
{
	g_string_append (gstr, "\"objects\":[");
	gboolean first = TRUE;
	for (; aliases ; aliases=aliases->next) {
		COMA(gstr,first);

		struct bean_ALIASES_s *a = aliases->data;
		struct bean_CONTENTS_HEADERS_s *h =
			g_tree_lookup (headers, ALIASES_get_content(a));

		g_string_append(gstr, "{\"name\":\"");
		oio_str_gstring_append_json_string(gstr, ALIASES_get_alias(a)->str);
		g_string_append_printf(gstr,
				"\",\"ver\":%"G_GINT64_FORMAT
				",\"ctime\":%"G_GINT64_FORMAT
				",\"mtime\":%"G_GINT64_FORMAT
				",\"deleted\":%s"
				",\"content\":\"",
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
	g_string_append_c (gstr, ']');
}

static void
_dump_json_beans (GString *gstr, GSList *beans)
{
	GSList *aliases = NULL;
	GTree *headers = g_tree_new ((GCompareFunc)metautils_gba_cmp);

	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES)
			aliases = g_slist_prepend (aliases, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			g_tree_insert (headers, CONTENTS_HEADERS_get_id(l->data), l->data);
		}
	}

	aliases = g_slist_sort (aliases, (GCompareFunc)_sort_aliases_by_name);
	_dump_json_aliases_and_headers (gstr, aliases, headers);

	g_slist_free (aliases);
	g_tree_destroy (headers);
}

static void
_dump_json_prefixes (GString *gstr, GTree *tree_prefixes)
{
	gchar **prefixes = gtree_string_keys (tree_prefixes);
	g_string_append (gstr, "\"prefixes\":[");
	if (prefixes) {
		gboolean first = TRUE;
		for (gchar **pp=prefixes; *pp ;++pp) {
			COMA(gstr,first);
			g_string_append_c (gstr, '"');
			oio_str_gstring_append_json_string (gstr, *pp);
			g_string_append_c (gstr, '"');
		}
		g_free (prefixes);
	}
	g_string_append_c (gstr, ']');
}

static void
_dump_json_properties (GString *gstr, GTree *properties)
{
	g_string_append (gstr, "\"properties\":{");
	if (properties) {
		gboolean first = TRUE;
		gboolean _func (gpointer k, gpointer v, gpointer i) {
			(void) i;
			COMA(gstr,first);
			oio_str_gstring_append_json_pair (gstr, (const char *)k, (const char *)v);
			return FALSE;
		}
		g_tree_foreach (properties, _func, NULL);
	}
	g_string_append (gstr, "}");
}

static enum http_rc_e
_reply_list_result (struct req_args_s *args, GError * err,
		struct list_result_s *out, GTree *tree_prefixes)
{
	if (err)
		return _reply_m2_error (args, err);

	/* TODO to be removed as soon as all the clients consime the properties
	 * in the headers. */
	_container_new_props_to_headers (args, out->props);

	GString *gstr = g_string_new ("{");
	_dump_json_prefixes (gstr, tree_prefixes);
	g_string_append_c (gstr, ',');
	_dump_json_properties (gstr, out->props);
	g_string_append_c (gstr, ',');
	_dump_json_beans (gstr, out->beans);
	g_string_append_c (gstr, '}');

	return _reply_success_json (args, gstr);
}

static enum http_rc_e
_reply_beans (struct req_args_s *args, GError * err, GSList * beans)
{
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

static gchar *
_service_key(const gchar *prefix, const gchar *id)
{
	gchar actual_type[LIMIT_LENGTH_SRVTYPE] = {0};
	if (!strcmp(prefix, "http")) {
		strcpy(actual_type, NAME_SRVTYPE_RAWX);
	} else {
		strcpy(actual_type, prefix);
	}
	return oio_make_service_key(ns_name, actual_type, id);
}

static gint32
_score_from_chunk_id(const gchar *id)
{
	gchar svc_prefix[LIMIT_LENGTH_SRVTYPE] = {0};
	gchar svc_id[STRLEN_ADDRINFO] = {0};
	gchar *start = strstr(id, "://");
	int offset = 0;
	if (start) {
		strncpy(svc_prefix, id, start - id);
		offset = start - id + 3;
	} else {
		strcpy(svc_prefix, "http");
	}
	strncpy(svc_id, id+offset, strchr(id+offset, '/') - id - offset);
	gchar *svc_key = _service_key(svc_prefix, svc_id);
	struct oio_lb_item_s *item = oio_lb_world__get_item(lb_world, svc_key);
	gint32 res = item? item->weight : 0;
	g_free(item);
	g_free(svc_key);
	return res;
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

	for (GSList *l0=beans; l0; l0=l0->next) {
		if (!l0->data)
			continue;

		if (&descr_struct_CHUNKS == DESCR(l0->data) && gstr) {
			if (!first)
				g_string_append (gstr, ",\n");
			first = FALSE;

			// Serialize the chunk
			struct bean_CHUNKS_s *chunk = l0->data;
			gint32 score = _score_from_chunk_id(CHUNKS_get_id(chunk)->str);
			g_string_append_printf (gstr, "{\"url\":\"%s\"", CHUNKS_get_id (chunk)->str);
			g_string_append_printf (gstr, ",\"pos\":\"%s\"", CHUNKS_get_position (chunk)->str);
			g_string_append_printf (gstr, ",\"size\":%"G_GINT64_FORMAT, CHUNKS_get_size (chunk));
			g_string_append (gstr, ",\"hash\":\"");
			metautils_gba_to_hexgstr (gstr, CHUNKS_get_hash (chunk));
			g_string_append_printf(gstr, "\",\"score\":%d}", score);
		}
		else if (&descr_struct_ALIASES == DESCR(l0->data)) {
			alias = l0->data;
			if (ALIASES_get_deleted(alias) && !metautils_cfg_get_bool(OPT("deleted"),FALSE)) {
				if (gstr)
					g_string_free (gstr, TRUE);
				_bean_cleanl2(beans);
				return _reply_notfound_error(args, NEWERROR(CODE_CONTENT_DELETED, "Alias deleted"));
			}
		}
		else if (&descr_struct_CONTENTS_HEADERS == DESCR(l0->data)) {
			header = l0->data;
		}
		else if (&descr_struct_PROPERTIES == DESCR(l0->data)) {
			struct bean_PROPERTIES_s *prop = l0->data;
			gchar *k = g_strdup_printf (PROXYD_HEADER_PREFIX "content-meta-x-%s",
					PROPERTIES_get_key(prop)->str);
			GByteArray *v = PROPERTIES_get_value (prop);
			args->rp->add_header(k, g_strndup ((gchar*)v->data, v->len));
			g_free (k);
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

		gchar *s = g_tree_lookup(args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-policy");
		if (NULL != s)
			CONTENTS_HEADERS_set2_policy (header, s);
	}

	if (!err) { // Content ID
		gchar *s = g_tree_lookup(args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-id");
		if (NULL != s) {
			GByteArray *h = metautils_gba_from_hexstring (s);
			if (!h)
				err = BADREQ("Invalid content ID (not hexa)");
			else {
				oio_url_set (args->url, OIOURL_CONTENTID, s);
				CONTENTS_HEADERS_set_id (header, h);
				/* JFS: this is clean to have uniform CONTENT ID among all
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
		gchar *s = g_tree_lookup(args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-hash");
		if (NULL != s) {
			GByteArray *h = NULL;
			if (!(err = _get_hash (s, &h)))
				CONTENTS_HEADERS_set_hash (header, h);
			if (h) g_byte_array_free(h, TRUE);
		}
	}

	if (!err) { // Content length
		gchar *s = g_tree_lookup(args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-length");
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
		s = g_tree_lookup (args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-mime-type");
		if (s)
			CONTENTS_HEADERS_set2_mime_type (header, s);

		// Extract the chunking method
		s = g_tree_lookup (args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-chunk-method");
		if (s)
			CONTENTS_HEADERS_set2_chunk_method (header, s);
	}

	if (!err) {
		struct bean_ALIASES_s *alias = _bean_create (&descr_struct_ALIASES);
		beans = g_slist_prepend (beans, alias);
		ALIASES_set2_alias (alias, PATH());
		ALIASES_set_content (alias, CONTENTS_HEADERS_get_id (header));

		if (!err) { // aliases version
			gchar *s = g_tree_lookup(args->rq->tree_headers,
					PROXYD_HEADER_PREFIX "content-meta-version");
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
		if (err->code == CODE_BAD_REQUEST)
			return _reply_format_error (args, err);
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
	gboolean autocreate = _request_get_flag (args, "autocreate");
	gchar **properties = _container_headers_to_props (args);

	struct m2v2_create_params_s param = {
		OPT("stgpol"), OPT("verpol"), properties, FALSE
	};
	PACKER_VOID (_pack) { return m2v2_remote_pack_CREATE (args->url, &param); }

	GError *err;
retry:
	GRID_TRACE("Container creation %s", oio_url_get (args->url, OIOURL_WHOLE));
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					err->code, err->message);
			autocreate = FALSE; /* autocreate just once */
			g_clear_error (&err);
			GError *hook_dir (const gchar *m1) {
				gchar **urlv = NULL;
				gchar realtype[64];
				_get_meta2_realtype (args, realtype, sizeof(realtype));
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

static void
_re_enable (struct req_args_s *args, struct sqlx_name_s *name)
{
	GByteArray* _pack_enable () { return sqlx_pack_ENABLE (name); }
	GError *e = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack_enable, NULL);
	if (e) {
		GRID_INFO("Failed to un-freeze [%s]", oio_url_get(args->url, OIOURL_WHOLE));
		g_clear_error (&e);
	}
}

static enum http_rc_e
action_m2_container_destroy (struct req_args_s *args)
{
	GError *err = NULL;
	gchar **urlv = NULL;
	struct sqlx_name_mutable_s n = {NULL,NULL,NULL};

	const gboolean flush = _request_get_flag (args, "flush");
	const gboolean force = _request_get_flag (args, "force");

	/* TODO(jfs): const! */
	struct sqlx_name_s *name = sqlx_name_mutable_to_const(&n);
	/* TODO(jfs): manage container subtype */
	sqlx_name_fill (&n, args->url, NAME_SRVTYPE_META2, 1);
	/* pre-loads the locations of the container. We will need this at the
	 * destroy step. */
	err = hc_resolve_reference_service (resolver, args->url, n.type, &urlv);

	/* 1. FREEZE the base to avoid writings during the operation */
	if (!err) {
		PACKER_VOID (_pack) { return sqlx_pack_FREEZE (name); }
		if (NULL != (err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL))) {
			/* rollback! */
			_re_enable (args, name);
			goto clean_and_exit;
		}
	}

	/* 2. FLUSH the base on the MASTER, so events are generated for all the
	   contents removed. */
	if (!err) {
		if (flush) {
			PACKER_VOID(_pack) { return m2v2_remote_pack_FLUSH (args->url); }
			err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
		} else if (!force) {
			PACKER_VOID(_pack) { return m2v2_remote_pack_ISEMPTY (args->url); }
			err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
		}
		if (NULL != err) {
			/* rollback! */
			_re_enable (args, name);
			goto clean_and_exit;
		}
	}

	/* 3. UNLINK the base in the directory */
	if (!err) {
		GError * _unlink (const char * m1) {
			return meta1v2_remote_unlink_service (m1, args->url, n.type);
		}
		if (NULL != (err = _m1_locate_and_action (args->url, _unlink))) {
			_re_enable (args, name);
			goto clean_and_exit;
		}
	}

	hc_decache_reference_service (resolver, args->url, n.type);

	/* 4. DESTROY each local base */
	if (!err && urlv && *urlv) {
		const guint32 flag_force = (force) ? M2V2_DESTROY_FORCE : 0;
		const guint32 flag_flush = (flush) ? M2V2_DESTROY_FLUSH : 0;

		meta1_urlv_shift_addr(urlv);
		err = m2v2_remote_execute_DESTROY (urlv[0], args->url,
				M2V2_DESTROY_EVENT|flag_force|flag_flush);
		if (!err && urlv[1]) {
			err = m2v2_remote_execute_DESTROY_many(urlv+1, args->url,
					flag_force|flag_flush);
		}
	}

clean_and_exit:
	if (urlv)
		g_strfreev (urlv);
	sqlx_name_clean (&n);
	if (NULL != err)
		return _reply_m2_error(args, err);
	return _reply_nocontent (args);
}

/* CONTAINER action resources ----------------------------------------------- */

static enum http_rc_e
action_m2_container_purge (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_PURGE (args->url); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	if (NULL != err) {
		g_prefix_error (&err, "M2 error: ");
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_flush (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_FLUSH (args->url); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	if (NULL != err) {
		g_prefix_error (&err, "M2 error: ");
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_dedup (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEDUP (args->url); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	if (NULL != err) {
		g_prefix_error (&err, "M2 error: ");
		return _reply_common_error (args, err);
	}
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_touch (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_TOUCHB (args->url, 0); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
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
	if (err) {
		EXTRA_ASSERT(beans == NULL);
		return _reply_format_error (args, err);
	}
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	PACKER_VOID(_pack) { return m2v2_remote_pack_RAW_ADD (args->url, beans); }
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	_bean_cleanl2(beans);
	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_raw_delete (struct req_args_s *args, struct json_object *jargs)
{
	GSList *beans = NULL;
	GError *err = m2v2_json_load_setof_xbean (jargs, &beans);
	if (err) {
		EXTRA_ASSERT(beans == NULL);
		return _reply_format_error (args, err);
	}
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	PACKER_VOID(_pack) { return m2v2_remote_pack_RAW_DEL (args->url, beans); }
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	_bean_cleanl2(beans);
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

	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_RAW_SUBST (args->url, beans_new, beans_old);
		}
		err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	}

	_bean_cleanl2 (beans_old);
	_bean_cleanl2 (beans_new);
	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

/* JFS: You talk to a meta2 with its subtype, because it is a "high level"
 * interaction with the DB, while sqlx access are quiet raw and "low level"
 * DB calls. So that they do not consider the same kind of type. SQLX want to
 * a fully qualified type, not just the subtype. */
static void
_add_meta2_type (struct req_args_s *args)
{
	gchar realtype[64] = "type=";
	gsize l = strlen(realtype);
	_get_meta2_realtype (args, realtype+l, sizeof(realtype)-l);
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

typedef GByteArray* (*list_packer_f) (struct list_params_s *);

static GError *
_list_loop (struct req_args_s *args, struct list_params_s *in0, struct list_result_s *out0,
		GTree *tree_prefixes, list_packer_f packer)
{
	GError *err = NULL;
	gboolean stop = FALSE;
	guint count = 0;
	struct list_params_s in = *in0;

	char delimiter = _delimiter (args);
	GRID_DEBUG("Listing [%s] max=%"G_GINT64_FORMAT" delim=%c prefix=%s"
			" marker=%s end=%s", oio_url_get(args->url, OIOURL_WHOLE),
			in0->maxkeys, delimiter, in0->prefix,
			in0->marker_start, in0->marker_end);

	PACKER_VOID(_pack) { return packer(&in); }

	while (!err && !stop && grid_main_is_running()) {

		struct list_result_s out = {0};
		m2v2_list_result_init (&out);

		/* patch the input parameters */
		if (in0->maxkeys > 0)
			in.maxkeys = in0->maxkeys - (count + g_tree_nnodes(tree_prefixes));
		if (out0->next_marker)
			in.marker_start = out0->next_marker;

		/* Action */
		err = _resolve_meta2_for_list (args, _pack, &out);
		if (NULL != err) {
			m2v2_list_result_clean (&out);
			break;
		}

		/* Manage the properties */
		gchar **keys = gtree_string_keys (out.props);
		if (keys) {
			for (gchar **pk=keys; *pk ;++pk) {
				gchar *v = g_tree_lookup (out.props, *pk);
				g_tree_steal (out.props, *pk);
				g_tree_replace (out0->props, *pk, v);
			}
			g_free (keys);
		}

		/* Manage the beans */
		oio_str_reuse (&out0->next_marker, out.next_marker);
		out.next_marker = NULL;
		if (out.beans) {
			struct filter_ctx_s ctx;
			ctx.beans = out0->beans;
			ctx.prefixes = tree_prefixes;
			ctx.count = count;
			ctx.prefix = in0->prefix;
			ctx.delimiter = delimiter;
			_filter (&ctx, out.beans);
			out.beans = NULL;
			count = ctx.count;
			out0->beans = ctx.beans;
		}

		if (in0->maxkeys > 0 && in0->maxkeys <= (count + g_tree_nnodes(tree_prefixes))) {
			/* enough elements received */
			out0->truncated = out.truncated;
			stop = TRUE;
		} else if (!out.truncated) {
			/* no more elements expected, the meta2 told us */
			out0->truncated = FALSE;
			stop = TRUE;
		} else if (out.truncated && !out0->next_marker) {
			GRID_ERROR("BUG : meta2 must return a ");
			err = NEWERROR(CODE_PLATFORM_ERROR, "BUG in meta2 : list truncated but no marker returned");
			stop = TRUE;
		}

		m2v2_list_result_clean (&out);
	}

	return err;
}

enum http_rc_e
action_container_list (struct req_args_s *args)
{
	struct list_result_s list_out = {0};
	struct list_params_s list_in = {0};
	GError *err = NULL;
	GTree *tree_prefixes = NULL;

	/* Triggers special listings */
	const char *chunk_id = g_tree_lookup (args->rq->tree_headers,
			PROXYD_HEADER_PREFIX "list-chunk-id");
	const char *content_hash_hex = g_tree_lookup (args->rq->tree_headers,
			PROXYD_HEADER_PREFIX "list-content-hash");

	GBytes *content_hash = NULL;
	if (content_hash_hex) {
		GByteArray *gba = NULL;
		if (NULL != (err = _get_hash (content_hash_hex, &gba)))
			return _reply_format_error (args, BADREQ("Invalid content hash"));
		content_hash = g_byte_array_free_to_bytes (gba);
	}

	/* Init the listing options common to all the modes */
	list_in.flag_headers = ~0;
	list_in.flag_nodeleted = ~0;
	list_in.prefix = OPT("prefix");
	list_in.marker_start = OPT("marker");
	list_in.marker_end = OPT("marker_end");
	if (OPT("deleted"))
		list_in.flag_nodeleted = 0;
	if (OPT("all"))
		list_in.flag_allversion = ~0;
	if (!err)
		err = _max (args, &list_in.maxkeys);
	if (!err) {
		tree_prefixes = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
		m2v2_list_result_init (&list_out);
	}

	if (!err) {
		GByteArray* _pack (struct list_params_s *in) {
			if (chunk_id)
				return m2v2_remote_pack_LIST_BY_CHUNKID (args->url, in, chunk_id);
			if (content_hash)
				return m2v2_remote_pack_LIST_BY_HEADERHASH (args->url, in, content_hash);
			return m2v2_remote_pack_LIST (args->url, in);
		}
		err = _list_loop (args, &list_in, &list_out, tree_prefixes, _pack);
	}

	if (!err) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "list-truncated",
				g_strdup(list_out.truncated ? "true" : "false"));
		if (list_out.next_marker) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "list-marker",
					g_uri_escape_string(list_out.next_marker, NULL, FALSE));
		}
	}

	enum http_rc_e rc = _reply_list_result (args, err, &list_out, tree_prefixes);

	if (tree_prefixes) g_tree_destroy (tree_prefixes);
	if (content_hash) g_bytes_unref (content_hash);
	m2v2_list_result_clean (&list_out);

	return rc;
}

enum http_rc_e
action_container_show (struct req_args_s *args)
{
	GError *err = NULL;

	CLIENT_CTX(ctx,args,NAME_SRVTYPE_META2,1);

	GByteArray* packer () {
		return sqlx_pack_PROPGET (sqlx_name_mutable_to_const(&ctx.name));
	}
	err = gridd_request_replicated (&ctx, packer);

	if (err) {
		client_clean (&ctx);
		return _reply_m2_error (args, err);
	}

	GSList *pairs = NULL;
	err = metautils_unpack_bodyv (ctx.bodyv, &pairs, key_value_pairs_unmarshall);
	if (err) {
		g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
		client_clean (&ctx);
		return _reply_system_error(args, err);
	}

	_container_old_props_to_headers (args, pairs);
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	client_clean (&ctx);
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

	gboolean autocreate = _request_get_flag (args, "autocreate");
	GError *err = NULL;
	GSList *beans = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_BEANS (args->url, stgpol, size, 0); }

retry:
	GRID_TRACE("Content preparation %s", oio_url_get (args->url, OIOURL_WHOLE));
	beans = NULL;
	err = _resolve_meta2 (args, CLIENT_PREFER_SLAVE, _pack, &beans);

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

		/* 'ns_chunk_size' should be read in a critical section ... but
		   nevermind 'cos it won't change often and will always be allocated,
		   so I (jfs) accept to just read without protection. We thus save a
		   lot of mutex operations on this. */
		gint64 chunk_size = ns_chunk_size;

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

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_SPARE (args->url, OPT("stgpol"), notin, broken);
	}
	GSList *obeans = NULL;
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, &obeans);
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
	PACKER_VOID(_pack) { return m2v2_remote_pack_TOUCHC (args->url); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
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

	PACKER_VOID(_pack) { return m2v2_remote_pack_LINK (args->url); }
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
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

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_SET (args->url, flags, beans); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
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

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_DEL (args->url, names); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	g_slist_free_full (names, g_free0);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

#define PROPGET_FLAGS M2V2_FLAG_ALLPROPS|M2V2_FLAG_NOFORMATCHECK

static enum http_rc_e
action_m2_content_propget (struct req_args_s *args, struct json_object *jargs)
{
	(void) jargs;
	/* TODO manage the version of the content */

	GSList *beans = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_GET (args->url, PROPGET_FLAGS); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_SLAVE, _pack, &beans);
	return _reply_properties (args, err, beans);
}

/* CONTENT resources ------------------------------------------------------- */

static GError *
_m2_json_put (struct req_args_s *args, struct json_object *jbody)
{
	if (!jbody)
		return BADREQ("Invalid JSON body");

	gboolean append = _request_get_flag (args, "append");
	gboolean force = _request_get_flag (args, "force");
	GSList *ibeans = NULL, *obeans = NULL;
	GError *err;

	if (NULL != (err = _load_simplified_content (args, jbody, &ibeans))) {
		_bean_cleanl2 (ibeans);
		return err;
	}

	PACKER_VOID(_pack) {
		if (force) return m2v2_remote_pack_OVERWRITE (args->url, ibeans);
		if (append) return m2v2_remote_pack_APPEND (args->url, ibeans);
		return m2v2_remote_pack_PUT (args->url, ibeans);
	}
	err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, &obeans);
	_bean_cleanl2 (obeans);
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
		gboolean autocreate = _request_get_flag (args, "autocreate");
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
	PACKER_VOID(_pack) { return m2v2_remote_pack_GET (args->url, 0); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_SLAVE, _pack, &beans);
	return _reply_simplified_beans (args, err, beans, TRUE);
}

enum http_rc_e
action_content_delete (struct req_args_s *args)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEL (args->url); }
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
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

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_COPY (target_url, oio_url_get(args->url, OIOURL_PATH));
	}
	GError *err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
	oio_url_pclean(&target_url);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}
