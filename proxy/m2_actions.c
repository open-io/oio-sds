/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

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
_resolve_meta2 (struct req_args_s *args, enum proxy_preference_e how,
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
		EXTRA_ASSERT(ctx.bodyv != NULL);
		for (guint i=0; i<ctx.count ;++i) {
			GError *e = ctx.errorv[i];
			GByteArray *b = ctx.bodyv[i];
			if (e && e->code != CODE_FINAL_OK)
				continue;
			if (b && b->data && b->len) {
				GSList *l = bean_sequence_unmarshall (b->data, b->len);
				if (l) {
					*out = metautils_gslist_precat (*out, l);
				}
			}
		}
	}
	if (g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PERFDATA)) {
		gchar *perfdata = g_strdup_printf(
				"resolve=%"G_GINT64_FORMAT",meta2=%"G_GINT64_FORMAT,
				ctx.resolve_duration, ctx.request_duration);
		args->rp->add_header(PROXYD_HEADER_PERFDATA, perfdata);
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
	if (err->code == CODE_CONTAINER_NOTEMPTY ||
			err->code == CODE_CONTENT_EXISTS)
		return _reply_conflict_error (args, err);
	if (err->code == CODE_CONTENT_DRAINED)
		return _reply_gone_error(args, err);
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
_container_old_props_to_headers (struct req_args_s *args, gchar **props)
{
	for (gchar **p=props; *p && *(p+1) ;p+=2)
		_container_single_prop_to_headers (args, *p, g_strdup(*(p+1)));
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
_dump_json_aliases_and_headers(GString *gstr, GSList *aliases,
		GTree *headers, GTree *props)
{
	g_string_append_static (gstr, "\"objects\":[");
	gboolean first = TRUE;
	for (; aliases ; aliases=aliases->next) {
		COMA(gstr,first);

		struct bean_ALIASES_s *a = aliases->data;
		struct bean_CONTENTS_HEADERS_s *h =
			g_tree_lookup (headers, ALIASES_get_content(a));
		gchar *prop_key = g_strdup_printf("%s_%"G_GINT64_FORMAT,
				ALIASES_get_alias(a)->str,
				ALIASES_get_version(a));
		GSList *prop_list = g_tree_lookup(props, prop_key);
		g_free(prop_key);

		g_string_append_c(gstr, '{');
		OIO_JSON_append_gstr(gstr, "name", ALIASES_get_alias(a));
		g_string_append_c(gstr, ',');
		OIO_JSON_append_int(gstr, "version", ALIASES_get_version(a));
		g_string_append_c(gstr, ',');
		OIO_JSON_append_int(gstr, "ctime", ALIASES_get_ctime(a));
		g_string_append_c(gstr, ',');
		OIO_JSON_append_int(gstr, "mtime", ALIASES_get_mtime(a));
		g_string_append_c(gstr, ',');
		OIO_JSON_append_bool(gstr, "deleted", ALIASES_get_deleted(a));
		g_string_append_c(gstr, ',');
		OIO_JSON_append_gba(gstr, "content", ALIASES_get_content(a));

		if (h) {
			g_string_append_c (gstr, ',');
			GString *pol = CONTENTS_HEADERS_get_policy(h);
			GByteArray *hh = CONTENTS_HEADERS_get_hash(h);

			if (pol)
				g_string_append_printf(gstr, "\"policy\":\"%s\",\"hash\":",
						pol->str);
			else
				g_string_append_printf(gstr, "\"policy\":null,\"hash\":");
			if (hh) {
				g_string_append_c (gstr, '"');
				metautils_gba_to_hexgstr(gstr, hh);
				g_string_append_c (gstr, '"');
			} else {
				g_string_append_static(gstr, "null");
			}

			g_string_append_printf(gstr, ",\"size\":%"G_GINT64_FORMAT,
					CONTENTS_HEADERS_get_size(h));
			g_string_append_printf(gstr, ",\"mime-type\":\"%s\"",
					CONTENTS_HEADERS_get_mime_type(h)->str);
		}
		if (prop_list) {
			g_string_append_static(gstr, ",\"properties\":{");
			gboolean inner_first = TRUE;
			for (GSList *prop = prop_list;
					prop && prop->data;
					prop = prop->next) {
				struct bean_PROPERTIES_s *bprop = prop->data;
				COMA(gstr, inner_first);
				g_string_append_printf(gstr, "\"%s\":\"",
						PROPERTIES_get_key(bprop)->str);
				GByteArray *val = PROPERTIES_get_value(bprop);
				oio_str_gstring_append_json_blob(gstr,
						(gchar*)val->data, val->len);
				g_string_append_c(gstr, '"');
			}
			g_string_append_c(gstr, '}');
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
	GTree *props = g_tree_new_full((GCompareDataFunc)metautils_strcmp3,
			NULL, g_free, NULL);

	for (GSList *l = beans; l; l = l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES) {
			aliases = g_slist_prepend (aliases, l->data);
		} else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS) {
			g_tree_insert (headers, CONTENTS_HEADERS_get_id(l->data), l->data);
		} else if (DESCR(l->data) == &descr_struct_PROPERTIES) {
			/* Properties are linked to a specific version of an alias,
			 * and there is possibly several properties,
			 * thus we must build composed keys and lists. */
			gchar *key = g_strdup_printf("%s_%"G_GINT64_FORMAT,
					PROPERTIES_get_alias(l->data)->str,
					PROPERTIES_get_version(l->data));
			GSList *val = g_tree_lookup(props, key);
			val = g_slist_prepend(val, l->data);
			g_tree_replace(props, key, val);
		}
	}

	aliases = g_slist_sort (aliases, (GCompareFunc)_sort_aliases_by_name);
	_dump_json_aliases_and_headers(gstr, aliases, headers, props);

	gboolean _props_cleaner(gpointer key UNUSED,
			gpointer val, gpointer data UNUSED)
	{
		g_slist_free(val);
		return FALSE;
	}
	g_tree_foreach(props, _props_cleaner, NULL);
	g_tree_destroy(props);

	g_slist_free (aliases);
	g_tree_destroy (headers);
}

static void
_dump_json_prefixes (GString *gstr, GTree *tree_prefixes)
{
	gchar **prefixes = gtree_string_keys (tree_prefixes);
	g_string_append_static (gstr, "\"prefixes\":[");
	if (prefixes) {
		gboolean first = TRUE;
		for (gchar **pp=prefixes; *pp ;++pp) {
			COMA(gstr,first);
			oio_str_gstring_append_json_quote (gstr, *pp);
		}
		g_free (prefixes);
	}
	g_string_append_c (gstr, ']');
}

static void
_dump_json_properties (GString *gstr, GTree *properties)
{
	gboolean first = TRUE;
	gboolean _func (gpointer k, gpointer v, gpointer i) {
		gboolean want_system = GPOINTER_TO_INT(i);
		gboolean is_user = g_str_has_prefix((gchar*)k, "user.");
		if (want_system ^ is_user) {
			COMA(gstr, first);
			if (is_user)
				k += sizeof("user.") - 1;
			oio_str_gstring_append_json_pair(gstr, (const char *)k, (const char *)v);
		}
		return FALSE;
	}
	g_string_append_static(gstr, "\"properties\":{");
	if (properties) {
		g_tree_foreach(properties, _func, GINT_TO_POINTER(0));
	}
	g_string_append_static(gstr, "},\"system\":{");
	if (properties) {
		first = TRUE;
		g_tree_foreach(properties, _func, GINT_TO_POINTER(1));
	}
	g_string_append_c(gstr, '}');
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

	GString *gstr = g_string_sized_new (4096);
	g_string_append_c (gstr, '{');
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

	GString *gstr = g_string_sized_new (2048);
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

static gint32
_score_from_chunk_id (const char *id)
{
	gchar *key = NULL, *type = NULL, *netloc = NULL;

	// FIXME: probably broken with B2 URLs
	oio_parse_chunk_url(id, &type, &netloc, NULL);
	key = oio_make_service_key(ns_name, type, netloc);

	struct oio_lb_item_s *item = oio_lb_world__get_item(lb_world, key);
	gint32 res = item ? item->weight : 0;

	g_free(item);
	g_free(key);
	g_free(netloc);
	g_free(type);
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
	GString *gstr = NULL;
	if (body) {
		gstr = g_string_sized_new (2048);
		g_string_append_c (gstr, '[');
	}

	beans = g_slist_sort(beans, _bean_compare_kind);

	for (GSList *l0=beans; l0; l0=l0->next) {
		if (!l0->data)
			continue;

		if (&descr_struct_CHUNKS == DESCR(l0->data) && gstr) {
			if (!first)
				g_string_append_static (gstr, ",\n");
			first = FALSE;

			// Serialize the chunk
			struct bean_CHUNKS_s *chunk = l0->data;
			gint32 score = _score_from_chunk_id(CHUNKS_get_id(chunk)->str);
			g_string_append_printf (gstr, "{\"url\":\"%s\"", CHUNKS_get_id (chunk)->str);
			g_string_append_printf (gstr, ",\"pos\":\"%s\"", CHUNKS_get_position (chunk)->str);
			g_string_append_printf (gstr, ",\"size\":%"G_GINT64_FORMAT, CHUNKS_get_size (chunk));
			g_string_append_static (gstr, ",\"hash\":\"");
			metautils_gba_to_hexgstr (gstr, CHUNKS_get_hash (chunk));
			g_string_append_printf(gstr, "\",\"score\":%d}", score);
		}
		else if (&descr_struct_ALIASES == DESCR(l0->data)) {
			alias = l0->data;
			if (ALIASES_get_deleted(alias) && !oio_str_parse_bool(OPT("deleted"),FALSE)) {
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
			gchar *k = g_strdup_printf (PROXYD_HEADER_PREFIX "content-meta-%s",
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
		return BADREQ("JSON: invalid hash: not hexa: '%s'", s);

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

static GSList *
_load_properties_from_strv (gchar **props)
{
	GSList *beans = NULL;
	for (gchar **p=props; *p && *(p+1) ;p+=2) {
		const char *k = *p;
		const char *v = *(p+1);
		if (!oio_str_is_set(k))
			continue;
		struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
		PROPERTIES_set_version (prop, 0); // still unknown
		PROPERTIES_set2_key (prop, k);
		PROPERTIES_set2_value (prop, (guint8*)v, strlen((gchar*)v));
		beans = g_slist_prepend (beans, prop);
	}
	return beans;
}

static GError *
_load_alias_from_headers(struct req_args_s *args, GSList **pbeans)
{
	GError *err = NULL;
	GSList *beans = *pbeans;
	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;

	header = _bean_create (&descr_struct_CONTENTS_HEADERS);
	beans = g_slist_prepend (beans, header);
	CONTENTS_HEADERS_set2_id(header, (guint8 *) "00", 2);
	/* dummy (yet valid) content ID (must be hexa) */

	do {
		gchar *s = g_tree_lookup(args->rq->tree_headers,
								 PROXYD_HEADER_PREFIX "content-meta-policy");
		if (NULL != s)
			CONTENTS_HEADERS_set2_policy(header, s);
	} while (0);

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
			gint64 s64 = 0;
			if (!oio_str_is_number(s, &s64))
				err = BADREQ("Header: bad content length");
			else
				CONTENTS_HEADERS_set_size (header, s64);
		}
	}

	if (!err) { // Content-Type
		gchar *s = g_tree_lookup(args->rq->tree_headers,
						  PROXYD_HEADER_PREFIX "content-meta-mime-type");
		if (s)
			CONTENTS_HEADERS_set2_mime_type(header, s);
	}

	if (!err) { // Chunking method
		gchar *s = g_tree_lookup (args->rq->tree_headers,
						   PROXYD_HEADER_PREFIX "content-meta-chunk-method");
		if (s)
			CONTENTS_HEADERS_set2_chunk_method (header, s);
	}

	if (!PATH())
		err = BADREQ("Missing path in query string");

	if (!err) { // Load all the alias fields
		alias = _bean_create(&descr_struct_ALIASES);
		beans = g_slist_prepend(beans, alias);
		ALIASES_set2_alias(alias, PATH());
		ALIASES_set_content(alias, CONTENTS_HEADERS_get_id(header));

		if (!err) { // aliases version
			gchar *s = g_tree_lookup(args->rq->tree_headers,
									 PROXYD_HEADER_PREFIX "content-meta-version");
			if (s) {
				gint64 s64 = 0;
				if (!oio_str_is_number(s, &s64))
					err = BADREQ("Header: negative content version");
				else
					ALIASES_set_version(alias, s64);
			}
		}
	}

	*pbeans = beans;
	return err;
}

static GError *
_load_content_from_json_array(struct req_args_s *args,
		struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;

	if (!json_object_is_type(jbody, json_type_array))
		return BADREQ ("JSON: Not an array");
	if (json_object_array_length(jbody) <= 0)
		return BADREQ ("JSON: Empty array");

	err = _load_simplified_chunks (jbody, &beans);
	if (!err)
		err = _load_alias_from_headers(args, &beans);

	if (err)
		_bean_cleanl2 (beans);
	else
		*out = beans;

	return err;
}

static GError * _load_content_from_json_object(struct req_args_s *args,
		struct json_object *jbody, GSList **out) {

	if (!json_object_is_type(jbody, json_type_object))
		return BADREQ ("JSON: Not an object");

	struct json_object *jchunks = NULL;
	gchar **props = NULL;
	GError *err = KV_read_properties(jbody, &props, "properties", FALSE);
	if (err) {
		g_prefix_error(&err, "properties error");
	} else {
		if (!json_object_object_get_ex(jbody, "chunks", &jchunks)) {
			err = BADREQ("No [chunks] field");
		} else {
			/* load the content the "old way", from an array of chunks and the
			 * header. Then if there is no error, complete it with properties */
			if (!(err = _load_content_from_json_array(args, jchunks, out))) {
				GSList *beans = _load_properties_from_strv(props);
				for (GSList *l = beans; l; l = l->next)
					PROPERTIES_set2_alias(l->data, oio_url_get(args->url, OIOURL_PATH));
				*out = metautils_gslist_precat(*out, beans);
			}
		}
		if (props)
			g_strfreev(props);
	}
	return err;
}

static enum http_rc_e
_reply_properties (struct req_args_s *args, GError * err, GSList * beans)
{
	if (err)
		return _reply_common_error (args, err);

	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) == &descr_struct_ALIASES)
			_populate_headers_with_alias (args, l->data);
		else if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS)
			_populate_headers_with_header (args, l->data);
	}

	gboolean first = TRUE;
	GString *gs = g_string_sized_new(1024);
	g_string_append_static(gs, "{\"properties\":{");
	for (GSList *l=beans; l ;l=l->next) {
		if (DESCR(l->data) != &descr_struct_PROPERTIES)
			continue;
		if (!first) g_string_append_c(gs, ',');
		first = FALSE;
		struct bean_PROPERTIES_s *bean = l->data;
		oio_str_gstring_append_json_quote(gs, PROPERTIES_get_key(bean)->str);
		g_string_append_c(gs, ':');
		g_string_append_c(gs, '"');
		oio_str_gstring_append_json_blob(gs,
										 (gchar*)PROPERTIES_get_value(bean)->data,
										 PROPERTIES_get_value(bean)->len);
		g_string_append_c(gs, '"');
	}
	for (int i=0; i<2 ;++i) g_string_append_c(gs, '}');

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
	const char *s = OPT("max");
	*pmax = 0;
	if (!s)
		return NULL;

	if (!oio_str_is_number(s, pmax))
		return BADREQ("Invalid max number of items");
	if (*pmax <= 0)
		return BADREQ("Invalid max number of items: %s", "too small");
	return NULL;
}

struct filter_ctx_s
{
	GSList *beans;
	GTree *prefixes;
	guint count; // aliases in <beans>
	const char *prefix;
	const char *marker;
	char delimiter;
};

static void
_filter_list_result(struct filter_ctx_s *ctx, GSList *l)
{
	void forget (GSList *p) { if (p->data) _bean_clean (p->data); g_slist_free1 (p); }
	void prepend (GSList *p) { p->next = ctx->beans; ctx->beans = p; }

	gsize prefix_len = ctx->prefix ? strlen(ctx->prefix) : 0;
	for (GSList *tmp; l; l = tmp) {
		tmp = l->next;
		l->next = NULL;

		if (!l->data) {
			forget (l);
			continue;
		}
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS ||
				DESCR(l->data) == &descr_struct_PROPERTIES) {
			prepend (l);
			continue;
		}
		if (DESCR(l->data) != &descr_struct_ALIASES) {
			forget (l);
			continue;
		}

		const char *name = ALIASES_get_alias(l->data)->str;
		if (ctx->delimiter) {
			const char *p = strchr(name + prefix_len, ctx->delimiter);
			if (p) {
				// We must not respond a prefix equal to the marker.
				if (!ctx->marker ||
						strncmp(name, ctx->marker, (p - name) + 1)) {
					g_tree_insert(ctx->prefixes,
							g_strndup(name, (p - name) + 1),
							GINT_TO_POINTER(1));
				}
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
_m2_container_create_with_properties (struct req_args_s *args, char **props,
		const char *container_stgpol, const char *container_verpol)
{
	gboolean autocreate = TRUE;

	/* JFS: don't lookup for default verpol and stgpol, we must left they unset
	 * so that they will follow the default values of the namespace and (later)
	 * of the account. This is how we do NOW, by letting the meta2 find the best
	 * value when necessary. */
	struct m2v2_create_params_s param = {
			container_stgpol, container_verpol, props, FALSE
	};

	GError *err = NULL;
	PACKER_VOID (_pack) { return m2v2_remote_pack_CREATE (args->url, &param, DL()); }

retry:
	GRID_TRACE("Container creation %s", oio_url_get (args->url, OIOURL_WHOLE));
	err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					   err->code, err->message);
			autocreate = FALSE; /* autocreate just once */
			g_clear_error (&err);
			GError *hook_dir (const char *m1) {
				gchar **urlv = NULL, realtype[64];
				_get_meta2_realtype (args, realtype, sizeof(realtype));
				GError *e = meta1v2_remote_link_service(
						m1, args->url, realtype, TRUE, &urlv,
						oio_ext_get_deadline());
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

	return err;
}

static GError *
_m2_container_create_with_defaults (struct req_args_s *args)
{
	return _m2_container_create_with_properties(args, NULL, NULL, NULL);
}

static void
_re_enable (struct req_args_s *args)
{
	PACKER_VOID (_pack) { return sqlx_pack_ENABLE (_u, DL()); }
	GError *e = _resolve_meta2(args, CLIENT_PREFER_MASTER, _pack, NULL);
	if (e) {
		GRID_INFO("Failed to un-freeze [%s]: (%d) %s",
				oio_url_get(args->url, OIOURL_WHOLE), e->code, e->message);
		g_clear_error(&e);
	}
}

static enum http_rc_e
action_m2_container_destroy (struct req_args_s *args)
{
	GError *err = NULL;
	gchar **urlv = NULL;

	const gboolean force = _request_get_flag (args, "force");

	/* TODO FIXME manage container subtype */
	struct sqlx_name_inline_s n0;
	sqlx_inline_name_fill (&n0, args->url, NAME_SRVTYPE_META2, 1);
	NAME2CONST(n, n0);

	/* 0. Pre-loads the locations of the container. We will need this at the
	 * destroy step. */
	err = hc_resolve_reference_service (resolver, args->url, n.type, &urlv,
			oio_ext_get_deadline());
	if (!err && (!urlv || !*urlv))
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "No service located");

	/* 1. FREEZE the base to avoid writings during the operation */
	if (!err) {
		PACKER_VOID(_pack) { return sqlx_pack_FREEZE(_u, DL()); }
		err = _resolve_meta2 (args, CLIENT_PREFER_MASTER, _pack, NULL);
		if (NULL != err && CODE_IS_NETWORK_ERROR(err->code)) {
			/* rollback! There are chances the request made a timeout
			 * but was actually managed by the server. */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 2. FLUSH the base on the MASTER, so events are generated for all the
	   contents removed. */
	if (!err && !force) {
		guint32 flags = flag_force_master ? M2V2_FLAG_MASTER : 0;
		PACKER_VOID(_pack) { return m2v2_remote_pack_ISEMPTY (args->url, flags, DL()); }
		err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
		if (NULL != err) {
			/* rollback! */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 3. UNLINK the base in the directory */
	if (!err) {
		GError * _unlink (const char * m1) {
			return meta1v2_remote_unlink_service(
					m1, args->url, n.type, oio_ext_get_deadline());
		}
		err = _m1_locate_and_action (args->url, _unlink);
		hc_decache_reference_service (resolver, args->url, n.type);
		if (NULL != err) {
			/* Rolling back will be hard if there is any chance the UNLINK has
			 * been managed by the server, despite a time-out that occured. */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 4. DESTROY each local base */
	if (!err && urlv && *urlv) {
		const guint32 flag_force = (force) ? M2V2_DESTROY_FORCE : 0;

		meta1_urlv_shift_addr(urlv);
		err = m2v2_remote_execute_DESTROY (urlv[0], args->url,
				M2V2_DESTROY_EVENT|flag_force);
		if (!err && urlv[1]) {
			err = m2v2_remote_execute_DESTROY_many(
					urlv+1, args->url, flag_force);
		}
	}

clean_and_exit:
	if (urlv)
		g_strfreev (urlv);
	if (NULL != err)
		return _reply_m2_error(args, err);
	return _reply_nocontent (args);
}

/* CONTAINER action resources ----------------------------------------------- */

static enum http_rc_e
action_m2_container_purge (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_PURGE (args->url, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (NULL != err)
		return _reply_common_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_flush (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_FLUSH (args->url, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (NULL != err)
		return _reply_common_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_dedup (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEDUP (args->url, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (NULL != err)
		return _reply_common_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_touch (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_TOUCHB (args->url, 0, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
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
	const gboolean force = _request_get_flag (args, "force");

	GSList *beans = NULL;
	GError *err = m2v2_json_load_setof_xbean (jargs, &beans);
	if (err) {
		EXTRA_ASSERT(beans == NULL);
		return _reply_format_error (args, err);
	}
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_RAW_ADD (args->url, beans, force, DL());
	}
	err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
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

	PACKER_VOID(_pack) { return m2v2_remote_pack_RAW_DEL (args->url, beans, DL()); }
	err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
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
	const gboolean frozen = OPT("frozen")?TRUE:FALSE;

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
			return m2v2_remote_pack_RAW_SUBST(args->url, beans_new, beans_old,
					frozen, DL());
		}
		err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
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

static enum http_rc_e
_m2_container_snapshot(struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;
	gchar **urlv = NULL;
	gchar **urlv_snapshot = NULL;
	char type[LIMIT_LENGTH_SRVTYPE] = {};
	_get_meta2_realtype(args, type, sizeof(type));
	const char *target_account, *target_container;
	char target_cid[65] = {};
	target_account = oio_url_get(args->url, OIOURL_ACCOUNT);
	target_container = oio_url_get(args->url, OIOURL_USER);
	g_strlcpy(target_cid, oio_url_get(args->url, OIOURL_HEXID),
			sizeof(target_cid));
	err = hc_resolve_reference_service(resolver, args->url, NAME_SRVTYPE_META2,
			&urlv, oio_ext_get_deadline());
	if (!err && (!urlv || !*urlv)) {
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "No service located");
	}
	if (err)
		goto cleanup;

	struct json_object *jaccount = NULL;
	struct json_object *jcontainer = NULL;
	struct json_object *jseq_num = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"account", &jaccount, json_type_string, 1},
		{"container", &jcontainer, json_type_string, 1},
		{"seq_num", &jseq_num, json_type_string, 0},
		{NULL, NULL, 0, 0}
	};

	err = oio_ext_extract_json(jargs, m);
	if (err)
		goto cleanup;

	const gchar *account = json_object_get_string(jaccount);
	const gchar *container = json_object_get_string(jcontainer);
	const gchar *seq_num = jseq_num? json_object_get_string(jseq_num): ".1";
	if(!strcmp(account, target_account) && !strcmp(container, target_container)) {
		err = BADREQ("the snapshot should have a different account or reference");
		goto cleanup;
	}

	oio_url_set(args->url, OIOURL_ACCOUNT, account);
	oio_url_set(args->url, OIOURL_USER, container);
	oio_url_set(args->url, OIOURL_HEXID, NULL);
	err = hc_resolve_reference_service (resolver, args->url,
			NAME_SRVTYPE_META2, &urlv_snapshot, oio_ext_get_deadline());
	if (!err) {
		err = BADREQ("Container already exists");
		goto cleanup;
	}else {
		g_error_free(err);
		err = NULL;
	}

	GError *hook_dir (const char *m1) {
		GError *e = meta1v2_remote_link_service(
				m1, args->url, type, TRUE, &urlv_snapshot,
				oio_ext_get_deadline());
		if (!e && urlv_snapshot && *urlv_snapshot) {
			e = meta1v2_remote_force_reference_service(
				m1, args->url, urlv_snapshot[0], FALSE, TRUE,
				oio_ext_get_deadline());
		}
		if (urlv_snapshot) {
			g_strfreev (urlv_snapshot);
			urlv_snapshot = NULL;
		}
		return e;
	}

	err = _m1_locate_and_action(args->url, hook_dir);
	if (err)
		goto cleanup;

	meta1_urlv_shift_addr(urlv);
	CLIENT_CTX(ctx, args, type, 1);
	GByteArray * _pack(const struct sqlx_name_s *n) {
		return sqlx_pack_SNAPSHOT(n, urlv[0], target_cid, seq_num, DL());
	}

	err = _resolve_meta2(args, CLIENT_PREFER_MASTER, _pack, NULL);
	if(err)
		goto cleanup;

cleanup:

	if(urlv_snapshot)
		g_strfreev(urlv_snapshot);
	if (urlv)
		g_strfreev(urlv);
	return _reply_m2_error(args, err);
}

static enum http_rc_e
_m2_container_create (struct req_args_s *args, struct json_object *jbody)
{
	gchar **properties = NULL;
	GError *err = NULL;
	if (!jbody || json_object_is_type(jbody, json_type_null))
		properties = g_malloc0(sizeof(void*));
	else
		err = KV_read_usersys_properties(jbody, &properties);
	EXTRA_ASSERT((err != NULL) ^ (properties != NULL));
	if (err)
		return _reply_m2_error(args, err);

	err = _m2_container_create_with_properties(
			args, properties, OPT("stgpol"), OPT("verpol"));
	g_strfreev (properties);

	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	if (err && err->code == CODE_CONTAINER_EXISTS) {
		/* We did not create it, thus we cannot _reply_created() */
		g_clear_error(&err);
		return _reply_nocontent(args);
	}
	if (!err || err->code == CODE_FINAL_OK) {
		/* No error means we actually created it. */
		g_clear_error(&err);
		return _reply_created(args);
	}
	return _reply_m2_error (args, err);
}

static void
_bulk_item_result(GString *gresponse,
		const guint i, const char *name,
		const GError *err, gint code_ok)
{
	if (i > 0)
		g_string_append_c(gresponse, ',');
	g_string_append_c(gresponse, '{');
	oio_str_gstring_append_json_pair(gresponse, "name", name);
	g_string_append_c(gresponse, ',');
	if (err)
		_append_status(gresponse, err->code, err->message);
	else
		_append_status(gresponse, code_ok, "ok");
	g_string_append_c(gresponse, '}');
}

static enum http_rc_e
_m2_container_create_many(struct req_args_s *args, struct json_object *jbody)
{
	if (!oio_url_get(args->url, OIOURL_ACCOUNT)
			|| !oio_url_get(args->url, OIOURL_NS))
		return _reply_format_error(args,
				BADREQ("Missing account or namespace"));

	json_object *jarray = NULL;
	if (!json_object_object_get_ex(jbody, "containers", &jarray)
			|| !json_object_is_type(jarray, json_type_array))
		return _reply_format_error(args,
				BADREQ("Invalid array of containers"));

	const guint jarray_len = json_object_array_length(jarray);
	if (jarray_len > proxy_bulk_max_create_many)
		return _reply_too_large(args, NEWERROR(HTTP_CODE_PAYLOAD_TO_LARGE,
					"More than %u requested", proxy_bulk_max_create_many));

	/* A final sanity check on the format of the payload */
	for (guint i = 0; i < jarray_len; i++) {
		struct json_object * jcontent = json_object_array_get_idx(jarray, i);
		if (!json_object_is_type(jcontent, json_type_object))
			return _reply_format_error(args, BADREQ("Invalid content description"));
		struct json_object * jname = NULL;
		if (!json_object_object_get_ex(jcontent, "name", &jname)
				|| !json_object_is_type(jname, json_type_string))
			return _reply_format_error(args, BADREQ("Invalid payload"));
	}

	GString *gresponse = g_string_sized_new(2048);
	g_string_append(gresponse, "{\"containers\":[");
	for (unsigned i= 0; i < jarray_len ; i++) {
		struct json_object * jcontainer = json_object_array_get_idx(jarray, i);

		struct json_object * jname = NULL;
		json_object_object_get_ex(jcontainer, "name", &jname);
		const gchar *name = json_object_get_string(jname);

		gchar **properties = NULL;
		GError *err = KV_read_usersys_properties(jcontainer, &properties);
		EXTRA_ASSERT((err != NULL) ^ (properties != NULL));

		if (err) {
			g_string_free(gresponse, TRUE);
			enum http_rc_e rc = _reply_format_error(args,
					BADREQ("Malformed properties at %d: (%d) %s", i,
						err->code, err->message));
			g_clear_error(&err);
			return rc;
		}

		oio_url_set(args->url, OIOURL_USER, name);
		err = _m2_container_create_with_properties(args, properties,
				OPT("stgpol"), OPT("verpol"));
		g_strfreev(properties);
		_bulk_item_result(gresponse, i, name, err, HTTP_CODE_CREATED);
		if (err) g_clear_error(&err);
	}
	g_string_append(gresponse, "]}");

	return _reply_success_json(args, gresponse);
}

typedef GByteArray* (*list_packer_f) (struct list_params_s *);

static GError * _list_loop (struct req_args_s *args,
		struct list_params_s *in0, struct list_result_s *out0,
		GTree *tree_prefixes, list_packer_f packer) {
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
		if (err) {
			m2v2_list_result_clean (&out);
			break;
		}

		/* Manage the properties */
		gchar **keys = gtree_string_keys (out.props);
		if (keys) {
			for (gchar **pk = keys; *pk; ++pk) {
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
			ctx.marker = in0->marker_start;
			ctx.delimiter = delimiter;
			_filter_list_result(&ctx, out.beans);
			out.beans = NULL;
			count = ctx.count;
			out0->beans = ctx.beans;
		}

		if (in0->maxkeys > 0 &&
				(count + g_tree_nnodes(tree_prefixes)) >= in0->maxkeys) {
			/* enough elements received */
			out0->truncated = out.truncated;
			stop = TRUE;
		} else if (!out.truncated) {
			/* no more elements expected, the meta2 told us */
			out0->truncated = FALSE;
			stop = TRUE;
		} else if (out.truncated && !out0->next_marker) {
			GRID_ERROR("BUG: meta2 must return a pagination marker");
			err = NEWERROR(CODE_PLATFORM_ERROR,
					"BUG in meta2: list truncated but no marker returned");
			stop = TRUE;
		}

		m2v2_list_result_clean (&out);
	}

	return err;
}

enum http_rc_e action_container_snapshot(struct req_args_s *args) {
	return rest_action(args, _m2_container_snapshot);
}

enum http_rc_e action_container_create_many (struct req_args_s *args) {
	return rest_action(args, _m2_container_create_many);
}

enum http_rc_e action_container_create (struct req_args_s *args) {
	return rest_action(args, _m2_container_create);
}

enum http_rc_e action_container_destroy (struct req_args_s *args) {
	return action_m2_container_destroy (args);
}

enum http_rc_e action_container_list (struct req_args_s *args) {
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
	list_in.flag_headers = 1;
	list_in.flag_nodeleted = 1;
	list_in.prefix = OPT("prefix");
	list_in.marker_start = OPT("marker");
	list_in.marker_end = OPT("marker_end");
	if (OPT("deleted"))
		list_in.flag_nodeleted = 0;
	if (OPT("all"))
		list_in.flag_allversion = 1;
	if (oio_str_parse_bool(OPT("properties"), FALSE))
		list_in.flag_properties = 1;
	if (!err)
		err = _max (args, &list_in.maxkeys);
	if (!err) {
		tree_prefixes = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
		m2v2_list_result_init (&list_out);
	}

	if (!err) {
		GByteArray* _pack (struct list_params_s *in) {
			guint32 flags = flag_force_master ? M2V2_FLAG_MASTER : 0;
			if (chunk_id)
				return m2v2_remote_pack_LIST_BY_CHUNKID (args->url, flags,
						in, chunk_id, DL());
			if (content_hash)
				return m2v2_remote_pack_LIST_BY_HEADERHASH (args->url, flags,
						in, content_hash, DL());
			return m2v2_remote_pack_LIST (args->url, flags, in, DL());
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

enum http_rc_e action_container_show (struct req_args_s *args) {
	GError *err = NULL;

	CLIENT_CTX(ctx,args,NAME_SRVTYPE_META2,1);

	PACKER_VOID(_pack) { return sqlx_pack_PROPGET(_u, DL()); }
	err = gridd_request_replicated (&ctx, _pack);
	if (err) {
		client_clean (&ctx);
		return _reply_m2_error (args, err);
	}

	/* TODO(jfs): the 2 next blocks are duplicated from proxy/sqlx_actions.c */

	/* Decode the output of the first service that replied */
	gchar **pairs = NULL;
	for (guint i=0; i<ctx.count && !err && !pairs ;++i) {
		GError *e = ctx.errorv[i];
		GByteArray *gba = ctx.bodyv[i];
		if (e && e->code != CODE_FINAL_OK)
			continue;
		if (gba->data && gba->len)
			err = KV_decode_buffer(gba->data, gba->len, &pairs);
	}

	/* avoid a memleak and ensure a result, even if empty */
	if (err) {
		/* TODO(jfs): maybe a good place for an assert */
		if (pairs) g_strfreev(pairs);
		return _reply_common_error(args, err);
	}
	if (!pairs) {
		pairs = g_malloc0(sizeof(void*));
		GRID_WARN("BUG the request for properties failed without error");
	}

	/* In the reply's headers, we store only the "system" properties, i.e. those
	 * that do not belong to the "user." domain */
	gchar **sys = KV_extract_not_prefixed(pairs, "user.");
	_container_old_props_to_headers (args, sys);
	g_free(sys);

	GString *body = g_string_sized_new(1024);

	/* In the reply's body, we then store only the "user." related properties
	 * without the implicit prefix. For the sake of uniformity, we store these
	 * properties under a json sub-object named "properties" */
	gchar **user = KV_extract_prefixed(pairs, "user.");
	g_string_append_static(body, "{\"properties\":");
	KV_encode_gstr2(body, user);
	g_string_append_c(body, '}');
	g_free(user);

	g_strfreev(pairs);
	client_clean (&ctx);
	return _reply_success_json (args, body);
}

enum http_rc_e action_container_touch (struct req_args_s *args) {
	return rest_action (args, action_m2_container_touch);
}

enum http_rc_e action_container_dedup (struct req_args_s *args) {
	return rest_action (args, action_m2_container_dedup);
}

enum http_rc_e action_container_purge (struct req_args_s *args) {
	return rest_action (args, action_m2_container_purge);
}

enum http_rc_e action_container_flush (struct req_args_s *args) {
	return rest_action (args, action_m2_container_flush);
}

enum http_rc_e action_container_prop_get (struct req_args_s *args) {
	return rest_action (args, action_m2_container_propget);
}

enum http_rc_e action_container_prop_set (struct req_args_s *args) {
	return rest_action (args, action_m2_container_propset);
}

enum http_rc_e action_container_prop_del (struct req_args_s *args) {
	return rest_action (args, action_m2_container_propdel);
}

enum http_rc_e action_container_raw_insert (struct req_args_s *args) {
	return rest_action (args, action_m2_container_raw_insert);
}

enum http_rc_e action_container_raw_update (struct req_args_s *args) {
	return rest_action (args, action_m2_container_raw_update);
}

enum http_rc_e action_container_raw_delete (struct req_args_s *args) {
	return rest_action (args, action_m2_container_raw_delete);
}


/* CONTENT action resource -------------------------------------------------- */

static enum http_rc_e action_m2_content_prepare (struct req_args_s *args,
		struct json_object *jargs) {
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
	PACKER_VOID(_pack) { return m2v2_remote_pack_BEANS (args->url, stgpol, size, 0, DL()); }

retry:
	GRID_TRACE("Content preparation %s", oio_url_get (args->url, OIOURL_WHOLE));
	beans = NULL;
	err = _resolve_meta2 (args, _prefer_slave(), _pack, &beans);

	// Maybe manage autocreation
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					err->code, err->message);
			autocreate = FALSE;
			g_clear_error (&err);
			err = _m2_container_create_with_defaults (args);
			if (!err)
				goto retry;
			if (err->code == CODE_CONTAINER_EXISTS
					|| err->code == CODE_USER_EXISTS) {
				g_clear_error(&err);
				goto retry;
			}
		}
	}

	// Patch the chunk size to ease putting contents with unknown size.
	if (!err) {
		gint64 chunk_size = oio_ns_chunk_size;
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

static GError *_m2_json_spare (struct req_args_s *args,
		struct json_object *jbody, GSList ** out) {
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
		return m2v2_remote_pack_SPARE (args->url, OPT("stgpol"), notin, broken, DL());
	}
	GSList *obeans = NULL;
	err = _resolve_meta2 (args, _prefer_master(), _pack, &obeans);
	_bean_cleanl2 (broken);
	_bean_cleanl2 (notin);
	EXTRA_ASSERT ((err != NULL) ^ (obeans != NULL));
	if (!err)
		*out = obeans;
	else
		_bean_cleanl2 (obeans);
	return err;
}

static enum http_rc_e action_m2_content_spare (struct req_args_s *args,
		struct json_object *jargs) {
	GSList *beans = NULL;
	GError *err = _m2_json_spare (args, jargs, &beans);
	return _reply_beans (args, err, beans);
}

static enum http_rc_e action_m2_content_touch (struct req_args_s *args,
		struct json_object *jargs) {
	(void) jargs;

	if (!oio_url_has_fq_container(args->url))
		return _reply_format_error(args, BADREQ("container unspecified"));
	if (!oio_url_has(args->url, OIOURL_PATH) &&
			!oio_url_has(args->url, OIOURL_CONTENTID))
		return _reply_format_error(args, BADREQ("missing content path of ID"));

	PACKER_VOID(_pack) { return m2v2_remote_pack_TOUCHC (args->url, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_link (struct req_args_s *args,
		struct json_object *jargs) {
	if (!oio_url_has_fq_container(args->url))
		return _reply_m2_error (args, BADREQ("no container identified"));
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

	PACKER_VOID(_pack) { return m2v2_remote_pack_LINK (args->url, DL()); }
	err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propset (struct req_args_s *args,
		struct json_object *jargs) {
	if (CONTENT())
		return _reply_m2_error (args, BADREQ("Content. not allowed in the URL"));

	GSList *beans = NULL;

	if (jargs) {
		gchar **kv = NULL;
		GError *err = KV_read_properties(jargs, &kv, "properties", TRUE);
		if (err)
			return _reply_format_error (args, err);
		for (gchar **p=kv; *p && *(p+1) ;p+=2) {
			struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
			PROPERTIES_set2_key (prop, *p);
			PROPERTIES_set2_value (prop, (guint8*)*(p+1), strlen(*(p+1)));
			PROPERTIES_set2_alias (prop, oio_url_get (args->url, OIOURL_PATH));
			PROPERTIES_set_version (prop, args->version);
			beans = g_slist_prepend (beans, prop);
		}
		g_strfreev(kv);
	}

	guint32 flags = 0;
	if (OPT("flush"))
		flags |= M2V2_FLAG_FLUSH;

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_SET (args->url, flags, beans, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	_bean_cleanl2 (beans);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propdel (struct req_args_s *args,
		struct json_object *jargs) {
	if (!json_object_is_type(jargs, json_type_array))
		return _reply_format_error (args, BADREQ("Array argument expected"));

	gchar **namev = NULL;
	GError *err = STRV_decode_object(jargs, &namev);
	EXTRA_ASSERT((err != NULL) ^ (namev != NULL));
	if (err)
		return _reply_format_error(args, err);

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_DEL (args->url, namev, DL()); }
	err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	g_strfreev(namev);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propget (struct req_args_s *args,
		struct json_object *jargs UNUSED) {
	const guint32 flags = flag_force_master ? M2V2_FLAG_MASTER : 0;

	GSList *beans = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_GET (args->url, flags, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_slave(), _pack, &beans);
	return _reply_properties (args, err, beans);
}

static GError *_m2_json_put (struct req_args_s *args,
		struct json_object *jbody) {
	if (!jbody)
		return BADREQ("Invalid JSON body");

	const gboolean append = _request_get_flag (args, "append");
	const gboolean force = _request_get_flag (args, "force");
	GSList *ibeans = NULL, *obeans = NULL;
	GError *err;

	if (json_object_is_type(jbody, json_type_array)) {
		err = _load_content_from_json_array(args, jbody, &ibeans);
		if (NULL != err) {
			_bean_cleanl2(ibeans);
			return err;
		}
	} else if (json_object_is_type(jbody, json_type_object)) {
		err = _load_content_from_json_object(args, jbody, &ibeans);
		if (NULL != err) {
			_bean_cleanl2(ibeans);
			return err;
		}
	}

	PACKER_VOID(_pack) {
		if (force) return m2v2_remote_pack_OVERWRITE (args->url, ibeans, DL());
		if (append) return m2v2_remote_pack_APPEND (args->url, ibeans, DL());
		return m2v2_remote_pack_PUT (args->url, ibeans, DL());
	}
	err = _resolve_meta2 (args, _prefer_master(), _pack, &obeans);
	_bean_cleanl2 (obeans);
	_bean_cleanl2 (ibeans);
	return err;
}

static enum http_rc_e action_m2_content_create (struct req_args_s *args,
		struct json_object *jbody) {
	gboolean autocreate = _request_get_flag(args, "autocreate");
	GError *err = NULL;
retry:
	err = _m2_json_put (args, jbody);
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation");
			autocreate = FALSE;
			g_clear_error (&err);
			err = _m2_container_create_with_defaults (args);
			if (!err)
				goto retry;
			if (err->code == CODE_CONTAINER_EXISTS
					|| err->code == CODE_USER_EXISTS) {
				g_clear_error(&err);
				goto retry;
			}
		}
	}
	return _reply_m2_error (args, err);
}

static enum http_rc_e _m2_content_update(struct req_args_s *args,
		struct json_object *jbody) {
	GSList *ibeans = NULL, *obeans = NULL;
	GError *err = _load_content_from_json_array(args, jbody, &ibeans);
	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_UPDATE(args->url, ibeans, DL());
		}
		err = _resolve_meta2(args, _prefer_master(), _pack, &obeans);
	}
	_bean_cleanl2(obeans);
	_bean_cleanl2(ibeans);
	return _reply_m2_error (args, err);
}


/* CONTENT resources ------------------------------------------------------- */

/*
CONTAINER{{
POST /v3.0/{NS}/content/create
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

}}CONTAINER
*/
enum http_rc_e action_content_put (struct req_args_s *args) {
	return rest_action(args, action_m2_content_create);
}

enum http_rc_e action_content_update(struct req_args_s *args) {
	return rest_action(args, _m2_content_update);
}

enum http_rc_e action_content_truncate(struct req_args_s *args) {
	GError *err = NULL;
	const char *size_str = OPT("size");
	char *end = NULL;
	gint64 size = 0;
	if (!size_str ||
			(!(size = g_ascii_strtoll(size_str, &end, 10)) && end == size_str))
		err = BADREQ("Missing/invalid size parameter: %s", OPT("size"));
	else {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_TRUNC(args->url, size, DL());
		}
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL);
	}
	return _reply_m2_error(args, err);
}

enum http_rc_e action_content_prepare (struct req_args_s *args) {
	return rest_action (args, action_m2_content_prepare);
}

enum http_rc_e action_content_show (struct req_args_s *args) {
	GSList *beans = NULL;
	guint32 flags = flag_force_master ? M2V2_FLAG_MASTER : 0;
	PACKER_VOID(_pack) { return m2v2_remote_pack_GET (args->url, flags, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_slave(), _pack, &beans);
	return _reply_simplified_beans (args, err, beans, TRUE);
}

enum http_rc_e action_content_delete (struct req_args_s *args) {
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEL (args->url, DL()); }
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
_m2_content_delete_many (struct req_args_s *args, struct json_object * jbody) {
	json_object *jarray = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEL (args->url, DL()); }

	if (!oio_url_has_fq_container(args->url))
		return _reply_format_error(args,
				BADREQ("Missing url argument"));

	if (!json_object_object_get_ex(jbody, "contents", &jarray)
			|| !json_object_is_type(jarray, json_type_array))
		return _reply_format_error(args,
				BADREQ("Invalid array of contents"));

	guint jarray_len = json_object_array_length(jarray);
	if (jarray_len < 1)
		return _reply_format_error(args,
				BADREQ("At least one element is needed"));

	if (jarray_len > proxy_bulk_max_create_many)
		return _reply_too_large(args, NEWERROR(HTTP_CODE_PAYLOAD_TO_LARGE,
				"Payload Too Large"));

	/* A final sanity check on the format of the payload */
	for (guint i = 0; i < jarray_len; i++) {
		struct json_object * jcontent = json_object_array_get_idx(jarray, i);
		if (!json_object_is_type(jcontent, json_type_object))
			return _reply_format_error(args, BADREQ("Invalid content description"));
		struct json_object * jname = NULL;
		if (!json_object_object_get_ex(jcontent, "name", &jname)
				|| !json_object_is_type(jname, json_type_string))
			return _reply_format_error(args, BADREQ("Invalid content name"));
	}

	GString *gresponse = g_string_sized_new(2048);
	g_string_append(gresponse, "{\"contents\":[");
	for (guint i = 0; i < jarray_len; i++) {
		struct json_object * jcontent = json_object_array_get_idx(jarray, i);

		struct json_object * jname = NULL;
		json_object_object_get_ex(jcontent, "name", &jname);
		const gchar *name = json_object_get_string(jname);

		oio_url_set(args->url, OIOURL_PATH, name);
		GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
		_bulk_item_result(gresponse, i, name, err, HTTP_CODE_NO_CONTENT);
		if (err) g_clear_error(&err);
	}

	g_string_append(gresponse, "]}");
	return _reply_success_json(args, gresponse);
}

enum http_rc_e action_content_delete_many (struct req_args_s *args) {
	return rest_action(args, _m2_content_delete_many);
}

enum http_rc_e action_content_touch (struct req_args_s *args) {
	return rest_action (args, action_m2_content_touch);
}

enum http_rc_e action_content_link (struct req_args_s *args) {
	return rest_action (args, action_m2_content_link);
}

enum http_rc_e action_content_spare (struct req_args_s *args) {
	return rest_action (args, action_m2_content_spare);
}

enum http_rc_e action_content_prop_get (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propget);
}

enum http_rc_e action_content_prop_set (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propset);
}

enum http_rc_e action_content_prop_del (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propdel);
}

enum http_rc_e action_content_drain(struct req_args_s *args) {
	PACKER_VOID(_pack) {return m2v2_remote_pack_DRAIN(args->url, DL());}
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL);
	return _reply_m2_error(args, err);
}

enum http_rc_e action_content_copy (struct req_args_s *args) {
	const gchar *target = g_tree_lookup (args->rq->tree_headers, "destination");
	const gchar *_err = NULL;

	if (!target)
		return _reply_format_error(args, BADREQ("Missing target header"));

	struct oio_url_s *target_url = oio_url_init(target);
	if (!target_url || !oio_url_check(target_url, NULL, &_err))
		return _reply_format_error(args, BADREQ("Invalid %s in target header", _err));

	// Check the namespace and container match between both URLs
	if (!oio_url_has(target_url, OIOURL_HEXID)
			|| !oio_url_has(target_url, OIOURL_NS)
			|| !oio_url_has(target_url, OIOURL_PATH)) {
		oio_url_pclean(&target_url);
		return _reply_format_error(args, BADREQ("Invalid source URL"));
	}
	if (!oio_url_has(args->url, OIOURL_HEXID)
			|| !oio_url_has(args->url, OIOURL_NS)
			|| strcmp(oio_url_get(target_url, OIOURL_NS), oio_url_get(args->url, OIOURL_NS))
			|| strcmp(oio_url_get(target_url, OIOURL_HEXID), oio_url_get(args->url, OIOURL_HEXID))) {
		oio_url_pclean(&target_url);
		return _reply_format_error(args, BADREQ("Invalid source/target URL"));
	}

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_COPY (target_url, oio_url_get(args->url, OIOURL_PATH), DL());
	}
	GError *err = _resolve_meta2 (args, _prefer_master(), _pack, NULL);
	oio_url_pclean(&target_url);
	if (err && CODE_IS_NOTFOUND(err->code))
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}
