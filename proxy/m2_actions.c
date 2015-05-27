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

#include <meta2v2/meta2_utils_json.h>
#include <meta2v2/autogen.h>
#include <meta2v2/generic.h>

static void
_json_dump_all_beans (GString * gstr, GSList * beans)
{
	g_string_append_c (gstr, '[');
	meta2_json_dump_all_beans (gstr, beans);
	g_string_append_c (gstr, ']');
}

static enum http_rc_e
_reply_m2_error (struct req_args_s *args, GError * err)
{
	if (!err)
		return _reply_success_json (args, NULL);

	g_prefix_error (&err, "M2 error: ");
	if (err->code == CODE_BAD_REQUEST)
		return _reply_format_error (args, err);
	else if (err->code == CODE_CONTAINER_NOTFOUND || err->code == CODE_CONTENT_NOTFOUND)
		return _reply_notfound_error (args, err);
	else if (err->code == CODE_CONTAINER_NOTEMPTY)
		return _reply_conflict_error (args, err);
	else
		return _reply_system_error (args, err);
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
	if (prefixes && *prefixes) {
		g_string_append (gstr, "\"prefixes\":[");
		first = TRUE;
		for (gchar **pp=prefixes; pp && *pp ;++pp) {
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
	for (GSList *la = aliases; la ; la=la->next) {

		if (!first)
			g_string_append_c(gstr, ',');
		first = FALSE;

		struct bean_ALIASES_s *a = la->data;
		// Look for the matching header
		// TODO optimize this with a tree or a hashmap
		struct bean_CONTENTS_HEADERS_s *h = NULL;
		for (GSList *lh=headers; lh ; lh=lh->next) {
			if (0 == metautils_gba_cmp(CONTENTS_HEADERS_get_id(lh->data), ALIASES_get_content_id(a))) {
				h = lh->data;
				break;
			}
		}

		g_string_append_c(gstr, '{');
		g_string_append_printf(gstr,
				"\"name\":\"%s\",\"ver\":%"G_GINT64_FORMAT","
				"\"ctime\":%"G_GINT64_FORMAT",\"system_metadata\":\"%s\","
				"\"deleted\":%s",
				ALIASES_get_alias(a)->str,
				ALIASES_get_version(a),
				ALIASES_get_ctime(a),
				ALIASES_get_mdsys(a)->str,
				ALIASES_get_deleted(a) ? "true" : "false");

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

static GError *
_jbody_to_beans (GSList ** beans, struct json_object *jbody, const gchar * k)
{
	if (!json_object_is_type (jbody, json_type_object))
		return BADREQ ("Body is not a valid JSON object");
	struct json_object *jbeans = NULL;
	if (!json_object_object_get_ex (jbody, k, &jbeans))
		return BADREQ ("Section %s not found in JSON body", k);
	if (!json_object_is_type (jbeans, json_type_object))
		return BADREQ ("Section %s from body is not a JSON object", k);
	return meta2_json_load_setof_beans (jbeans, beans);
}

static void
_populate_headers_with_header (struct req_args_s *args, struct bean_CONTENTS_HEADERS_s *header)
{
	if (!header)
		return;
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-length",
			g_strdup_printf("%"G_GINT64_FORMAT, CONTENTS_HEADERS_get_size(header)));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-policy",
			g_strdup(CONTENTS_HEADERS_get_policy(header)->str));
	args->rp->add_header_gstr(PROXYD_HEADER_PREFIX "content-meta-hash",
			metautils_gba_to_hexgstr(NULL, CONTENTS_HEADERS_get_hash(header)));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-hash-method",
			g_strdup("md5"));
}

static void
_populate_headers_with_alias (struct req_args_s *args, struct bean_ALIASES_s *alias)
{
	if (!alias)
		return;

	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-name",
			g_strdup(ALIASES_get_alias(alias)->str));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-version",
			g_strdup_printf("%"G_GINT64_FORMAT, ALIASES_get_version(alias)));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-deleted",
			g_strdup(ALIASES_get_deleted(alias) ? "True" : "False"));
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-ctime",
			g_strdup_printf("%"G_GINT64_FORMAT, ALIASES_get_ctime(alias)));

	gpointer _k, _v;
	GHashTableIter iter;
	GHashTable *md = metadata_unpack_string (ALIASES_get_mdsys(alias)->str, NULL);
	if (md) {
		g_hash_table_iter_init (&iter, md);
		while (g_hash_table_iter_next (&iter, &_k, &_v)) {
			const char *k = _k, *v = _v;
			if (!g_ascii_strcasecmp (k, "mime-type")) {
				args->rp->add_header (PROXYD_HEADER_PREFIX "content-meta-mime-type", g_strdup(v));
			} else if (!g_ascii_strcasecmp (k, "chunk-method")) {
				args->rp->add_header (PROXYD_HEADER_PREFIX "content-meta-chunk-method", g_strdup(v));
			} else if (!g_ascii_strcasecmp (k, "storage-policy") ||
					!g_ascii_strcasecmp(k, "creation-date")) {
				continue;
			} else {
				gchar *rk = g_strdup_printf (PROXYD_HEADER_PREFIX "content-meta-X-%s", k);
				args->rp->add_header (rk, g_strdup(v));
				g_free (rk);
			}
		}
		g_hash_table_destroy (md);
	}
}

static enum http_rc_e
_reply_simplified_beans (struct req_args_s *args, GError *err, GSList *beans, gboolean body)
{
	if (err)
		return _reply_m2_error(args, err);

	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	gboolean first = TRUE;
	GString *gstr = body ? g_string_new ("[") : NULL;

	beans = g_slist_sort(beans, _bean_compare_kind);

	for (GSList *l0=beans; l0 ;l0=l0->next) {
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
		if (&descr_struct_CHUNKS != DESCR(l0->data))
			continue;
		struct bean_CHUNKS_s *chunk = l0->data;
		// TODO FIXME argl, inner loop
		for (GSList *l1=beans; body && l1 ;l1=l1->next) {
			if (&descr_struct_CONTENTS != DESCR(l1->data))
				continue;
			struct bean_CONTENTS_s *content = l1->data;
			if (!g_ascii_strcasecmp(CHUNKS_get_id(chunk)->str, CONTENTS_get_chunk_id(content)->str)) {
				// Separator
				if (!first)
					g_string_append_c (gstr, ',');
				first = FALSE;
				// Serialize the chunk
				g_string_append_printf (gstr,
						"{\"url\":\"%s\", \"pos\":\"%s\", \"size\":%"G_GINT64_FORMAT", \"hash\":\"",
						CHUNKS_get_id (chunk)->str, CONTENTS_get_position (content)->str,
						CHUNKS_get_size (chunk));
				metautils_gba_to_hexgstr (gstr, CHUNKS_get_hash (chunk));
				g_string_append (gstr, "\"}");
				break;
			}
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
_load_simplified_chunks (struct req_args_s *args, struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;

	if (!json_object_is_type(jbody, json_type_array))
		return BADREQ ("JSON: Not an array");
	if (json_object_array_length(jbody) <= 0)
		return BADREQ ("JSON: Empty array");

	// Load the beans
	for (int i=json_object_array_length(jbody); i>0 && !err ;i--) {
		GRID_TRACE("JSON: parsing chunk at %i", i-1);
		struct json_object *jchunk = json_object_array_get_idx (jbody, i-1);
		if (!json_object_is_type(jchunk, json_type_object)) {
			err = BADREQ("JSON: expected object for chunk");
			continue;
		}
		struct json_object *jurl = NULL, *jpos = NULL, *jsize = NULL, *jhash = NULL;
		(void) json_object_object_get_ex(jchunk, "url", &jurl);
		(void) json_object_object_get_ex(jchunk, "pos", &jpos);
		(void) json_object_object_get_ex(jchunk, "size", &jsize);
		(void) json_object_object_get_ex(jchunk, "hash", &jhash);
		if (!jurl || !jpos || !jsize || !jhash) {
			err = BADREQ("JSON: missing chunk's field");
		} else if (!json_object_is_type(jurl, json_type_string)
				|| !json_object_is_type(jpos, json_type_string)
				|| !json_object_is_type(jsize, json_type_int)
				|| !json_object_is_type(jhash, json_type_string)) {
			err = BADREQ("JSON: invalid chunk's field");
		} else {
			GByteArray *h = metautils_gba_from_hexstring(json_object_get_string(jhash));
			struct timespec ts;
			clock_gettime(CLOCK_REALTIME_COARSE, &ts);
			struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
			CHUNKS_set2_id (chunk, json_object_get_string(jurl));
			CHUNKS_set_hash (chunk, h);
			CHUNKS_set_size (chunk, json_object_get_int64(jsize));
			CHUNKS_set_ctime (chunk, ts.tv_sec);
			struct bean_CONTENTS_s *content = _bean_create(&descr_struct_CONTENTS);
			CONTENTS_set2_position (content, json_object_get_string(jpos));
			CONTENTS_set2_chunk_id (content, json_object_get_string(jurl));
			CONTENTS_set2_content_id (content, (guint8*)"0", 1);

			beans = g_slist_prepend(beans, chunk);
			beans = g_slist_prepend(beans, content);
			g_byte_array_free (h, TRUE);
		}
	}

	if (!err) {
		gchar *s;

		struct bean_CONTENTS_HEADERS_s *header = _bean_create (&descr_struct_CONTENTS_HEADERS);
		beans = g_slist_prepend (beans, header);
		CONTENTS_HEADERS_set2_id (header, (guint8*)"0", 1);
		if (NULL != (s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-policy")))
			CONTENTS_HEADERS_set2_policy (header, s);
		if (NULL != (s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-hash"))) {
			GByteArray *h = metautils_gba_from_hexstring(s);
			CONTENTS_HEADERS_set_hash (header, h);
			g_byte_array_free(h, TRUE);
		}
		if (NULL != (s = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-length")))
			CONTENTS_HEADERS_set_size (header, g_ascii_strtoll(s, NULL, 10));
		else
			err = BADREQ("Header: missing content length");
	}

	if (!err) {
		struct bean_ALIASES_s *alias = _bean_create (&descr_struct_ALIASES);
		beans = g_slist_prepend (beans, alias);
		ALIASES_set2_alias (alias, PATH());
		ALIASES_set2_content_id (alias, (guint8*)"0", 1);

		gchar *s;
		GString *mdsys = ALIASES_get_mdsys(alias);
		// Extract the content-type
		if (NULL != (s = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-type"))) {
			if (mdsys->len > 0)
				g_string_append_c (mdsys, ';');
			g_string_append_printf (mdsys, "mime-type=%s", s);
		} else if (NULL != (s = g_tree_lookup (args->rq->tree_headers, "content-type"))) {
			if (mdsys->len > 0)
				g_string_append_c (mdsys, ';');
			g_string_append_printf (mdsys, "mime-type=%s", s);
		}
		// Extract the chunking method
		if (NULL != (s = g_tree_lookup (args->rq->tree_headers, PROXYD_HEADER_PREFIX "content-meta-chunk-method"))) {
			if (mdsys->len > 0)
				g_string_append_c (mdsys, ';');
			g_string_append_printf (mdsys, "chunk-method=%s", s);
		}

		gboolean run_headers (gpointer k, gpointer v, gpointer u) {
			(void)u;
			if (!g_str_has_prefix((gchar*)k, PROXYD_HEADER_PREFIX "content-meta-x-"))
				return FALSE;
			const gchar *rk = ((gchar*)k) + sizeof(PROXYD_HEADER_PREFIX "content-meta-x-");
			struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES); 
			PROPERTIES_set_alias (prop, ALIASES_get_alias(alias));
			PROPERTIES_set_alias_version (prop, 0);
			PROPERTIES_set2_key (prop, rk);
			PROPERTIES_set2_value (prop, (guint8*)v, strlen((gchar*)v));
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

static void
_purify_header (gchar *k)
{
	for (gchar *p = k; *p ;++p) {
		if (*p != '-' && !g_ascii_isalnum(*p))
			*p = '-';
	}
}

static void
_container_props_to_headers (struct req_args_s *args, GSList *props)
{
	for (GSList *l = props; l ;l=l->next) {
		const struct key_value_pair_s *kv = l->data;
		const gchar *pk = kv->key;
		GByteArray *gv = kv->value;
		gchar *v = g_strndup((gchar*)(gv->data), gv->len);
		if (!g_ascii_strcasecmp(pk, "sys.container_name")) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-name", v);
		} else if (!g_ascii_strcasecmp(pk, "sys.container_size")) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-size", v);
		} else if (!g_ascii_strcasecmp(pk, "sys.m2vers")) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-seq", v);
		} else if (!g_ascii_strcasecmp(pk, "sys.namespace")) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "container-meta-ns", v);
		} else if (g_str_has_prefix(pk, "sys.")) {
			gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-sys-%s", pk + sizeof("sys.") - 1);
			_purify_header(k);
			args->rp->add_header(k, v);
			g_free(k);
		} else if (g_str_has_prefix(pk, "user.")) {
			gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-user-%s", pk + sizeof("user.") - 1);
			_purify_header(k);
			args->rp->add_header(k, v);
			g_free(k);
		} else {
			gchar *k = g_strdup_printf(PROXYD_HEADER_PREFIX "container-meta-X-%s", pk);
			_purify_header(k);
			args->rp->add_header(k, v);
			g_free(k);
		}
	}
}

static enum http_rc_e
_reply_properties (struct req_args_s *args, GError * err, GSList * beans)
{
	if (err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error (args, err);
		if (err->code == CODE_CONTENT_NOTFOUND)
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

static gint64
_max (struct req_args_s *args)
{
	const char *s = OPT("max");
	return s ? atoi(s) : 0;
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
				g_tree_insert(ctx->prefixes, g_strndup(name, p-name+1), GINT_TO_POINTER(1));
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

/** @todo TODO FIXME ensure we get a correct result if we have to loop
 * toward several meta2 servers */
static enum http_rc_e
action_m2_container_list (struct req_args_s *args)
{
	struct list_result_s list_out = {NULL,NULL,FALSE};
	struct list_params_s list_in;
	GError *err = NULL;
	guint count = 0;
	char delimiter = 0;
	GTree *tree_prefixes = NULL;

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		GError *e = NULL;
		struct list_params_s in = list_in;
		struct list_result_s out = {NULL,NULL,FALSE};
		while (grid_main_is_running()) {
			// patch the input parameters
			if (list_in.maxkeys > 0)
				in.maxkeys = list_in.maxkeys - (count + g_tree_nnodes(tree_prefixes));
			if (out.next_marker)
				in.marker_start = out.next_marker;

			// Action
			if (NULL != (e = m2v2_remote_execute_LIST (m2->host, args->url, &in, &out)))
				return e;

			// transmit the output
			metautils_str_reuse (&list_out.next_marker, out.next_marker);
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

	memset(&list_in, 0, sizeof(list_in));
	list_in.flag_headers = ~0;
	list_in.flag_nodeleted = ~0;
	list_in.snapshot = OPT("snapshot");
	list_in.prefix = OPT("prefix");
	list_in.marker_start = OPT("marker");
	list_in.marker_end = OPT("marker_end");
	list_in.maxkeys = _max (args);
	delimiter = _delimiter (args);
	if (OPT("deleted"))
		list_in.flag_nodeleted = 0;
	if (OPT("all"))
		list_in.flag_allversion = ~0;

	tree_prefixes = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);

	if (!err) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "list-truncated",
				g_strdup(list_out.truncated ? "true" : "false"));
		if (list_out.next_marker) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "list-marker",
					g_strdup(list_out.next_marker));
		}
	}

	gchar **tab = NULL;
	if (!err)
		tab = gtree_string_keys (tree_prefixes);
	enum http_rc_e rc = _reply_aliases (args, err, list_out.beans, tab);
	if (tab)
		g_free (tab);
	g_tree_destroy (tree_prefixes);
	metautils_str_clean (&list_out.next_marker);
	return rc;
}

static enum http_rc_e
action_m2_container_check (struct req_args_s *args)
{
	GError *err = NULL;
	gchar *bn = g_strdup_printf("1@%s", hc_url_get(args->url, HCURL_HEXID));
	struct sqlx_name_s n = {NULL,NULL,NULL};
	n.ns = NS();
	n.base = bn;
	n.type = NAME_SRVTYPE_META2;

	GByteArray **bodies = NULL;
	GByteArray* packer () { return sqlx_pack_PROPGET (&n, NULL); }
	err = _gbav_request (n.type, 0, args->url, packer, NULL, &bodies);
	g_free(bn);
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

	_container_props_to_headers (args, pairs);
	g_slist_free_full (pairs, (GDestroyNotify)key_value_pair_clean);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_create (struct req_args_s *args)
{
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		struct m2v2_create_params_s param = {
			hc_url_get_option_value (args->url, "stgpol"),
			hc_url_get_option_value (args->url, "verpol"),
			FALSE
		};
		return m2v2_remote_execute_CREATE (m2->host, args->url, &param);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (err && err->code == CODE_CONTAINER_NOTFOUND)	// The reference doesn't exist
		return _reply_forbidden_error (args, err);
	if (err && err->code == CODE_CONTAINER_EXISTS)
		return _reply_created(args);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_container_destroy (struct req_args_s *args)
{
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_DESTROY (m2->host, args->url, 0);
	}

	GError *err;
	if (NULL != (err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook)))
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
		return m2v2_remote_execute_PURGE (m2->host, args->url, FALSE,
				m2_timeout_all, &beans);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
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
		GError *e =
			m2v2_remote_execute_DEDUP (m2->host, args->url, 0, &msg);
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
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (NULL != err) {
		g_string_free (gstr, TRUE);
		g_prefix_error (&err, "M2 error: ");
		if (err->code == CODE_CONTAINER_NOTFOUND)
			return _reply_notfound_error (args, err);
		return _reply_system_error (args, err);
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
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (NULL != err) {
		if (err->code == CODE_CONTAINER_NOTFOUND)
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
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (NULL != err) {
		return _reply_m2_error (args, err);
	}
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
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (NULL != err) {
		return _reply_m2_error (args, err);
	}
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
	if (!err) err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	_bean_cleanl2 (beans_old);
	_bean_cleanl2 (beans_new);

	if (NULL != err)
		return _reply_m2_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_propget (struct req_args_s *args, struct json_object *jargs)
{
	path_matching_set_variable(args->matchings[0], g_strdup("TYPE=meta2"));
	path_matching_set_variable(args->matchings[0], g_strdup("SEQ=1"));
	return action_sqlx_propget(args, jargs);
}

static enum http_rc_e
action_m2_container_propset (struct req_args_s *args, struct json_object *jargs)
{
	path_matching_set_variable(args->matchings[0], g_strdup("TYPE=meta2"));
	path_matching_set_variable(args->matchings[0], g_strdup("SEQ=1"));
	return action_sqlx_propset(args, jargs);
}

static enum http_rc_e
action_m2_container_propdel (struct req_args_s *args, struct json_object *jargs)
{
	path_matching_set_variable(args->matchings[0], g_strdup("TYPE=meta2"));
	path_matching_set_variable(args->matchings[0], g_strdup("SEQ=1"));
	return action_sqlx_propdel(args, jargs);
}

static enum http_rc_e
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

static enum http_rc_e
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

static enum http_rc_e
action_m2_container_action (struct req_args_s *args)
{
	struct sub_action_s actions[] = {
		{"Purge", action_m2_container_purge},
		{"Dedup", action_m2_container_dedup},
		{"Touch", action_m2_container_touch},

		{"RawInsert", action_m2_container_raw_insert},
		{"RawDelete", action_m2_container_raw_delete},
		{"RawUpdate", action_m2_container_raw_update},

		{"GetProperties", action_m2_container_propget},
		{"SetProperties", action_m2_container_propset},
		{"DelProperties", action_m2_container_propdel},

		{"SetStoragePolicy", action_m2_container_stgpol},
		{"SetVersioning", action_m2_container_setvers},

		{NULL,NULL}
	};
	return abstract_action (args, actions);
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

	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_BEANS (m2->host, args->url, stgpol, size, 0, &beans);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);

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
_m2_json_spare (struct hc_url_s *url, struct json_object *jbody, GSList ** out)
{
	GSList *notin = NULL, *broken = NULL;
	GError *err;

	if (NULL != (err = _jbody_to_beans (&notin, jbody, "notin"))
		|| NULL != (err = _jbody_to_beans (&broken, jbody, "broken"))) {
		_bean_cleanl2 (notin);
		_bean_cleanl2 (broken);
		return err;
	}

	GSList *obeans = NULL;
	GError *hook (struct meta1_service_url_s * m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_SPARE (m2->host, url,
				hc_url_get_option_value (url, "stgpol"),
				notin, broken, &obeans);
	}
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, url, hook);
	_bean_cleanl2 (broken);
	_bean_cleanl2 (notin);
	g_assert ((err != NULL) ^ (obeans != NULL));
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
	GError *err = _m2_json_spare (args->url, jargs, &beans);
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
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (err && err->code == CODE_CONTAINER_NOTFOUND)
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_stgpol (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type (jargs, json_type_string))
		return _reply_format_error (args, BADREQ ("the storage policy must be a string"));
		
	const gchar *stgpol = json_object_get_string (jargs);
	if (!stgpol)
		return _reply_format_error (args, BADREQ ("missing policy"));

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_STGPOL (m2->host, args->url, stgpol, NULL);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	if (err && err->code == CODE_CONTAINER_NOTFOUND)
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_propset (struct req_args_s *args, struct json_object *jargs)
{
	if (!json_object_is_type(jargs, json_type_object))
		return _reply_format_error (args, BADREQ("Object argument expected"));

	// TODO manage the version of the content
	gint64 version = 0;

	// build the set of properties
	GSList *beans = NULL;
	json_object_object_foreach(jargs,sk,jv) {
		struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
		PROPERTIES_set2_key (prop, sk);
		if (json_object_is_type (jv, json_type_null)) {
			PROPERTIES_set2_value (prop, (guint8*)"", 0);
		} else {
			const char *sv = json_object_get_string (jv);
			PROPERTIES_set2_value (prop, (guint8*)sv, strlen(sv));
		}
		PROPERTIES_set2_alias (prop, hc_url_get (args->url, HCURL_PATH));
		PROPERTIES_set_alias_version (prop, version);
		beans = g_slist_prepend (beans, prop);
	}

	guint32 flags = 0;
	if (OPT("flush"))
		flags |= M2V2_FLAG_FLUSH;

	if (!beans)
		return _reply_format_error (args, BADREQ("No property provided"));

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_PROP_SET (m2->host, args->url, flags, beans);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	return _reply_properties (args, err, beans);
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
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	g_slist_free_full (names, g_free0);
	if (err && err->code == CODE_CONTAINER_NOTFOUND)
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
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	return _reply_properties (args, err, beans);
}

static enum http_rc_e
action_m2_content_action (struct req_args_s *args)
{
	struct sub_action_s actions[] = {
		{"Beans", action_m2_content_beans},
		{"Spare", action_m2_content_spare},
		{"Touch", action_m2_content_touch},
		{"SetStoragePolicy", action_m2_content_stgpol},
		{"GetProperties", action_m2_content_propget},
		{"SetProperties", action_m2_content_propset},
		{"DelProperties", action_m2_content_propdel},
		{NULL,NULL}
	};
	return abstract_action (args, actions);
}

/* CONTENT resources ------------------------------------------------------- */

static enum http_rc_e
action_m2_content_copy (struct req_args_s *args)
{
	const gchar *target = g_tree_lookup (args->rq->tree_headers, "destination");
	if (!target)
		return _reply_format_error(args, BADREQ("Missing target header"));

	struct hc_url_s *target_url = hc_url_oldinit(target);
	if (!target_url)
		return _reply_format_error(args, BADREQ("Invalid URL in target header"));

	// Check the namespace and container match between both URLs
	if (!hc_url_has(target_url, HCURL_HEXID)
			|| !hc_url_has(target_url, HCURL_NS)
			|| !hc_url_has(target_url, HCURL_PATH)
			|| !hc_url_has(args->url, HCURL_HEXID)
			|| !hc_url_has(args->url, HCURL_NS)
			|| strcmp(hc_url_get(target_url, HCURL_HEXID), hc_url_get(args->url, HCURL_HEXID))
			|| strcmp(hc_url_get(target_url, HCURL_HEXID), hc_url_get(args->url, HCURL_HEXID))) {
		hc_url_pclean(&target_url);
		return _reply_format_error(args, BADREQ("Invalid source/target URL"));
	}

	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_COPY (m2->host, target_url, hc_url_get(args->url, HCURL_PATH));
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	hc_url_pclean(&target_url);
	if (err && err->code == CODE_CONTAINER_NOTFOUND)
		return _reply_forbidden_error (args, err);
	return _reply_m2_error (args, err);
}

static GError *
_m2_json_put (struct req_args_s *args, struct json_object *jbody)
{
	const char *mode = g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PREFIX "action-mode");
	if (!mode)
		mode = "put";
	GSList *ibeans = NULL;
	GError *err;

	if (NULL != (err = _load_simplified_chunks (args, jbody, &ibeans))) {
		_bean_cleanl2 (ibeans);
		return err;
	}

	GError *hook (struct meta1_service_url_s * m2, gboolean *next) {
		(void) next;
		GSList *obeans = NULL;
		GError *e = NULL;
		if (!g_ascii_strcasecmp(mode, "force"))
			e = m2v2_remote_execute_OVERWRITE (m2->host, args->url, ibeans);
		else if (!g_ascii_strcasecmp(mode, "append"))
			e = m2v2_remote_execute_APPEND (m2->host, args->url, ibeans, &obeans);
		else
			e = m2v2_remote_execute_PUT (m2->host, args->url, ibeans, &obeans);
		_bean_cleanl2 (obeans);
		return e;
	}
	err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	_bean_cleanl2 (ibeans);
	return err;
}

static enum http_rc_e
action_m2_content_put (struct req_args_s *args)
{
	struct json_tokener *parser;
	struct json_object *jbody;
	GError *err;

	parser = json_tokener_new ();
	jbody = json_tokener_parse_ex (parser, (char *) args->rq->body->data,
		args->rq->body->len);
	err = _m2_json_put (args, jbody);
	json_object_put (jbody);
	json_tokener_free (parser);

	return _reply_beans (args, err, NULL);
}

static enum http_rc_e
action_m2_content_delete (struct req_args_s *args)
{
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_DEL (m2->host, args->url);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	return _reply_simplified_beans (args, err, beans, TRUE);
}

static enum http_rc_e
_m2_content_get (struct req_args_s *args, gboolean body)
{
	GSList *beans = NULL;
	GError *hook (struct meta1_service_url_s *m2, gboolean *next) {
		(void) next;
		return m2v2_remote_execute_GET (m2->host, args->url, 0, &beans);
	}
	GError *err = _resolve_service_and_do (NAME_SRVTYPE_META2, 0, args->url, hook);
	return _reply_simplified_beans (args, err, beans, body);
}

static enum http_rc_e
action_m2_content_check (struct req_args_s *args)
{
	return _m2_content_get (args, FALSE);
}

static enum http_rc_e
action_m2_content_get (struct req_args_s *args)
{
	return _m2_content_get (args, TRUE);
}

