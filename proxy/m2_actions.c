/*
OpenIO SDS proxy
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2020 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021-2023 OVH SAS

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
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_bean.h>
#include <meta2v2/autogen.h>

#include "common.h"
#include "actions.h"

#define META2_LISTING_DEFAULT_LIMIT 1000
#define META2_LISTING_MAX_LIMIT 10000


static gchar*
_resolve_service_id(const char *service_id)
{
	gchar *out = oio_lb_resolve_service_id(service_id, FALSE);
	if (!out)
		out = g_strdup(service_id);
	GRID_TRACE("Service [%s] resolved to [%s]", service_id, out);
	return out;
}

static GError *
_load_redirect_shard(gchar *redirect_message, gpointer *predirect_shard)
{
	GError *err = NULL;
	json_object *jredirect_message = NULL, *jredirect = NULL;
	gpointer redirect_shard = NULL;
	err = JSON_parse_buffer((const guint8*)redirect_message,
			strlen(redirect_message), &jredirect_message);
	if (err)
		return err;
	struct oio_ext_json_mapping_s mapping[] = {
		{"redirect",  &jredirect, json_type_object, 1},
		{NULL, NULL, 0, 0}
	};
	err = oio_ext_extract_json(jredirect_message, mapping);
	if (err) {
		json_object_put(jredirect_message);
		return err;
	}
	err = m2v2_json_load_single_shard_range(jredirect, &redirect_shard);
	json_object_put(jredirect_message);
	if (err)
		return err;
	*predirect_shard = redirect_shard;
	return NULL;
}

static GError *
_resolve_meta2(struct req_args_s *args, enum proxy_preference_e how,
		request_packer_f pack, gpointer out, client_on_reply decoder)
{
	GSList **out_list = NULL;

	CLIENT_CTX2(ctx, args, NAME_SRVTYPE_META2, 1, NULL, how, decoder, out);
	if (!ctx.decoder && out) {
		out_list = (GSList **) out;
		*out_list = NULL;
	}
	/* Check if the client application wants performance data. */
	gboolean req_perfdata_enabled =
		g_tree_lookup(args->rq->tree_headers, PROXYD_HEADER_PERFDATA) != NULL;
	oio_ext_enable_perfdata(req_perfdata_enabled);

	GError *err = NULL;
	struct oio_url_s *original_url = args->url;
	struct oio_url_s *redirect_url = NULL;
	gpointer redirect_shard = NULL;

	if (!(args->cache_control & SHARDING_NO_CACHE)) {
		redirect_shard = shard_resolver_get_cached(shard_resolver,
				original_url);
		if (redirect_shard) {
			redirect_url = oio_url_dup(args->url);
			oio_url_unset(redirect_url, OIOURL_ACCOUNT);
			oio_url_unset(redirect_url, OIOURL_USER);
			gchar *redirect_cid = g_string_free(metautils_gba_to_hexgstr(NULL,
				SHARD_RANGE_get_cid(redirect_shard)), FALSE);
			oio_url_set(redirect_url, OIOURL_HEXID, redirect_cid);
			g_free(redirect_cid);
			args->url = redirect_url;
			client_clean(&ctx);
			client_init(&ctx, args, NAME_SRVTYPE_META2, 1, NULL, how,
					decoder, out);
			oio_ext_set_is_shard_redirection(TRUE);
		}
	}

	guint nb_redirects = 0;
	while (TRUE) {
		if (nb_redirects > 2) {
			err = NEWERROR(CODE_TOOMANY_REDIRECT,
				"Too many redirections (to shards)");
			break;
		}

		err = gridd_request_replicated_with_retry(args, &ctx, pack);

		/* Extract root_hexid */
		const gchar* root_hexid = oio_ext_get_root_hexid();
		oio_url_set(ctx.url, OIOURL_ROOT_HEXID, root_hexid);

		if (!err) {
			break;
		}

		if (err->code == CODE_REDIRECT_SHARD) { // Redirection requested
			if (redirect_url) {
				g_error_free(err);
				err = SYSERR("Shard redirect to another shard");
				break;
			}

			// Redirect to the shard having the object manipulated
			nb_redirects++;
			GError *redirect_err = _load_redirect_shard(err->message,
					&redirect_shard);
			g_clear_error(&err);
			if (redirect_err) {
				err = SYSERR("Failed to decode redirect message: (%d) %s",
						redirect_err->code, redirect_err->message);
				g_error_free(redirect_err);
				break;
			}
			if (!(args->cache_control & SHARDING_NO_STORE)) {
				shard_resolver_store(shard_resolver, original_url,
						redirect_shard);
			}

			redirect_url = oio_url_dup(args->url);
			oio_url_unset(redirect_url, OIOURL_ACCOUNT);
			oio_url_unset(redirect_url, OIOURL_USER);
			gchar *cid = g_string_free(metautils_gba_to_hexgstr(NULL,
				SHARD_RANGE_get_cid(redirect_shard)), FALSE);
			oio_url_set(redirect_url, OIOURL_HEXID, cid);
			g_free(cid);
			args->url = redirect_url;
			client_clean(&ctx);
			client_init(&ctx, args, NAME_SRVTYPE_META2, 1, NULL, how,
					decoder, out);
			oio_ext_set_is_shard_redirection(TRUE);
			continue;
		}
		if (redirect_url) { // Current request is a redirection
			if (err->code == CODE_CONTAINER_FROZEN
					|| err->code == CODE_CONTAINER_NOTFOUND
					|| err->code == CODE_USER_NOTFOUND) {
				// Maybe the shard is being deleted,
				// decache and retry on the root container
				shard_resolver_forget(shard_resolver, original_url,
						redirect_shard);
				args->url = original_url;
				oio_url_clean(redirect_url);
				redirect_url = NULL;
				_bean_clean(redirect_shard);
				redirect_shard = NULL;
				client_clean(&ctx);
				client_init(&ctx, args, NAME_SRVTYPE_META2, 1, NULL, how,
						decoder, out);
				oio_ext_set_is_shard_redirection(FALSE);
				g_clear_error(&err);
				continue;
			}
		} else if (err->code == CODE_CONTAINER_NOTFOUND
				|| err->code == CODE_USER_NOTFOUND) {
			// Container no longer exists.
			// If it had any cached shards, let's forget about them.
			shard_resolver_forget_root(shard_resolver, original_url);
		}
		break;
	}

	if (err) {
		GRID_DEBUG("M2V2 call failed: %d %s", err->code, err->message);
	} else if (out_list) {
		EXTRA_ASSERT(ctx.bodyv != NULL);
		for (guint i=0; i<ctx.count ;++i) {
			GError *e = ctx.errorv[i];
			GByteArray *b = ctx.bodyv[i];
			if (e && e->code != CODE_FINAL_OK)
				continue;
			if (b && b->data && b->len) {
				GSList *l = bean_sequence_unmarshall (b->data, b->len);
				if (l) {
					*out_list = metautils_gslist_precat (*out_list, l);
				}
			}
		}
	}
	if (req_perfdata_enabled) {
		gchar *perfdata = g_strdup_printf(
				"resolve=%"G_GINT64_FORMAT",meta2=%"G_GINT64_FORMAT,
				ctx.resolve_duration, ctx.request_duration);
		args->rp->add_header(PROXYD_HEADER_PERFDATA, perfdata);
	}

	oio_ext_set_is_shard_redirection(FALSE);
	oio_ext_enable_perfdata(FALSE);
	oio_ext_set_root_hexid(NULL);
	args->url = original_url;
	oio_url_clean(redirect_url);
	_bean_clean(redirect_shard);
	client_clean(&ctx);
	return err;
}

static void
_json_dump_all_beans (GString * gstr, GSList * beans)
{
	g_string_append_c (gstr, '{');
	meta2_json_dump_all_beans(gstr, beans);
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
	if (err->code == SQLITE_CONSTRAINT) {
		if (strstr(err->message, OBJ_LOCK_ABORT_PATTERN) != NULL) {
			// For triggers
			return	_reply_forbidden_error(args, err);
		}
		else {
			// For NULL properties
			return _reply_format_error(args, err);
		}
	}
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

/** @private */
struct location_and_score_s {
	oio_location_t location;
	oio_weight_t put_score;
	oio_weight_t get_score;
};

static struct location_and_score_s
_score_from_chunk_id (const char *id)
{
	gchar *key = NULL, *type = NULL, *netloc = NULL;
	struct location_and_score_s res = {};

	oio_parse_chunk_url(id, &type, &netloc, NULL);
	key = oio_make_service_key(ns_name, type, netloc);

	struct oio_lb_item_s *item = oio_lb_world__get_item(lb_world, key);
	if (item) {
		res.put_score = item->put_weight;
		res.get_score = item->get_weight;
		res.location = item->location;
	}

	g_free(item);
	g_free(key);
	g_free(netloc);
	g_free(type);
	return res;
}

static gchar*
_real_url_from_chunk_id (const char *id)
{
	gchar *out = NULL;
	gchar *addr = NULL, *type = NULL, *netloc = NULL;
	oio_parse_chunk_url(id, &type, &netloc, NULL);


	if (oio_ext_has_upgrade_to_tls()) {
		addr = oio_lb_resolve_service_id(netloc, TRUE);

		if (addr) {
			out = g_strdup_printf("https://%s/%s",
					addr, id + strlen("http://") + strlen(netloc) + 1);
		}
	}

	/* allow fallback */
	if (!addr) {
		addr = _resolve_service_id(netloc);
		out = g_strdup_printf("http://%s/%s",
				addr, id + strlen("http://") + strlen(netloc) + 1);
	}

	g_free(addr);
	g_free(netloc);
	g_free(type);
	return out;
}

#define _remap(score,lo,hi) (lo + ((score * (hi - lo)) / 100))

static oio_weight_t
_patch_score(const oio_weight_t score,
		const oio_location_t location, const oio_location_t reference)
{
	if (score <= 0 || !location || !reference)
		return score;
	switch (oio_location_proximity(location, reference)) {
		case OIO_LOC_PROX_VOLUME:
		case OIO_LOC_PROX_HOST:
			return _remap(score, 91, 100);
		case OIO_LOC_PROX_RACK:
			return _remap(score, 51, 80);
		case OIO_LOC_PROX_ROOM:
			return _remap(score, 11, 50);
		case OIO_LOC_PROX_REGION:
			return _remap(score, 5, 10);
		case OIO_LOC_PROX_NONE:
		default:
			return _remap(score, 1, 4);
	}
}

static void
_serialize_chunk(struct bean_CHUNKS_s *chunk, GString *gstr,
		const oio_location_t location)
{
	/* Unfortunately, we have two different formats for chunks.
	 * See encode_chunk() function in meta2_utils_json_out.c. */
	const char *chunk_id = CHUNKS_get_id(chunk)->str;
	struct location_and_score_s srv = _score_from_chunk_id(chunk_id);

	/* The caller asks us to patch the services so that the client will
	 * prefer those locals. We do this with a mangling of the score */
#ifdef HAVE_EXTRA_DEBUG
	const oio_weight_t pre_put_score = srv.put_score;
	const oio_weight_t pre_get_score = srv.get_score;
#endif
	srv.put_score = _patch_score(srv.put_score, srv.location, location);
	srv.get_score = _patch_score(srv.get_score, srv.location, location);
#ifdef HAVE_EXTRA_DEBUG
	if (pre_put_score != srv.put_score) {
		GRID_TRACE("Put score changed for %s: %d -> %d", chunk_id, pre_put_score, srv.put_score);
	}
	if (pre_get_score != srv.get_score) {
		GRID_TRACE("Get score changed for %s: %d -> %d", chunk_id, pre_get_score, srv.get_score);
	}
#endif

	g_string_append_printf(gstr, "{\"url\":\"%s\"", chunk_id);

	gchar *real_url = _real_url_from_chunk_id(chunk_id);
	if (real_url) {
		g_string_append_printf(gstr, ",\"real_url\":\"%s\"", real_url);
		g_free(real_url);
	}

	g_string_append_printf(gstr, ",\"pos\":\"%s\"", CHUNKS_get_position(chunk)->str);
	g_string_append_printf(gstr, ",\"size\":%"G_GINT64_FORMAT, CHUNKS_get_size(chunk));
	g_string_append_static(gstr, ",\"hash\":\"");
	metautils_gba_to_hexgstr(gstr, CHUNKS_get_hash(chunk));
	g_string_append_printf(gstr, "\",\"score\":%d}", srv.get_score);
}

static void
_serialize_property(struct bean_PROPERTIES_s *prop, GString *gstr)
{
	oio_str_gstring_append_json_quote(gstr, PROPERTIES_get_key(prop)->str);
	g_string_append_c(gstr, ':');
	g_string_append_c(gstr, '"');
	GByteArray *val = PROPERTIES_get_value(prop);
	oio_str_gstring_append_json_blob(gstr, (gchar*)val->data, val->len);
	g_string_append_c(gstr, '"');
}

static void
_dump_json_aliases_and_headers(struct oio_url_s *url, GString *gstr,
		GSList *aliases, GTree *headers, GTree *props, GTree *chunks)
{
	/* Url will can be altered (if <chunks> is not NULL), so let's use a copy */
	struct oio_url_s *object_url = oio_url_dup(url);
	const gchar *policy = NULL;
	const oio_location_t _loca = oio_proxy_local_patch ? location_num : 0;

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

		GString *chunk_key = metautils_gba_to_hexgstr(NULL,
				ALIASES_get_content(a));
		GSList *chunk_list = g_tree_lookup(chunks, chunk_key->str);
		g_string_free(chunk_key, TRUE);

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
		OIO_JSON_append_gba(gstr, "id", ALIASES_get_content(a));
		// TODO(adu) Remove this when all clients will only use `id`
		g_string_append_c(gstr, ',');
		OIO_JSON_append_gba(gstr, "content", ALIASES_get_content(a));

		if (h) {
			g_string_append_c(gstr, ',');
			OIO_JSON_append_gstr(gstr, "policy",
					CONTENTS_HEADERS_get_policy(h));
			g_string_append_c(gstr, ',');
			OIO_JSON_append_gstr(gstr, "chunk-method",
					CONTENTS_HEADERS_get_chunk_method(h));
			g_string_append_c(gstr, ',');
			OIO_JSON_append_gba(gstr, "hash",
					CONTENTS_HEADERS_get_hash(h));
			g_string_append_c(gstr, ',');
			OIO_JSON_append_int(gstr, "size",
					CONTENTS_HEADERS_get_size(h));
			g_string_append_c(gstr, ',');
			OIO_JSON_append_gstr(gstr, "mime-type",
					CONTENTS_HEADERS_get_mime_type(h));
		} else {
			g_string_append_c(gstr, ',');
			OIO_JSON_append_null(gstr, "policy");
			g_string_append_c(gstr, ',');
			OIO_JSON_append_null(gstr, "chunk-method");
			g_string_append_c(gstr, ',');
			OIO_JSON_append_null(gstr, "hash");
			g_string_append_c(gstr, ',');
			OIO_JSON_append_null(gstr, "size");
			g_string_append_c(gstr, ',');
			if (ALIASES_get_deleted(a)) {
				OIO_JSON_append_str(gstr, "mime-type",
						OIO_DELETE_MARKER_CONTENT_TYPE);
			} else {
				OIO_JSON_append_null(gstr, "mime-type");
			}
		}

		if (prop_list) {
			g_string_append_static(gstr, ",\"properties\":{");
			gboolean inner_first = TRUE;
			for (GSList *prop = prop_list;
					prop && prop->data;
					prop = prop->next) {
				struct bean_PROPERTIES_s *bprop = prop->data;
				COMA(gstr, inner_first);
				_serialize_property(bprop, gstr);
			}
			g_string_append_c(gstr, '}');
		}

		if (chunk_list) {
			/* PATH and VERSION need to be set to use to be able to
			 * call <m2v2_extend_chunk_url> */
			oio_url_set(object_url, OIOURL_PATH, ALIASES_get_alias(a)->str);
			gchar strver[24];
			g_snprintf(strver, sizeof(strver), "%"G_GINT64_FORMAT,
					ALIASES_get_version(a));
			oio_url_set(object_url, OIOURL_VERSION, strver);
			if (h) {
				policy = CONTENTS_HEADERS_get_policy(h)->str;
			} else {
				/* No header, no possibility to compute chunks */
				continue;
			}

			g_string_append_static(gstr, ",\"chunks\":[");
			gboolean inner_first = TRUE;
			for (GSList *chunk = chunk_list;
					chunk && chunk->data;
					chunk = chunk->next) {
				struct bean_CHUNKS_s *bchunk = chunk->data;
				GError *err = m2v2_extend_chunk_url(object_url, policy, bchunk);
				if (err) {
					GRID_WARN("Failed to extend chunk url: (%d) (%s)",
							err->code, err->message);
					g_clear_error(&err);
					continue;
				}
				COMA(gstr, inner_first);
				_serialize_chunk(bchunk, gstr, _loca);
			}
			g_string_append_c(gstr, ']');
		}
		g_string_append_c(gstr, '}');
	}
	g_string_append_c (gstr, ']');

	oio_url_clean(object_url);
}

static void
_dump_json_beans (struct oio_url_s *url, GString *gstr, GSList *beans)
{
	GSList *aliases = NULL;
	GTree *headers = g_tree_new ((GCompareFunc)metautils_gba_cmp);
	GTree *props = g_tree_new_full((GCompareDataFunc)metautils_strcmp3,
			NULL, g_free, NULL);
	GTree *chunks = g_tree_new_full((GCompareDataFunc)metautils_strcmp3,
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
		} else if (DESCR(l->data) == &descr_struct_CHUNKS) {
			/* <chunks> is a GTree of GLists. There is one GList per object.
			 * The key used to discriminate a list for an object is built from
			 * the content.
			 */
			GString *key_string = metautils_gba_to_hexgstr(NULL,
					CHUNKS_get_content(l->data));
			/* A gchar* is needed because g_tree_destroy() will free it (and is
			 * not able to free the GString).
			 */
			gchar *key = g_string_free(key_string, FALSE);
			GSList *val = g_tree_lookup(chunks, key);
			val = g_slist_prepend(val, l->data);
			g_tree_replace(chunks, key, val);
		}
	}

	_dump_json_aliases_and_headers(url, gstr, aliases, headers, props, chunks);

	gboolean _cleaner(gpointer key UNUSED,
			gpointer val, gpointer data UNUSED)
	{
		g_slist_free(val);
		return FALSE;
	}
	g_tree_foreach(props, _cleaner, NULL);
	g_tree_destroy(props);
	g_tree_foreach(chunks, _cleaner, NULL);
	g_tree_destroy(chunks);

	g_slist_free(aliases);
	g_tree_destroy(headers);
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
	g_string_append_c(gstr, '{');
	_dump_json_prefixes (gstr, tree_prefixes);
	g_string_append_c(gstr, ',');
	_dump_json_properties (gstr, out->props);
	g_string_append_c(gstr, ',');
	_dump_json_beans (args->url, gstr, out->beans);
	g_string_append_c(gstr, '}');

	return _reply_success_json (args, gstr);
}

static enum http_rc_e
_reply_beans (struct req_args_s *args, GError * err, GSList * beans)
{
	if (err)
		return _reply_m2_error (args, err);

	GString *gstr = g_string_sized_new (2048);
	_json_dump_all_beans(gstr, beans);
	_bean_cleanl2 (beans);
	return _reply_success_json (args, gstr);
}

static void
_populate_headers_with_header (struct req_args_s *args,
		struct bean_CONTENTS_HEADERS_s *header)
{
	if (!header)
		return;

	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-size",
			g_strdup_printf("%"G_GINT64_FORMAT, CONTENTS_HEADERS_get_size(header)));
	// TODO(adu) Remove this when all clients will only use `content-meta-size`
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
	args->rp->add_header(PROXYD_HEADER_PREFIX "content-meta-mtime",
			g_strdup_printf("%"G_GINT64_FORMAT, ALIASES_get_mtime(alias)));
}

static enum http_rc_e
_reply_simplified_beans_ext(struct req_args_s *args, GError *err,
		GSList *beans, gboolean legacy_format)
{
	const oio_location_t _loca = oio_proxy_local_patch ? location_num : 0;

	/* version_id will be "(null)" if not passed in request. We will
	 * rewrite the whole "tail" later when we have more information. */
	args->rp->access_tail("hexid:%s\tversion_id:%s",
			oio_url_get(args->url, OIOURL_HEXID),
			oio_url_get(args->url, OIOURL_VERSION));

	if (err)
		return _reply_m2_error(args, err);

	struct bean_ALIASES_s *alias = NULL;
	struct bean_CONTENTS_HEADERS_s *header = NULL;
	gboolean first = TRUE, first_prop = TRUE;
	const gchar *policy = NULL;
	GError *chunk_err = NULL;

	GString *gstr, *props_gstr = NULL;
	if (!legacy_format)
		props_gstr = g_string_sized_new(1024);

	GString *chunks_gstr = g_string_sized_new(2048);
	g_string_append_c(chunks_gstr, '[');

	beans = g_slist_sort(beans, _bean_compare_kind);

	for (GSList *l0=beans; l0; l0=l0->next) {
		if (!l0->data)
			continue;

		if (&descr_struct_CHUNKS == DESCR(l0->data)) {
			if (!first)
				g_string_append_c(chunks_gstr, ',');
			first = FALSE;

			struct bean_CHUNKS_s *chunk = l0->data;
			GError *err2 = m2v2_extend_chunk_url(args->url, policy, chunk);
			if (err2) {
				// Discard the previous error
				g_clear_error(&chunk_err);
				chunk_err = err2;
			}
			_serialize_chunk(chunk, chunks_gstr, _loca);
		}
		else if (&descr_struct_ALIASES == DESCR(l0->data)) {
			alias = l0->data;
			gchar strver[24];
			g_snprintf(strver, sizeof(strver), "%"G_GINT64_FORMAT,
					ALIASES_get_version(alias));
			oio_url_set(args->url, OIOURL_VERSION, strver);
			if (ALIASES_get_deleted(alias) &&
					!oio_str_parse_bool(OPT("deleted"), FALSE)) {
				g_string_free(chunks_gstr, TRUE);
				_bean_cleanl2(beans);
				/* This branch is supposed to be executed before the branch
				 * above (because of the way the list is sorted) so this
				 * error should be NULL. If it is not, no harm, just a small
				 * memory leak. */
				EXTRA_ASSERT(chunk_err == NULL);
				return _reply_notfound_error(args,
						NEWERROR(CODE_CONTENT_DELETED, "Alias deleted"));
			}
			if (!oio_url_has(args->url, OIOURL_PATH)) {
				oio_url_set(args->url, OIOURL_PATH,
						ALIASES_get_alias(alias)->str);
			}
		}
		else if (&descr_struct_CONTENTS_HEADERS == DESCR(l0->data)) {
			header = l0->data;
			policy = CONTENTS_HEADERS_get_policy(header)->str;
		}
		else if (&descr_struct_PROPERTIES == DESCR(l0->data)) {
			struct bean_PROPERTIES_s *prop = l0->data;
			if (legacy_format) {
				gchar *k = g_strdup_printf(
						PROXYD_HEADER_PREFIX "content-meta-%s",
						PROPERTIES_get_key(prop)->str);
				GByteArray *v = PROPERTIES_get_value(prop);
				g_byte_array_append(v, (guint8*)"", 1);  // Ensure nul-terminated
				args->rp->add_header(k,
						g_uri_escape_string((gchar*)v->data, NULL, FALSE));
				g_free (k);
			} else {
				if (!first_prop)
					g_string_append_c(props_gstr, ',');
				first_prop = FALSE;
				_serialize_property(prop, props_gstr);
			}
		}
	}
	g_string_append_c(chunks_gstr, ']');

	gstr = chunks_gstr;
	if (!legacy_format) {
		g_string_prepend(gstr, "{\"chunks\":");
		g_string_append(gstr, ",\"properties\":{");
		g_string_append_len(gstr, props_gstr->str, props_gstr->len);
		g_string_append(gstr, "}");
		g_string_free(props_gstr, TRUE);
		g_string_append_c(gstr, '}');
	}

	// Not set all the header
	_populate_headers_with_header (args, header);
	_populate_headers_with_alias (args, alias);

	if (chunk_err) {
		GRID_WARN("Some chunk URLs may have an invalid format: %s (reqid=%s)",
				chunk_err->message, oio_ext_get_reqid());
		g_clear_error(&chunk_err);
	}
	_bean_cleanl2 (beans);

	args->rp->access_tail("hexid:%s\tversion_id:%s",
			oio_url_get(args->url, OIOURL_HEXID),
			oio_url_get(args->url, OIOURL_VERSION));
	return _reply_success_json (args, gstr);
}

static enum http_rc_e
_reply_simplified_beans_legacy(struct req_args_s *args, GError *err,
		GSList *beans)
{
	return _reply_simplified_beans_ext(args, err, beans, TRUE);
}

static enum http_rc_e
_reply_simplified_beans(struct req_args_s *args, GError *err, GSList *beans)
{
	return _reply_simplified_beans_ext(args, err, beans, FALSE);
}

static GError *
_get_hash(const char *s, GByteArray **out)
{
	*out = NULL;
	GByteArray *hash = metautils_gba_from_hexstring(s);
	if (!hash)
		return BADREQ("JSON: invalid hash: not hexa: '%s'", s);

	const gssize len = hash->len;
	if (len != g_checksum_type_get_length(G_CHECKSUM_MD5)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA256)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA512)
			&& len != g_checksum_type_get_length(G_CHECKSUM_SHA1)) {
		metautils_gba_clean(hash);
		return BADREQ("JSON: invalid hash: invalid length");
	}

	*out = hash;
	return NULL;
}

static GError *
_load_simplified_chunks(struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;

	if (!json_object_is_type(jbody, json_type_array))
		return BADREQ("JSON: Not an array");

	gint64 now = oio_ext_real_time() / G_TIME_SPAN_SECOND;

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
		err = oio_ext_extract_json(json_object_array_get_idx(jbody, i-1), m);
		if (err) break;

		GByteArray *hash = NULL;
		if (!(err = _get_hash(json_object_get_string(jhash), &hash))) {
			struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
			CHUNKS_set2_id(chunk, json_object_get_string(jurl));
			CHUNKS_set_hash(chunk, hash);
			CHUNKS_set_size(chunk, json_object_get_int64(jsize));
			CHUNKS_set_ctime(chunk, now);
			CHUNKS_set2_position(chunk, json_object_get_string(jpos));
			CHUNKS_set2_content(chunk, (guint8*)"0", 1);
			beans = g_slist_prepend(beans, chunk);
		}
		metautils_gba_clean(hash);
	}

	if (err)
		_bean_cleanl2(beans);
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

	header = _bean_create(&descr_struct_CONTENTS_HEADERS);
	beans = g_slist_prepend(beans, header);
	CONTENTS_HEADERS_set2_id(header, (guint8 *) "00", 2);
	/* dummy (yet valid) content ID (must be hexa) */

	do {
		gchar *s = g_tree_lookup(args->rq->tree_headers,
								 PROXYD_HEADER_PREFIX "content-meta-policy");
		if (oio_str_is_set(s))
			CONTENTS_HEADERS_set2_policy(header, s);
	} while (0);

	if (!err) { // Content ID
		gchar *s = g_tree_lookup(args->rq->tree_headers,
								 PROXYD_HEADER_PREFIX "content-meta-id");
		if (NULL != s) {
			GByteArray *hash = metautils_gba_from_hexstring(s);
			if (!hash)
				err = BADREQ("Invalid content ID (not hexa)");
			else {
				oio_url_set(args->url, OIOURL_CONTENTID, s);
				CONTENTS_HEADERS_set_id(header, hash);
				/* JFS: this is clean to have uniform CONTENT ID among all
				 * the beans, but it is a bit useless since this requires more
				 * bytes on the network and can be done in the meta2 server */
				for (GSList *l=beans; l ;l=l->next) {
					if (DESCR(l->data) != &descr_struct_CHUNKS)
						continue;
					CHUNKS_set_content(l->data, hash);
				}
				metautils_gba_clean(hash);
			}
		}
	}

	if (!err) { // Content hash
		gchar *s = g_tree_lookup(args->rq->tree_headers,
								 PROXYD_HEADER_PREFIX "content-meta-hash");
		if (NULL != s) {
			GByteArray *hash = NULL;
			if (!(err = _get_hash(s, &hash)))
				CONTENTS_HEADERS_set_hash(header, hash);
			if (hash)
				metautils_gba_clean(hash);
		}
	}

	if (!err) { // Content size
		gchar *s = g_tree_lookup(args->rq->tree_headers,
				PROXYD_HEADER_PREFIX "content-meta-size");
		if (!s) {
			// TODO(adu) Remove this when all clients will only use `content-meta-size`
			s = g_tree_lookup(args->rq->tree_headers,
					PROXYD_HEADER_PREFIX "content-meta-length");
			if (oio_str_is_set(s)) {
				GRID_DEBUG("Client is using the deprecated %s header "
						"(replaced by %s)",
						PROXYD_HEADER_PREFIX "content-meta-length",
						PROXYD_HEADER_PREFIX "content-meta-size");
			}
		}
		if (!s) {
			err = BADREQ("Header: missing content size");
		} else {
			gint64 s64 = 0;
			if (!oio_str_is_number(s, &s64))
				err = BADREQ("Header: bad content size");
			else
				CONTENTS_HEADERS_set_size(header, s64);
		}
	}

	if (!err) { // Content-Type
		gchar *s = g_tree_lookup(args->rq->tree_headers,
						  PROXYD_HEADER_PREFIX "content-meta-mime-type");
		if (s)
			CONTENTS_HEADERS_set2_mime_type(header, s);
	}

	if (!err) { // Chunking method
		gchar *s = g_tree_lookup(args->rq->tree_headers,
						   PROXYD_HEADER_PREFIX "content-meta-chunk-method");
		if (s)
			CONTENTS_HEADERS_set2_chunk_method(header, s);
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
				{
					PROPERTIES_set2_alias(l->data, oio_url_get(args->url, OIOURL_PATH));
				}
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
		_serialize_property(bean, gs);
	}
	for (int i=0; i<2 ;++i) g_string_append_c(gs, '}');

	_bean_cleanl2 (beans);
	return _reply_success_json (args, gs);
}

/* CONTAINER resources ------------------------------------------------------ */

static const char *
_delimiter (struct req_args_s *args)
{
	const char *s = OPT("delimiter");
	return s;
}

static GError *
_max(struct req_args_s *args, gint64 *pmax)
{
	const char *s = OPT("max");
	if (!s) {
		*pmax = META2_LISTING_DEFAULT_LIMIT;
		return NULL;
	}

	if (!oio_str_is_number(s, pmax))
		return BADREQ("Invalid max number of items");
	if (*pmax <= 0)
		*pmax = META2_LISTING_DEFAULT_LIMIT;
	else
		*pmax = MIN(META2_LISTING_MAX_LIMIT, *pmax);
	return NULL;
}

struct filter_ctx_s
{
	GSList *beans;
	GTree *prefixes;
	guint count; // aliases in <beans>
	const char *prefix;
	const char *marker;
	const char *delimiter;
};

static void
_filter_list_result(struct filter_ctx_s *ctx, GSList *l)
{
	void forget(GSList *p) {
		if (p->data)
			_bean_clean(p->data);
		g_slist_free1(p);
	}
	void prepend(GSList *p) {
		p->next = ctx->beans;
		ctx->beans = p;
	}

	gsize prefix_len = ctx->prefix ? strlen(ctx->prefix) : 0;
	for (GSList *tmp; l; l = tmp) {
		tmp = l->next;
		l->next = NULL;

		if (!l->data) {
			forget (l);
			continue;
		}
		if (DESCR(l->data) == &descr_struct_CONTENTS_HEADERS ||
				DESCR(l->data) == &descr_struct_PROPERTIES ||
				DESCR(l->data) == &descr_struct_CHUNKS) {
			prepend (l);
			continue;
		}
		if (DESCR(l->data) != &descr_struct_ALIASES) {
			forget (l);
			continue;
		}

		const char *name = ALIASES_get_alias(l->data)->str;
		if (ctx->delimiter && *(ctx->delimiter)) {
			const char *p = strstr(name + prefix_len, ctx->delimiter);
			if (p) {
				int len_delimiter = strlen(ctx->delimiter);
				// We must not respond a prefix equal to the marker.
				if (!ctx->marker ||
						strncmp(name, ctx->marker, (p - name + len_delimiter))) {
					gchar *prefix = g_strndup(name, (p - name + len_delimiter));
					// Use replace (vs insert) to be sure prefix stays valid
					g_tree_replace(ctx->prefixes, prefix, GINT_TO_POINTER(1));
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

	/* JFS: don't lookup for default verpol and stgpol, we must leave them unset
	 * so that they will follow the default values of the namespace and (later)
	 * of the account. This is how we do NOW, by letting the meta2 find the best
	 * value when necessary. */
	struct m2v2_create_params_s param = {
			container_stgpol, container_verpol, NULL, props, FALSE
	};

	GError *err = NULL;
	GByteArray *_pack(const struct sqlx_name_s *_u UNUSED,
			const gchar **headers) {
		return m2v2_remote_pack_CREATE(args->url, &param, headers, DL());
	}

retry:
	GRID_TRACE("Container creation %s", oio_url_get (args->url, OIOURL_WHOLE));

	/* Prevent the use of old peers
	 * if the container has already existed
	 * and is still in the cache */
	CLIENT_CTX(ctx, args, NAME_SRVTYPE_META2, 1);
	cache_flush_user(args, &ctx);

	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	if (err && CODE_IS_NOTFOUND(err->code)) {
		if (autocreate) {
			GRID_DEBUG("Resource not found, autocreation: (%d) %s",
					   err->code, err->message);
			autocreate = FALSE; /* autocreate just once */
			g_clear_error (&err);
			GError *hook_dir (const char *m1) {
				gchar **urlv = NULL;
				GError *e = meta1v2_remote_link_service (
						m1, args->url, NAME_SRVTYPE_META2, FALSE, TRUE, &urlv,
						oio_ext_get_deadline());
				if (!e && urlv && *urlv) {
					/* Explicitly feeding the meta1 avoids a subsequent
					   call to meta1 to locate the meta2 */
					hc_resolver_tell (resolver, args->url, NAME_SRVTYPE_META2,
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

static void
_re_enable (struct req_args_s *args)
{
	PACKER_VOID (_pack) { return sqlx_pack_ENABLE (_u, DL()); }
	GError *e = _resolve_meta2(args, CLIENT_PREFER_MASTER, _pack, NULL, NULL);
	if (e && e->code == CODE_CONTAINER_ENABLED)
		g_clear_error(&e);
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
	CLIENT_CTX2(ctx, args, NAME_SRVTYPE_META2, 1, NULL, CLIENT_PREFER_MASTER,
			NULL, NULL);
	NAME2CONST(n, ctx.name);

	/* 0. Pre-loads the locations of the container. We will need this at the
	 * destroy step. The decache helps working on recent information */
	hc_decache_reference_service (resolver, args->url, n.type);
	err = hc_resolve_reference_service (resolver, args->url, n.type, &urlv,
			oio_ext_get_deadline());
	if (!err && (!urlv || !*urlv))
		err = NEWERROR(CODE_CONTAINER_NOTFOUND, "No service located");

	/* 1. FREEZE the base to avoid writings during the operation */
	if (!err) {
		PACKER_VOID(_pack) { return sqlx_pack_FREEZE(_u, DL()); }
		err = _resolve_meta2(args, CLIENT_PREFER_MASTER, _pack, NULL, NULL);
		if (err != NULL && err->code == CODE_CONTAINER_FROZEN) {
			g_clear_error(&err);
		} else if (err != NULL && CODE_IS_NETWORK_ERROR(err->code)) {
			/* rollback! There are chances the request made a timeout
			 * but was actually managed by the server. */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 2. Check the base is empty. */
	if (!err && !force) {
		PACKER_VOID(_pack) { return m2v2_remote_pack_ISEMPTY(args->url, DL()); }
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
		if (err != NULL) {
			/* rollback! */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 3. UNLINK the base from the directory. */
	if (!err) {
		GError * _unlink (const char * m1) {
			return meta1v2_remote_unlink_service(
					m1, args->url, n.type, oio_ext_get_deadline());
		}
		err = _m1_locate_and_action (args->url, _unlink);
		if (err != NULL) {
			/* Rolling back will be hard if there is any chance the UNLINK has
			 * been managed by the server, despite a time-out that occurred. */
			_re_enable (args);
			goto clean_and_exit;
		}
	}

	/* 4. DESTROY each local base */
	if (!err && urlv && *urlv) {
		const guint32 flag_force = (force) ? M2V2_DESTROY_FORCE : 0;

		meta1_urlv_shift_addr(urlv);
		/* Execute the first destroy on the master
		 * so that the delete event is sent from the master. */
		sort_services(&ctx, urlv);
		err = m2v2_remote_execute_DESTROY(urlv[0], args->url,
				M2V2_DESTROY_EVENT|flag_force);
		if (err != NULL) {
			/* rollback! */
			struct meta1_service_url_s m1u;
			m1u.seq = 1;
			g_strlcpy(m1u.srvtype, n.type, LIMIT_LENGTH_SRVTYPE);
			gchar *hosts = g_strjoinv(OIO_CSV_SEP, urlv);
			g_strlcpy(m1u.host, hosts, 256);
			g_free(hosts);
			m1u.args[0] = 0;
			GError * _link (const char * m1) {
				gchar *packed = meta1_pack_url(&m1u);
				GError *e = meta1v2_remote_force_reference_service(
						m1, args->url, packed, FALSE, FALSE,
						oio_ext_get_deadline());
				g_free(packed);
				return e;
			}
			GError *_err = _m1_locate_and_action(args->url, _link);
			if (_err) {
				GRID_ERROR("Failed to re-link the meta2 services for %s: "
						"(%d) %s", oio_url_get(args->url, OIOURL_HEXID),
						_err->code, _err->message);
				g_error_free(_err);
			}
			_re_enable(args);
			goto clean_and_exit;
		} else if (urlv[1]) {
			err = m2v2_remote_execute_DESTROY_many(urlv+1, args->url,
					flag_force);
		}
	}

clean_and_exit:
	/* Whatever happened, decache anything related to that current user */
	cache_flush_user(args, &ctx);

	if (urlv)
		g_strfreev (urlv);
	if (err != NULL)
		return _reply_m2_error(args, err);
	return _reply_nocontent (args);
}

/* CONTAINER action resources ----------------------------------------------- */

static enum http_rc_e
action_m2_container_purge (struct req_args_s *args, struct json_object *j UNUSED)
{
	GError *err = NULL;
	const char *maxvers_str = OPT("maxvers");
	if (maxvers_str && !oio_str_is_number(maxvers_str, NULL)) {
		err = BADREQ("Invalid maxvers parameter: %s", maxvers_str);
	} else {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_PURGEB(args->url, maxvers_str, DL());
		}
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	}
	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_flush (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_FLUSH (args->url, DL()); }
	gboolean truncated = FALSE;
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, &truncated,
			m2v2_boolean_truncated_extract);
	if (NULL != err)
		return _reply_common_error (args, err);
	args->rp->add_header(PROXYD_HEADER_PREFIX "truncated",
			g_strdup(truncated ? "true" : "false"));
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_drain(struct req_args_s *args, struct json_object *j UNUSED)
{
	GError *err = NULL;
	gboolean truncated = FALSE;
	const gchar *limit_str = OPT("limit");
	if (limit_str != NULL && !oio_str_is_number(limit_str, NULL)) {
		err = BADREQ("Invalid limit parameter: %s", limit_str);
	} else {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_container_DRAIN(args->url, limit_str, DL());
		}
		err = _resolve_meta2(args, _prefer_master(), _pack, &truncated,
			m2v2_boolean_truncated_extract);

		args->rp->add_header(PROXYD_HEADER_PREFIX "truncated",
			g_strdup(truncated ? "true" : "false"));
	}

	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_dedup (struct req_args_s *args, struct json_object *j UNUSED)
{
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEDUP (args->url, DL()); }
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	if (NULL != err)
		return _reply_common_error (args, err);
	return _reply_success_json (args, NULL);
}

static enum http_rc_e
action_m2_container_touch (struct req_args_s *args, struct json_object *j UNUSED)
{
	GError *err = NULL;

	gboolean recompute = oio_str_parse_bool(OPT("recompute"), FALSE);
	PACKER_VOID(_pack) {
		return m2v2_remote_pack_TOUCHB(args->url, 0, DL(), recompute);
	}
	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);

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
	const gboolean frozen = OPT("frozen")?TRUE:FALSE;

	GSList *beans = NULL;
	GError *err = m2v2_json_load_setof_xbean (jargs, &beans);
	if (err) {
		EXTRA_ASSERT(beans == NULL);
		return _reply_format_error (args, err);
	}
	if (!beans)
		return _reply_format_error (args, BADREQ("Empty beans list"));

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_RAW_ADD (args->url, beans, frozen, force, DL());
	}
	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
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
	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
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
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
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
	OIO_STRV_APPEND_COPY (args->req_uri->query_tokens, "type=" NAME_SRVTYPE_META2);
	OIO_STRV_APPEND_COPY (args->req_uri->query_tokens, "seq=1");
}

static enum http_rc_e
action_m2_container_propget (struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type (args);
	return action_sqlx_propget(args, jargs);
}

static GError* _container_sharding_show(struct req_args_s *args,
		struct list_params_s list_in, struct list_result_s *plist_out);

static gboolean
_update_shard_properties(struct req_args_s *args, guint status)
{
	if (status != CODE_REDIRECT_SHARD) {
		return TRUE;
	}

	gchar **shared_properties = oio_ext_get_shared_properties();
	if (!shared_properties) {
		return TRUE;
	}

	GError *err = NULL;
	gchar *marker = NULL;
	gboolean truncated = TRUE;
	struct oio_url_s *original_url = args->url;
	while (!err && truncated) {
		struct list_params_s list_in = {0};
		struct list_result_s list_out = {0};
		list_in.marker_start = marker;
		list_in.maxkeys = META2_LISTING_DEFAULT_LIMIT;
		err = _container_sharding_show(args, list_in, &list_out);
		if (err) {
			break;
		}
		truncated = list_out.truncated;
		for (GSList *l=list_out.beans; !err && l; l=l->next) {
			gpointer bean = l->data;
			if (DESCR(bean) != &descr_struct_SHARD_RANGE) {
				continue;
			}
			struct oio_url_s *shard_url = oio_url_dup(args->url);
			oio_url_unset(shard_url, OIOURL_ACCOUNT);
			oio_url_unset(shard_url, OIOURL_USER);
			gchar *shard_cid = g_string_free(metautils_gba_to_hexgstr(NULL,
					SHARD_RANGE_get_cid(bean)), FALSE);
			oio_url_set(shard_url, OIOURL_HEXID, shard_cid);
			args->url = shard_url;
			PACKER_VOID(_pack) {
				return sqlx_pack_PROPSET_tab(args->url, _u, FALSE, FALSE,
						shared_properties, DL());
			};
			err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
			if (err) {
				GRID_WARN("Failed to update properties for shard %s: (%d) %s",
						shard_cid, err->code, err->message);
				g_clear_error(&err);
			}
			g_free(shard_cid);
			oio_url_clean(shard_url);
			args->url = original_url;
		}
		m2v2_list_result_clean(&list_out);
	}
	if (err) {
		GRID_WARN("Failed to update shards properties: (%d) %s",
				err->code, err->message);
		g_error_free(err);
	}
	return TRUE;
}

static enum http_rc_e
action_m2_container_propset(struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type(args);

	gboolean
	_container_propset_decoder(gpointer UNUSED ctx, guint status,
			MESSAGE reply UNUSED)
	{
		return _update_shard_properties(args, status);
	};
	return action_sqlx_propset_with_decoder(args, jargs,
			_container_propset_decoder);
}

static enum http_rc_e
action_m2_container_propdel(struct req_args_s *args, struct json_object *jargs)
{
	_add_meta2_type (args);

	gboolean
	_container_propdel_decoder(gpointer UNUSED ctx, guint status,
			MESSAGE reply UNUSED)
	{
		return _update_shard_properties(args, status);
	};
	return action_sqlx_propdel_with_decoder(args, jargs,
			_container_propdel_decoder);
}

static enum http_rc_e
_container_snapshot(struct req_args_s *args, gchar *src_service_id,
		struct oio_url_s *src_url, const gint src_seq,
		const gchar *src_suffix, struct oio_url_s *dest_url,
		gchar **dest_properties)
{
	EXTRA_ASSERT(src_url != NULL);
	EXTRA_ASSERT(dest_url != NULL);

	GError *err = NULL;
	gchar **src_urlv = NULL;
	gchar *src_base = NULL;
	const gchar *src_cid = oio_url_get(src_url, OIOURL_HEXID);
	gchar **dest_urlv = NULL;
	const gchar *dest_account = oio_url_get(dest_url, OIOURL_ACCOUNT);
	const gchar *dest_container = oio_url_get(dest_url, OIOURL_USER);
	const gchar *dest_cid = oio_url_get(dest_url, OIOURL_HEXID);
	struct oio_url_s *orig_url = args->url;
	args->url = dest_url;

	if (!src_cid || !*src_cid) {
		err = BADREQ("Missing source container URL");
		goto cleanup;
	}

	if (!dest_account || !*dest_account
			|| !dest_container || !*dest_container) {
		err = BADREQ("Missing destination account name or container name");
		goto cleanup;
	}

	if (strcmp(src_cid, dest_cid) == 0) {
		err = BADREQ("The snapshot must either have a different name or "
				"be placed in another account");
		goto cleanup;
	}

	src_base = g_strdup_printf("%s.%d", src_cid, src_seq);

	if (!src_service_id) {
		err = hc_resolve_reference_service(resolver, src_url,
				NAME_SRVTYPE_META2, &src_urlv, oio_ext_get_deadline());
		if (!err && (!src_urlv || !*src_urlv)) {
			err = NEWERROR(CODE_CONTAINER_NOTFOUND, "No service located");
		}
		if (err)
			goto cleanup;
		meta1_urlv_shift_addr(src_urlv);
		src_service_id = src_urlv[0];
	}

	err = hc_resolve_reference_service(resolver, dest_url,
			NAME_SRVTYPE_META2, &dest_urlv, oio_ext_get_deadline());
	if (!err) {
		err = BADREQ("Container already exists");
		goto cleanup;
	} else {
		g_error_free(err);
		err = NULL;
	}

	GError *hook_dir(const char *m1) {
		GError *err2 = meta1v2_remote_link_service(
				m1, dest_url, NAME_SRVTYPE_META2, FALSE, TRUE, &dest_urlv,
				oio_ext_get_deadline());
		if (dest_urlv) {
			g_strfreev(dest_urlv);
			dest_urlv = NULL;
		}
		return err2;
	}
	err = _m1_locate_and_action(dest_url, hook_dir);
	if (err)
		goto cleanup;

	GPtrArray *tmp = g_ptr_array_new();
	if (dest_properties) {
		for (gchar **p=dest_properties; *p; p+=1) {
			g_ptr_array_add(tmp, *p);
		}
	}
	g_ptr_array_add(tmp, SQLX_ADMIN_ACCOUNT);
	g_ptr_array_add(tmp, (gchar *) dest_account);
	g_ptr_array_add(tmp, SQLX_ADMIN_USERNAME);
	g_ptr_array_add(tmp, (gchar *) dest_container);
	gchar **all_dest_properties = (gchar **) metautils_gpa_to_array(tmp,
			TRUE);
	CLIENT_CTX(ctx, args, NAME_SRVTYPE_META2, 1);
	gchar *src_addr = _resolve_service_id(src_service_id);
	/* Willfully ignore the proxy timeout as for large meta2 databases
	   the client may need more time. */
	oio_ext_allow_long_timeout(TRUE);
	GByteArray * _pack_snapshot(const struct sqlx_name_s *n,
			const gchar **headers) {
		return sqlx_pack_SNAPSHOT(n, src_addr, src_base, src_suffix,
				all_dest_properties, headers, DL());
	}
	err = _resolve_meta2(args, CLIENT_PREFER_MASTER,
			_pack_snapshot, NULL, NULL);
	oio_ext_allow_long_timeout(FALSE);
	g_free(all_dest_properties);
	g_free(src_addr);

cleanup:
	args->url = orig_url;
	g_free(src_base);
	if (dest_urlv)
		g_strfreev(dest_urlv);
	if (src_urlv)
		g_strfreev(src_urlv);
	return _reply_m2_error(args, err);
}

static enum http_rc_e
_m2_container_snapshot(struct req_args_s *args, struct json_object *jargs)
{
	GError *err = NULL;

	struct json_object *jaccount = NULL;
	struct json_object *jcontainer = NULL;
	struct json_object *jseq_num = NULL;
	struct oio_ext_json_mapping_s m[] = {
		{"account", &jaccount, json_type_string, 1},
		{"container", &jcontainer, json_type_string, 1},
		{"seq_num", &jseq_num, json_type_int, 0},
		{NULL, NULL, 0, 0}
	};

	err = oio_ext_extract_json(jargs, m);
	if (err)
		return _reply_m2_error(args, err);

	const gchar *account = json_object_get_string(jaccount);
	const gchar *container = json_object_get_string(jcontainer);
	const gint seq_num = jseq_num ? json_object_get_int(jseq_num) : 1;

	struct oio_url_s *dest_url = oio_url_dup(args->url);
	oio_url_set(dest_url, OIOURL_ACCOUNT, account);
	oio_url_set(dest_url, OIOURL_USER, container);
	oio_url_set(dest_url, OIOURL_HEXID, NULL);

	enum http_rc_e rc = _container_snapshot(args, NULL, args->url, seq_num,
			NULL, dest_url, NULL);

	oio_url_clean(dest_url);
	return rc;
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

	err = _m2_container_create_with_properties(args, properties,
			KV_get_value(properties, M2V2_ADMIN_STORAGE_POLICY),
			KV_get_value(properties, M2V2_ADMIN_VERSIONING_POLICY));
	g_strfreev(properties);

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
		const char *version,
		const GError *err, gint code_ok)
{
	if (i > 0)
		g_string_append_c(gresponse, ',');
	g_string_append_c(gresponse, '{');
	oio_str_gstring_append_json_pair(gresponse, "name", name);
	g_string_append_c(gresponse, ',');
	if (oio_str_is_set(version)) {
		oio_str_gstring_append_json_pair(gresponse, "version", version);
		g_string_append_c(gresponse, ',');
	}
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
				KV_get_value(properties, M2V2_ADMIN_STORAGE_POLICY),
				KV_get_value(properties, M2V2_ADMIN_VERSIONING_POLICY));
		g_strfreev(properties);
		_bulk_item_result(gresponse, i, name, NULL, err, HTTP_CODE_CREATED);
		if (err) g_clear_error(&err);
	}
	g_string_append(gresponse, "]}");

	return _reply_success_json(args, gresponse);
}

typedef GByteArray* (*list_packer_f) (struct list_params_s *);

/* Build a marker for the next iteration of the object listing loop.
 * - marker: the marker specified in the client request or returned
 *     by the previous iteration of the listing loop.
 * - delimiter: the delimiter specified in the request.
 * - req_prefix: the prefix specified in the request. */
static gchar *
_build_next_marker(const char *marker, const char *delimiter,
		const char *req_prefix, GTree *tree_prefixes)
{
	/* There is no input marker, or the marker is before the request's prefix.
	 * Let the downstream code use the prefix as a marker (or do not use any
	 * marker if there is no prefix). */
	if (!marker || g_strcmp0(marker, req_prefix) < 0) {
		return NULL;
	}

	/* There is a marker and a prefix, but the marker does not contain the
	 * prefix and is sorted after. This looks like a bad request.
	 * Or maybe we just reached the end without noticing. */
	if (req_prefix && !g_str_has_prefix(marker, req_prefix)) {
		// FIXME(adu): We should directly return an empty list.
		return g_strdup(marker);
	}

	/* Nothing special to do. Use the marker as specified by the customer
	 * or as returned by the last iteration. */
	if (!delimiter || !*delimiter) {
		return g_strdup(marker);
	}

	/* Look for a "sub-prefix" in the candidate marker. */
	gsize prefix_len = req_prefix ? strlen(req_prefix) : 0;
	const char *suffix = strstr(marker + prefix_len, delimiter);
	if (!suffix) {
		return g_strdup(marker);
	}

	/* Check if the "sub-prefix" is known. If the marker we built this prefix
	 * from is a shard boundary, we must check if any object containing this
	 * prefix have been yielded already. If we jump too far, we may miss some
	 * objects at the beginning of the next shard. */
	int len_delimiter = strlen(delimiter);
	gchar subprefix[LIMIT_LENGTH_CONTENTPATH] = {0};
	strncpy(subprefix, marker, suffix + len_delimiter - marker);
	if (tree_prefixes && !g_tree_lookup(tree_prefixes, subprefix)) {
		return g_strdup(marker);
	}

	/* HACK: we have found a "sub-prefix" which will be returned to the
	 * client. Objects containing this prefix won't be returned (because
	 * the request has a delimiter), and thus we can skip them.
	 *
	 * There are very few chances that an object has it in its name,
	 * and even if it has, it won't be listed
	 * (because it would be behind the delimiter).
	 * With such a marker, we will force meta2 to skip objects
	 * that won't be listed, and won't even be used to generate
	 * new prefixes (they all share the current prefix).
	 *
	 * Here is a trivial example:
	 * - a/b/0
	 * - a/b/1
	 * - a/b/2
	 * - a/c/3
	 * - d/e/4
	 * With a page size of 3, and '/' as a delimiter:
	 * - the first request will return "a/b/0", "a/b/1", "a/b/2",
	 *   generating the prefix "a/";
	 * - the marker for the next iteration will be "a/\xf4\x8f\xbf\xbd";
	 * - the second request will skip "a/c/3", and return "d/e/4",
	 *   generating the prefix "d/".
	 *
	 * Notice that we must not return a prefix equal to the marker.
	 *
	 * Notice that there is the same mechanism in the meta2 service.
	 * It is used to return a single alias per sub-prefix. */
	gchar *next_marker = g_strdup_printf("%s"LAST_UNICODE_CHAR, subprefix);
	return next_marker;
}

static GError * _list_loop (struct req_args_s *args,
		struct list_params_s *in0, struct list_result_s *out0,
		GTree *tree_prefixes, list_packer_f packer) {
	GError *err = NULL;
	gboolean stop = FALSE;
	gint iterations = 0;
	// Total number of objects listed so far
	guint main_count = 0;
	struct list_params_s in = *in0;

	GRID_DEBUG("Listing [%s] max=%"G_GINT64_FORMAT" delim=%s prefix=%s"
			" marker=%s version_marker=%s end=%s",
			oio_url_get(args->url, OIOURL_WHOLE),
			in0->maxkeys, in0->delimiter, in0->prefix,
			in0->marker_start, in0->version_marker, in0->marker_end);

	PACKER_VOID(_pack) { return packer(&in); }

	struct filter_ctx_s ctx = {0};
	while (!err && !stop && grid_main_is_running()) {
		iterations++;

		struct list_result_s out = {0};
		m2v2_list_result_init (&out);

		/* patch the input parameters */
		if (in0->maxkeys > 0)
			in.maxkeys = in0->maxkeys - (main_count + g_tree_nnodes(tree_prefixes));

		/* Build an optimized marker.
		 * In the first iteration, skip the prefix check: if the marker sent
		 * by the client contains a prefix, it has been reported by the
		 * previous request. */
		in.marker_start = _build_next_marker(
				out0->next_marker?: in0->marker_start,
				in0->delimiter,
				in0->prefix,
				iterations > 1? tree_prefixes : NULL
		);
		in.version_marker = g_strdup(
			out0->next_version_marker?: in0->version_marker);

		/* Build a routing key (object path) so the sharding resolver
		 * will direct the request to the next shard. */
		gchar *routing_key = NULL;
		if (!(in.prefix && *in.prefix)
				&& !(in.marker_start && *in.marker_start)) {
			routing_key = g_strdup("");
		} else if (g_strcmp0(in.prefix, in.marker_start) > 0) {
			routing_key = g_strdup(in.prefix);
		} else {
			/* HACK: "\x01" is the (UTF-8 encoded) first unicode */
			routing_key = g_strdup_printf("%s\x01", in.marker_start);
		}

		/* Action */
		if (routing_key) {
			oio_url_set(args->url, OIOURL_PATH, routing_key);
		}
		enum cache_control_e original_cache_control = args->cache_control;
		if (g_tree_nnodes(out0->props) == 0) {
			// Disable sharding resolver to fetch container properties
			// from root container
			args->cache_control |= SHARDING_NO_CACHE;
		}
		err = _resolve_meta2(args, _prefer_slave(), _pack, &out,
				m2v2_list_result_extract);
		args->cache_control = original_cache_control;
		if (routing_key) {
			g_free(routing_key);
			oio_url_unset(args->url, OIOURL_PATH);
		}
		oio_str_clean((gchar**)&(in.marker_start));
		oio_str_clean((gchar**)&(in.version_marker));
		if (err) {
			if (err->code == CODE_UNAVAILABLE && main_count > 0) {
				// We reached request deadline, just tell the caller the
				// listing is truncated, it will call us again with the
				// appropriate marker.
				out0->truncated = TRUE;
				g_clear_error(&err);
			}
			m2v2_list_result_clean(&out);
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
		oio_str_reuse(&out0->next_marker, out.next_marker);
		out.next_marker = NULL;
		oio_str_reuse(&out0->next_version_marker, out.next_version_marker);
		out.next_version_marker = NULL;
		if (out.beans) {
			ctx.beans = out0->beans;
			ctx.prefixes = tree_prefixes;
			ctx.count = main_count;
			ctx.prefix = in0->prefix;
			ctx.marker = in0->marker_start;
			ctx.delimiter = in0->delimiter;

			_filter_list_result(&ctx, out.beans);

			out.beans = NULL;
			main_count = ctx.count;
			out0->beans = ctx.beans;
		}

		if (in0->maxkeys > 0 &&
				(main_count + g_tree_nnodes(tree_prefixes)) >= in0->maxkeys) {
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

// CONTAINER{{
// POST /v3.0/{NS}/container/snapshot?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {
//      "account":"destination account name",
//      "container":"destination container name"
//    }
//
// Take a snapshot of a container. Create a separate database containing all
// information about the contents from the original database.
//
// WARNING: this command is not intended to be used as-is as source and destination
// containers will share same chunks.
//
// Please use `openio container snapshot` command.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/snapshot?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 44
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_snapshot(struct req_args_s *args) {
	return rest_action(args, _m2_container_snapshot);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/create_many?acct={account}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// For each container, you can specify system and properties value
// by adding them on dictionary after container name.
// Syntax is same as "container create"
//
// .. code-block:: json
//
//    {
//      "containers":[{"name":"cont0"}, {"name":"cont1", "properties":{"test":"1"}}]
//    }
//
// Create containers with given configuration and name.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/create_many?acct=my_account HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 78
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 106
//
// .. code-block:: json
//
//    {
//      "containers":[
//                     {"name":"cont0","status":201,"message":"ok"},
//                     {"name":"cont1","status":201,"message":"ok"}
//                   ]
//    }
//
// }}CONTAINER
enum http_rc_e action_container_create_many (struct req_args_s *args) {
	return rest_action(args, _m2_container_create_many);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/create?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// System and properties value are optional
//
// .. code-block:: text
//
//    {
//      "system":{"sys.m2.quota": val, "sys.m2.policy.storage": policy, ...},
//      "properties":{"test":"1", ...}
//    }
//
// Create container with given configuration.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/create?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 30
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 201 CREATED
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_create (struct req_args_s *args) {
	return rest_action(args, _m2_container_create);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/destroy?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Delete container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/destroy?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_destroy (struct req_args_s *args) {
	return action_m2_container_destroy (args);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/drain?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Remove all the objects of a container but keep the properties. We can
// replace the data or the properties of the content but no action needing
// the removed chunks are accepted.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/drain?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.68.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_drain(struct req_args_s *args) {
	return rest_action(args, action_m2_container_drain);
}

// CONTAINER{{
// GET /v3.0/{NS}/container/list?acct={account}&ref={container}&properties={bool}&max={int}&chunks={bool}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// List object of container.
// In this example, only 2 objects are given without their properties
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/container/list?acct=my_account&ref=mycontainer&properties=False%max=2 HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 857
//    x-oio-container-meta-sys-account: my_account
//    x-oio-container-meta-sys-m2-ctime: 1533286343746147
//    x-oio-container-meta-sys-m2-init: 1
//    x-oio-container-meta-sys-m2-objects: 2
//    x-oio-container-meta-sys-m2-usage: 360
//    x-oio-container-meta-sys-m2-version: 2
//    x-oio-container-meta-sys-name: B6A905025EBA78C555B4437321C176B4F9CC1EF49A45BBA8FA561D7F08592D2D.1
//    x-oio-container-meta-sys-ns: OPENIO
//    x-oio-container-meta-sys-status: 0
//    x-oio-container-meta-sys-type: meta2
//    x-oio-container-meta-sys-user-name: mycontainer
//    x-oio-list-marker: obj2
//    x-oio-list-truncated: true
//
// .. code-block:: text
//
//    {"prefixes":[], ...}
//
// }}CONTAINER
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
	list_in.delimiter = _delimiter(args);
	list_in.marker_start = OPT("marker");
	list_in.marker_end = OPT("end_marker");
	if (!list_in.marker_end){
		list_in.marker_end = OPT("marker_end");  // backward compatibility
	}
	if (oio_str_parse_bool(OPT("mpu_marker_only"), FALSE)){
		list_in.flag_mpu_marker_only = 1;
	}
	if (OPT("deleted")){
		list_in.flag_nodeleted = 0;
	}
	if (OPT("all")) {
		list_in.version_marker = OPT("version_marker");
		list_in.flag_allversion = 1;
	}
	if (oio_str_parse_bool(OPT("properties"), FALSE)){
		list_in.flag_properties = 1;
	}
	if (oio_str_parse_bool(OPT("chunks"), FALSE)){
		list_in.flag_recursion = 1;
	}
	if (!err){
		err = _max(args, &list_in.maxkeys);
	}
	if (!err) {
		tree_prefixes = g_tree_new_full (metautils_strcmp3, NULL, g_free, NULL);
		m2v2_list_result_init (&list_out);
	}

	if (!err) {
		GByteArray* _pack (struct list_params_s *in) {
			if (chunk_id)
				return m2v2_remote_pack_LIST_BY_CHUNKID(args->url,
						in, chunk_id, DL());
			if (content_hash)
				return m2v2_remote_pack_LIST_BY_HEADERHASH(args->url,
						in, content_hash, DL());
			return m2v2_remote_pack_LIST(args->url, in, DL());
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
		if (list_out.next_version_marker) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "list-version-marker",
					g_uri_escape_string(list_out.next_version_marker, NULL,
							FALSE));
		}
	}

	enum http_rc_e rc = _reply_list_result (args, err, &list_out, tree_prefixes);

	if (tree_prefixes) g_tree_destroy (tree_prefixes);
	if (content_hash) g_bytes_unref (content_hash);
	m2v2_list_result_clean (&list_out);

	return rc;
}

// CONTAINER{{
// GET /v3.0/{NS}/container/show?acct={account}&ref={container}&properties={bool}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Show container information, and return container properties
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/container/show?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 17
//    x-oio-container-meta-sys-account: my_account
//    x-oio-container-meta-sys-m2-ctime: 1533286343746147
//    x-oio-container-meta-sys-m2-init: 1
//    x-oio-container-meta-sys-m2-objects: 2
//    x-oio-container-meta-sys-m2-usage: 360
//    x-oio-container-meta-sys-m2-version: 2
//    x-oio-container-meta-sys-name: B6A905025EBA78C555B4437321C176B4F9CC1EF49A45BBA8FA561D7F08592D2D.1
//    x-oio-container-meta-sys-ns: OPENIO
//    x-oio-container-meta-sys-status: 0
//    x-oio-container-meta-sys-type: meta2
//    x-oio-container-meta-sys-user-name: mycontainer
//    x-oio-container-meta-x-schema-version: 1.8
//    x-oio-container-meta-x-version-main-admin: 1%3A0
//    x-oio-container-meta-x-version-main-aliases: 1%3A0
//    x-oio-container-meta-x-version-main-chunks: 1%3A0
//    x-oio-container-meta-x-version-main-contents: 1%3A0
//    x-oio-container-meta-x-version-main-properties: 1%3A0
//
// .. code-block:: json
//
//   {"properties":{}}
//
// }}CONTAINER
enum http_rc_e action_container_show (struct req_args_s *args) {
	GError *err = NULL;

	CLIENT_CTX(ctx,args,NAME_SRVTYPE_META2,1);

	PACKER_VOID(_pack) { return sqlx_pack_PROPGET(_u, DL()); }
	err = gridd_request_replicated_with_retry (args, &ctx, _pack);
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

// CONTAINER{{
// POST /v3.0/{NS}/container/touch?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Send an event to update object and object size on container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/touch?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_touch (struct req_args_s *args) {
	return rest_action (args, action_m2_container_touch);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/dedup?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/dedup?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_dedup (struct req_args_s *args) {
	return rest_action (args, action_m2_container_dedup);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/purge?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Purge exceeding object versions.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/purge?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_purge (struct req_args_s *args) {
	return rest_action (args, action_m2_container_purge);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/flush?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Remove object of container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/flush?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTAINER
enum http_rc_e action_container_flush (struct req_args_s *args) {
	return rest_action (args, action_m2_container_flush);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/get_properties?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get container properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/get_properties?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 515
//
// .. code-block:: text
//
//   {"properties":[], ...}
//
// }}CONTAINER
enum http_rc_e action_container_prop_get (struct req_args_s *args) {
	return rest_action (args, action_m2_container_propget);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/set_properties?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {
//      "system":{},
//      "properties":{"test":"1"}
//    }
//
// Set container properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/set_properties?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 40
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 2
//
// .. code-block:: json
//
//   {}
//
// }}CONTAINER
enum http_rc_e action_container_prop_set (struct req_args_s *args) {
	return rest_action (args, action_m2_container_propset);
}

// CONTAINER{{
// POST /v3.0/{NS}/container/del_properties?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    ["test"]
//
// Delete container properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/del_properties?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 8
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 2
//
// .. code-block:: json
//
//   {}
//
// }}CONTAINER
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


/* SHARDING action resource ------------------------------------------------- */

static gboolean
_sharding_properties_extract(gpointer ctx, guint status UNUSED, MESSAGE reply)
{
	GTree *props = ctx;
	EXTRA_ASSERT(props != NULL);

	/* Extract properties and merge them into the temporary TreeSet. */
	gchar **names = metautils_message_get_field_names(reply);
	for (gchar **n = names; names && *n; ++n) {
		if (!g_str_has_prefix(*n, NAME_MSGKEY_PREFIX_PROPERTY))
			continue;
		g_tree_replace(props,
				g_strdup((*n) + sizeof(NAME_MSGKEY_PREFIX_PROPERTY) - 1),
				metautils_message_extract_string_copy(reply, *n));
	}
	g_strfreev(names);

	return TRUE;
}

static GError *
_load_simplified_shard_ranges(struct json_object *jbody, GSList **out)
{
	GError *err = NULL;
	GSList *beans = NULL;
	gpointer shard_range = NULL;

	// Load the beans
	if (json_object_is_type(jbody, json_type_null)) {
		// Nothing to do
	} else if (json_object_is_type(jbody, json_type_array)) {
		for (gint i = json_object_array_length(jbody) - 1; i >= 0; i--) {
			shard_range = NULL;
			err = m2v2_json_load_single_shard_range(
					json_object_array_get_idx(jbody, i),
					&shard_range);
			if (err)
				break;
			beans = g_slist_prepend(beans, shard_range);
		}
	} else if (json_object_is_type(jbody, json_type_object)) {
		shard_range = NULL;
		err = m2v2_json_load_single_shard_range(jbody,
				&shard_range);
		beans = g_slist_prepend(beans, shard_range);
	} else {
		err = BADREQ ("JSON: Not an array or an object");
	}

	if (err)
		_bean_cleanl2(beans);
	else
		*out = beans;
	return err;
}

static enum http_rc_e
_reply_shard_ranges_list_result(struct req_args_s *args, GError * err,
		struct list_result_s *out)
{
	if (err)
		return _reply_m2_error (args, err);

	GString *gstr = g_string_sized_new (4096);
	g_string_append_c (gstr, '{');
	_dump_json_properties(gstr, out->props);
	g_string_append_c(gstr, ',');
	g_string_append_static(gstr, "\"shard_ranges\":[");
	meta2_json_shard_ranges_only(gstr, out->beans, FALSE);
	g_string_append_static(gstr, "]}");

	return _reply_success_json (args, gstr);
}

static enum http_rc_e
action_m2_container_sharding_prepare(struct req_args_s *args,
		struct json_object *j)
{
	GError *err = NULL;
	const gchar *action = OPT("action");
	GTree *properties = g_tree_new_full(metautils_strcmp3, NULL, g_free, g_free);
	GSList *beans = NULL;

	err = _load_simplified_shard_ranges(j, &beans);
	if (err) {
		goto end;
	}
	PACKER_VOID(_pack) {
		return m2v2_remote_pack_PREPARE_SHARDING(args->url, action, beans,
			DL());
	};
	err = _resolve_meta2(args, _prefer_master(), _pack,
			properties, _sharding_properties_extract);
	if (err) {
		goto end;
	}

	GString *gstr = g_string_sized_new(256);
	gboolean first = TRUE;
	gboolean _func(gpointer k, gpointer v, gpointer i UNUSED) {
		gboolean is_sharding_property = g_str_has_prefix((gchar*)k,
				"sys.m2.sharding.");
		COMA(gstr, first);
		if (is_sharding_property)
			k += sizeof("sys.m2.sharding.") - 1;
		oio_str_gstring_append_json_pair(gstr, (const char *)k,
				(const char *)v);
		return FALSE;
	}
	g_string_append_c(gstr, '{');
	g_tree_foreach(properties, _func, NULL);
	g_string_append_c(gstr, '}');

end:
	g_tree_destroy(properties);
	if (beans) {
		_bean_cleanl2(beans);
	}
	if (err) {
		return _reply_common_error(args, err);
	}
	return _reply_success_json(args, gstr);
}

static enum http_rc_e
action_m2_container_sharding_create_shard(struct req_args_s *args,
		struct json_object *j)
{
	GError *err = NULL;
	struct json_object *jroot = NULL, *jparent = NULL, *jlower = NULL,
			*jupper = NULL, *jtimestamp = NULL, *jmaster = NULL,
			*jindex = NULL;
	struct oio_ext_json_mapping_s mapping[] = {
		{"index",     &jindex,     json_type_int,    1},
		{"root",      &jroot,      json_type_string, 1},
		{"parent",    &jparent,    json_type_string, 1},
		{"lower",     &jlower,     json_type_string, 1},
		{"upper",     &jupper,     json_type_string, 1},
		{"timestamp", &jtimestamp, json_type_int,    1},
		{"master",    &jmaster,    json_type_string, 1},
		{NULL,        NULL,        0,                0}
	};
	err = oio_ext_extract_json(j, mapping);
	if (err) {
		return _reply_m2_error(args, err);
	}
	gchar *root = (gchar *) json_object_get_string(jroot);
	gchar *admin_lower = g_strconcat(">", json_object_get_string(jlower), NULL);
	gchar *admin_upper = g_strconcat("<", json_object_get_string(jupper), NULL);
	gchar *timestamp = (gchar *) json_object_get_string(jtimestamp);
	gchar *master = (gchar *) json_object_get_string(jmaster);
	gchar *index = (gchar *) json_object_get_string(jindex);
	gchar *src_suffix = g_strdup_printf("sharding-%s-%s", timestamp, index);
	gchar *state = g_strdup_printf("%d", NEW_SHARD_STATE_APPLYING_SAVED_WRITES);

	gchar *shard_properties[22] = {
		M2V2_ADMIN_SIZE, "0",
		M2V2_ADMIN_SIZE".", "",  // delete size for all policies
		M2V2_ADMIN_OBJ_COUNT, "0",
		M2V2_ADMIN_OBJ_COUNT".", "",  // delete count for all policies
		M2V2_ADMIN_SHARD_COUNT, "0",
		M2V2_ADMIN_SHARDING_STATE, state,
		M2V2_ADMIN_SHARDING_TIMESTAMP, timestamp,
		M2V2_ADMIN_SHARDING_ROOT, root,
		M2V2_ADMIN_SHARDING_LOWER, admin_lower,
		M2V2_ADMIN_SHARDING_UPPER, admin_upper,
		NULL, NULL
	};

	struct oio_url_s *parent_url = oio_url_dup(args->url);
	oio_url_set(parent_url, OIOURL_ACCOUNT, NULL);
	oio_url_set(parent_url, OIOURL_USER, NULL);
	oio_url_set(parent_url, OIOURL_HEXID, json_object_get_string(jparent));
	enum http_rc_e rc = _container_snapshot(args, master, parent_url, 1,
			src_suffix, args->url, shard_properties);
	oio_url_clean(parent_url);

	g_free(admin_lower);
	g_free(admin_upper);
	g_free(src_suffix);
	g_free(state);
	return rc;
}

static enum http_rc_e
action_m2_container_sharding_merge(struct req_args_s *args,
		struct json_object *j)
{
	GError *err = NULL;
	GSList *beans = NULL;
	gboolean truncated = FALSE;

	err = _load_simplified_shard_ranges(j, &beans);
	if (!err) {
		if (g_slist_length(beans) != 1) {
			err = BADREQ("Only one shard can be merged");
		} else {
			PACKER_VOID(_pack) {
				return m2v2_remote_pack_MERGE_SHARDING(args->url, beans, DL());
			};
			err = _resolve_meta2(args, _prefer_master(), _pack, &truncated,
					m2v2_boolean_truncated_extract);
		}
	}
	_bean_cleanl2(beans);
	args->rp->add_header(PROXYD_HEADER_PREFIX "truncated",
			g_strdup(truncated ? "true" : "false"));
	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_sharding_update_shard(struct req_args_s *args,
		struct json_object *j UNUSED)
{
	if (!json_object_is_type(j, json_type_array))
		return _reply_format_error(args, BADREQ("Array argument expected"));

	gchar **queries = NULL;
	GError *err = STRV_decode_object(j, &queries);
	EXTRA_ASSERT((err != NULL) ^ (queries != NULL));
	if (err)
		return _reply_format_error(args, err);

	PACKER_VOID(_pack) {
		return m2v2_remote_pack_UPDATE_SHARD(args->url, queries, DL());
	};
	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	g_strfreev(queries);
	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_sharding_lock(struct req_args_s *args,
		struct json_object *j UNUSED)
{
	GError *err = NULL;
	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_LOCK_SHARDING(args->url, DL());
		};
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	}
	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_sharding_replace(struct req_args_s *args,
		struct json_object *j)
{
	GError *err = NULL;
	GSList *beans = NULL;

	err = _load_simplified_shard_ranges(j, &beans);
	if (!err) {
		if (!g_slist_length(beans)) {
			err = BADREQ("No shard");
		} else {
			PACKER_VOID(_pack) {
				return m2v2_remote_pack_REPLACE_SHARDING(args->url, beans,
						DL());
			};
			err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
		}
	}
	_bean_cleanl2(beans);
	return _reply_m2_error(args, err);
}

static enum http_rc_e
action_m2_container_sharding_clean(struct req_args_s *args,
		struct json_object *j)
{
	GError *err = NULL;
	gboolean truncated = FALSE;
	GSList *beans = NULL;
	gboolean local = _request_get_flag(args, "local");
	gboolean urgent = _request_get_flag(args, "urgent");

	err = _load_simplified_shard_ranges(j, &beans);
	if (!err) {
		if (beans && g_slist_length(beans) != 1) {
			err = BADREQ("Only one shard can be cleaned");
		} else {
			/* If it's a local request, the database is cleaned in one go
			 * and it may take some time.
			 * Otherwise, it is better to avoid replaying this rather expensive
			 * request.
			 */
			oio_ext_allow_long_timeout(TRUE);
			PACKER_VOID(_pack) {
				return m2v2_remote_pack_CLEAN_SHARDING(args->url, beans,
						local, urgent, DL());
			};
			err = _resolve_meta2(args, _prefer_master(), _pack, &truncated,
					m2v2_boolean_truncated_extract);
			oio_ext_allow_long_timeout(FALSE);
			args->rp->add_header(PROXYD_HEADER_PREFIX "truncated",
					g_strdup(truncated ? "true" : "false"));
		}
	}
	if (beans) {
		_bean_cleanl2(beans);
	}
	return _reply_m2_error(args, err);
}

static GError*
_container_sharding_show(struct req_args_s *args,
		struct list_params_s list_in, struct list_result_s *plist_out)
{
	GError *err = NULL;
	struct list_result_s list_out = {0};
	if (!err) {
		m2v2_list_result_init(&list_out);
	}

	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_SHOW_SHARDING(args->url, &list_in, DL());
		};
		err = _resolve_meta2(args, _prefer_slave(), _pack, &list_out,
				m2v2_list_result_extract);
	}

	if (!err) {
		args->rp->add_header(PROXYD_HEADER_PREFIX "list-truncated",
				g_strdup(list_out.truncated ? "true" : "false"));
		if (list_out.next_marker) {
			args->rp->add_header(PROXYD_HEADER_PREFIX "list-marker",
					g_uri_escape_string(list_out.next_marker, NULL, FALSE));
		}
	}

	if (err) {
		m2v2_list_result_clean(&list_out);
	} else {
		*plist_out = list_out;
	}
	return err;
}

static enum http_rc_e
action_m2_container_sharding_abort(struct req_args_s *args,
		struct json_object *j UNUSED)
{
	GError *err = NULL;
	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_ABORT_SHARDING(args->url, DL());
		};
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	}
	return _reply_m2_error(args, err);
}

// SHARDING{{
// GET /v3.0/{NS}/container/sharding/find?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Find the distribution of shard ranges on unsharded container
// or an existing shard
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/container/sharding/find?acct=my_account&ref=mycontainer&strategy=shard-with-partition HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 38
//    Content-Type: application/x-www-form-urlencoded
//
//    {
//      "partition": [50, 50]
//    }
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 476
//
//    {
//      "properties": {},
//      "system": {
//        "sys.account": "myaccount",
//        "sys.m2.chunks.missing": "0",
//        "sys.m2.ctime": "1613657902787922",
//        "sys.m2.init": "1",
//        "sys.m2.objects": "4",
//        "sys.m2.objects.damaged": "0",
//        "sys.m2.usage": "0",
//        "sys.m2.version": "1",
//        "sys.name": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360.1",
//        "sys.ns": "OPENIO",
//        "sys.status": "0",
//        "sys.type": "meta2",
//        "sys.user.name": "mycontainer"
//      },
//      "shard_ranges": [
//        {
//          "lower": "",
//          "upper": "shard",
//          "metadata": {"count":2}
//        },
//        {
//          "lower": "shard",
//          "upper": "",
//          "metadata": {"count":2}
//        }
//      ]
//    }
//
// }}SHARDING
enum http_rc_e
action_container_sharding_find(struct req_args_s *args)
{
	GError *err = NULL;
	struct list_result_s list_out = {0};

	const gchar *strategy = OPT("strategy");
	if (!strategy) {
		err = BADREQ("Missing strategy");
		return _reply_format_error (args, err);
	}

	m2v2_list_result_init(&list_out);
	if (!err) {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_FIND_SHARDS(args->url,
					strategy, args->rq->body, DL());
		};
		err = _resolve_meta2(args, _prefer_master(), _pack, &list_out,
				m2v2_list_result_extract);
	}

	enum http_rc_e rc = _reply_shard_ranges_list_result(args, err, &list_out);
	m2v2_list_result_clean(&list_out);
	return rc;
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/prepare?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Prepare container to be shard.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/prepare?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 110
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 225
//
//    {
//      "master": "127.0.0.1:6008",
//      "queue": "beanstalk://127.0.0.1:6005",
//      "state": "1",
//      "timestamp": "1623948108576683"
//    }
//
// }}SHARDING
enum http_rc_e
action_container_sharding_prepare(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_prepare);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/create_shard?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Create shard of container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/create_shard?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 110
//    Content-Type: application/x-www-form-urlencoded
//
//    {
//      "lower": "",
//      "upper": "shard",
//      "root": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360",
//      "parent": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360",
//      "timestamp": 1623946933424828,
//      "master": "127.0.0.1:6008"
//    }
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_create_shard(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_create_shard);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/merge?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Merge shard with the local copy of the specified shard.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/merge?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 110
//    Content-Type: application/x-www-form-urlencoded
//
//    {
//      "cid": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360",
//      "lower": "",
//      "upper": "shard",
//      "metadata": {
//        "root": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360",
//        "timestamp": 1623946933424828
//      }
//    }
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_merge(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_merge);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/update_shard?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Update new shard with SQL update queries.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/update_shard?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 110
//    Content-Type: application/x-www-form-urlencoded
//
//    [
//      "INSERT OR REPLACE INTO chunks(id,content,position,hash,size,ctime) VALUES ('http://127.0.0.1:6011/2EE13DF4D55AF992C992BE6C4779179C58F484EBD589E4EE86DF0325680FFCB2',x'daf77a6876bb050008c356e9ff2e70db','0',x'272913026300e7ae9b5e2d51f138e674',111,1613492116)",
//      "INSERT OR REPLACE INTO contents(id,hash,size,ctime,mtime,mime_type,chunk_method,policy) VALUES (x'daf77a6876bb050008c356e9ff2e70db',x'272913026300e7ae9b5e2d51f138e674',111,1613492116,1613492116,'application/octet-stream','plain/nb_copy=1','SINGLE')",
//      "INSERT OR REPLACE INTO aliases(alias,version,content,deleted,ctime,mtime) VALUES ('obj',1613492116977628,x'daf77a6876bb050008c356e9ff2e70db',0,1613492116,1613492116)"
//    ]
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_update_shard(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_update_shard);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/lock?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Lock the container to put all requests on hold.
// This container will soon be replaced by new shards.
// It's a temporary state.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/lock?acct=myaccount&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 0
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_lock(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_lock);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/replace?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Replace shard ranges in root container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/replace?acct=myaccount&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 216
//    Content-Type: application/x-www-form-urlencoded
//
//    [
//      {
//        "lower": "",
//        "upper": "shard",
//        "cid": "8B78B3245B74710F3ACC1BEF4978E621F5E764E01FFB5621D23C4EECA2B7BB3D"
//      },
//      {
//        "lower": "shard",
//        "upper": "",
//        "cid": "BC99330D9F1A70D2AD6CA388DF8A09AD1DCD4066B439C945A157122CEC9800EA"
//      }
//    ]
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_replace(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_replace);
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/clean?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Clean up new shard (and the root container).
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/clean?acct=myaccount&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 0
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_clean(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_clean);
}

// SHARDING{{
// GET /v3.0/{NS}/container/sharding/show?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get shard ranges from a root container.
//
// .. code-block:: http
//
//    GET /v3.0/OPENIO/container/sharding/show?acct=myaccount&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 637
//    x-oio-list-truncated: false
//
//    {
//      "properties": {},
//      "system": {
//        "sys.account": "myaccount",
//        "sys.m2.chunks.missing": "0",
//        "sys.m2.ctime": "1613657902787922",
//        "sys.m2.init": "1",
//        "sys.m2.objects": "0",
//        "sys.m2.objects.damaged": "0",
//        "sys.m2.usage": "0",
//        "sys.m2.version": "1",
//        "sys.name": "594C8B26EA13E562391013AE6FC360C2C1691F314164DD457EF583B16712E360.1",
//        "sys.ns": "OPENIO",
//        "sys.status": "0",
//        "sys.type": "meta2",
//        "sys.user.name": "mycontainer"
//      },
//      "shard_ranges": [
//        {
//          "lower": "",
//          "upper": "shard",
//          "cid": "8B78B3245B74710F3ACC1BEF4978E621F5E764E01FFB5621D23C4EECA2B7BB3D",
//          "metadata": ""
//        },
//        {
//          "lower": "shard",
//          "upper": "",
//          "cid": "BC99330D9F1A70D2AD6CA388DF8A09AD1DCD4066B439C945A157122CEC9800EA",
//          "metadata": ""
//        }
//      ]
//    }
//
// }}SHARDING
enum http_rc_e
action_container_sharding_show(struct req_args_s *args)
{
	GError *err = NULL;
	struct list_params_s list_in = {0};
	struct list_result_s list_out = {0};

	/* Init the listing options common to all the modes */
	list_in.marker_start = OPT("marker");
	err = _max(args, &list_in.maxkeys);
	// Params not used with sharding
	// list_in.prefix = 0;
	// list_in.marker_end = 0;
	// list_in.flag_nodeleted = 0;
	// list_in.flag_allversion = 0;
	// list_in.flag_headers = 1;
	// list_in.flag_properties = 0;

	err = _container_sharding_show(args, list_in, &list_out);
	enum http_rc_e rc = _reply_shard_ranges_list_result(args, err, &list_out);
	m2v2_list_result_clean(&list_out);
	return rc;
}

// SHARDING{{
// POST /v3.0/{NS}/container/sharding/abort?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Abort sharding.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/container/sharding/abort?acct=myaccount&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.58.0
//    Accept: */*
//    Content-Length: 0
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}SHARDING
enum http_rc_e
action_container_sharding_abort(struct req_args_s *args)
{
	return rest_action(args, action_m2_container_sharding_abort);
}

/* CONTENT action resource -------------------------------------------------- */

static GError*
_get_conditioned_spare_chunks(struct oio_url_s *url, const gchar *position,
		const char *polname, GSList *notin, GSList *broken,
		gboolean force_fair_constraints, gboolean adjacent_mode, GSList **beans)
{
	struct namespace_info_s ni = {};
	NSINFO_READ(namespace_info_copy(&nsinfo, &ni));
	struct storage_policy_s *policy = storage_policy_init(&ni, polname);
	namespace_info_clear(&ni);

	if (!policy)
		return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Unexpected storage policy");
	GError *err = get_conditioned_spare_chunks(url, position,
			lb_rawx, policy, ns_name, notin, broken, force_fair_constraints,
			adjacent_mode, beans);
	storage_policy_clean(policy);
	return err;
}

static GError*
_get_spare_chunks(struct oio_url_s *url, const gchar *position,
		const char *polname, GSList **beans)
{
	struct namespace_info_s ni = {};
	NSINFO_READ(namespace_info_copy(&nsinfo, &ni));
	struct storage_policy_s *policy = storage_policy_init(&ni, polname);
	namespace_info_clear(&ni);

	if (!policy)
		return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Unexpected storage policy");
	GError *err = get_spare_chunks_focused(url, position,
			lb_rawx, policy,
			location_num, oio_proxy_local_prepare,
			beans);
	storage_policy_clean(policy);
	return err;
}

static GError*
_generate_beans(struct oio_url_s *url, gint64 pos,  gint64 size,
		const char *polname, gboolean random_ids, GSList **beans)
{
	struct namespace_info_s ni = {};
	NSINFO_READ(namespace_info_copy(&nsinfo, &ni));
	struct storage_policy_s *policy = storage_policy_init(&ni, polname);
	namespace_info_clear(&ni);

	if (!policy)
		return NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Unexpected storage policy");

	struct oio_generate_beans_params_s params = {
		.lb=lb_rawx,
		.url=url,
		.pos=pos,
		.size=size,
		.chunk_size=oio_ns_chunk_size,
		.pol=policy,
		.pin=location_num,
		.mode=oio_proxy_local_prepare,
		.random_ids=random_ids
	};
	GError *err = oio_generate_focused_beans(&params, beans);

	storage_policy_clean(policy);
	return err;
}

static enum http_rc_e
_action_m2_content_prepare(struct req_args_s *args, struct json_object *jargs,
		enum http_rc_e (*_reply_beans_func)(struct req_args_s *, GError *, GSList *))
{
	struct json_object *jsize = NULL, *jpol = NULL, *jpos = NULL,
			*jappend = NULL;
	json_object_object_get_ex(jargs, "size", &jsize);
	json_object_object_get_ex(jargs, "policy", &jpol);
	json_object_object_get_ex(jargs, "position", &jpos);
	json_object_object_get_ex(jargs, "append", &jappend);

	const gchar *strsize = !jsize ? NULL : json_object_get_string (jsize);
	const gchar *stgpol = !jpol ? oio_ns_storage_policy : json_object_get_string (jpol);
	const gchar *strpos = !jpos ? "0" : json_object_get_string(jpos);

	/* Parse the size */
	if (!strsize)
		return _reply_format_error (args, BADREQ("Missing size estimation"));
	errno = 0;
	gchar *end = NULL;
	gint64 size = g_ascii_strtoll (strsize, &end, 10);
	if ((end && *end) || errno == ERANGE || errno == EINVAL)
		return _reply_format_error (args, BADREQ("Invalid size format"));

	end = NULL;
	gint64 pos = g_ascii_strtoll(strpos, &end, 10);
	if ((end && *end) || errno == ERANGE || errno == EINVAL)
		return _reply_format_error(args,
				BADREQ("Invalid position format (integer expected)"));

	/* If we are preparing chunks in order to append data to an existing
	 * object, we must generate random IDs, because the final position
	 * of the chunks is not known yet. */
	gboolean random_ids = json_object_get_boolean(jappend);

	/* Local generation of beans */
	GSList *beans = NULL;
	GError *err = _generate_beans(args->url, pos, size, stgpol, random_ids,
			&beans);

	/* Patch the chunk size to ease putting contents with unknown size. */
	if (!err) {
		const gint64 chunk_size = oio_ns_chunk_size;
		for (GSList *l=beans; l ;l=l->next) {
			if (l->data && (DESCR(l->data) == &descr_struct_CHUNKS)) {
				struct bean_CHUNKS_s *bean = l->data;
				CHUNKS_set_size(bean, chunk_size);
			}
		}
		args->rp->add_header(PROXYD_HEADER_PREFIX "ns-chunk-size",
				g_strdup_printf("%"G_GINT64_FORMAT, chunk_size));
	}

	return _reply_beans_func(args, err, beans);
}

static enum http_rc_e
action_m2_content_prepare(struct req_args_s *args, struct json_object *jargs)
{
	return _action_m2_content_prepare(args, jargs,
			_reply_simplified_beans_legacy);
}

static enum http_rc_e
action_m2_content_prepare_v2(struct req_args_s *args, struct json_object *jargs)
{
	return _action_m2_content_prepare(args, jargs, _reply_simplified_beans);
}

static GError *_m2_json_spare (struct req_args_s *args,
		struct json_object *jbody, GSList ** out) {
	struct json_object *jnotin = NULL, *jbroken = NULL;
	struct json_object *jforce_fair_constraints = NULL, *jadjacent_mode = NULL;
	GSList *notin = NULL, *broken = NULL, *obeans = NULL;
	GError *err = NULL;
	gboolean force_fair_constraints, adjacent_mode;

	*out = NULL;
	const char *stgpol = OPT("stgpol");
	if (!stgpol)
		return BADREQ("'stgpol' field not a string");

	if (!json_object_is_type (jbody, json_type_object))
		return BADREQ ("Body is not a valid JSON object");
	if (!json_object_object_get_ex (jbody, "notin", &jnotin))
		return BADREQ("'notin' field missing");
	if (!json_object_object_get_ex (jbody, "broken", &jbroken))
		return BADREQ("'broken' field missing");
	if (json_object_object_get_ex (jbody, "force_fair_constraints", &jforce_fair_constraints)) {
		if (json_object_is_type(jforce_fair_constraints, json_type_boolean)) {
			force_fair_constraints = json_object_get_boolean(jforce_fair_constraints);
		} else {
			goto label_exit;
		}
	} else {
		/* use default value */
		force_fair_constraints = FALSE;
	}
	if (json_object_object_get_ex (jbody, "adjacent_mode", &jadjacent_mode)) {
		if (json_object_is_type(jadjacent_mode, json_type_boolean)) {
			adjacent_mode = json_object_get_boolean(jadjacent_mode);
		} else {
			goto label_exit;
		}
	} else {
		/* use default value */
		adjacent_mode = FALSE;
	}
	if (!json_object_is_type(jnotin, json_type_null)
			&& NULL != (err = _load_simplified_chunks (jnotin, &notin)))
		goto label_exit;
	if (!json_object_is_type(jbroken, json_type_null)
			&& NULL != (err = _load_simplified_chunks (jbroken, &broken)))
		goto label_exit;

	for (GSList *l=broken; l; l=l->next) {
		struct bean_CHUNKS_s *chunk = l->data;
		CHUNKS_set_size(chunk, -1);
	}

	if (!notin && !broken) {
		/* traditional prepare but only for chunks */
		err = _get_spare_chunks(args->url, OPT("position"), stgpol, &obeans);
	} else {
		err = _get_conditioned_spare_chunks(args->url, OPT("position"),
				stgpol, notin, broken, force_fair_constraints, adjacent_mode, &obeans);
	}
	EXTRA_ASSERT ((err != NULL) ^ (obeans != NULL));

	if (!err) {
		*out = obeans;
		obeans = NULL;
	}
label_exit:
	_bean_cleanl2 (obeans);
	_bean_cleanl2 (broken);
	_bean_cleanl2 (notin);
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
		return _reply_format_error(args, BADREQ("missing content path or ID"));

	PACKER_VOID(_pack) { return m2v2_remote_pack_TOUCHC (args->url, DL()); }
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propset (struct req_args_s *args,
		struct json_object *jargs) {
	if (CONTENT())
		return _reply_m2_error (args, BADREQ("Content. not allowed in the URL"));

	GSList *beans = NULL;
	const gchar *destinations = NULL;

	if (jargs) {
		gchar **kv = NULL;
		GError *err = KV_read_properties(jargs, &kv, "properties", TRUE);
		if (err) {
			return _reply_format_error (args, err);
		}
		for (gchar **p=kv; *p && *(p+1) ;p+=2) {
			struct bean_PROPERTIES_s *prop = _bean_create (&descr_struct_PROPERTIES);
			PROPERTIES_set2_key (prop, *p);
			PROPERTIES_set2_value (prop, (guint8*)*(p+1), strlen(*(p+1)));
			PROPERTIES_set2_alias (prop, oio_url_get (args->url, OIOURL_PATH));
			PROPERTIES_set_version (prop, args->version);
			beans = g_slist_prepend (beans, prop);
		}
		g_strfreev(kv);
		struct json_object *jdests = NULL;
		json_object_object_get_ex(jargs, "replication_destinations", &jdests);
		if (jdests) {
			destinations = json_object_get_string(jdests);
		}
	}

	guint32 flags = 0;
	if (OPT("flush")) {
		flags |= M2V2_FLAG_FLUSH;
	}

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_SET (args->url, flags, beans, destinations, DL()); }
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	_bean_cleanl2 (beans);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propdel (struct req_args_s *args,
		struct json_object *jargs) {
	struct json_object * jprops = jargs;
	const gchar *destinations = NULL;

	// Payload with replication destinations
	if (json_object_is_type(jargs, json_type_object)) {
		json_object_object_get_ex(jargs, "properties", &jprops);
		struct json_object *jdests = NULL;
		json_object_object_get_ex(jargs, "replication_destinations", &jdests);
		if (jdests) {
			destinations =json_object_get_string(jdests);
		}
	} else if (!json_object_is_type(jargs, json_type_array)) {
		return _reply_format_error (args, BADREQ("Array or object argument expected"));
	}

	gchar **namev = NULL;
	GError *err = STRV_decode_object(jprops, &namev);
	EXTRA_ASSERT((err != NULL) ^ (namev != NULL));
	if (err){
		return _reply_format_error(args, err);
	}

	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_DEL (args->url, namev, destinations, DL()); }
	err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	g_strfreev(namev);
	return _reply_m2_error (args, err);
}

static enum http_rc_e action_m2_content_propget (struct req_args_s *args,
		struct json_object *jargs UNUSED) {
	GSList *beans = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_PROP_GET(args->url, DL()); }
	GError *err = _resolve_meta2(args, _prefer_slave(), _pack, &beans, NULL);
	return _reply_properties (args, err, beans);
}

static GError *_m2_json_put (struct req_args_s *args,
		struct json_object *jbody) {
	if (!jbody) {
		return BADREQ("Invalid JSON body");
	}

	const gboolean append = _request_get_flag (args, "append");
	const gboolean force = _request_get_flag (args, "force");
	const gboolean change_policy = _request_get_flag (args, "change_policy");
	const gboolean restore_drained = _request_get_flag (args, "restore_drained");
	/* used from oio-swift for "sharding" in containers */
	const char* force_versioning = g_tree_lookup(args->rq->tree_headers,
			PROXYD_HEADER_FORCE_VERSIONING);
	oio_ext_set_force_versioning(force_versioning);

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

	struct json_object *jdests = NULL;
	json_object_object_get_ex(jbody, "replication_destinations", &jdests);
	const gchar *destinations = !jdests ? NULL : json_object_get_string(jdests);

	PACKER_VOID(_pack) {
		if (force) return m2v2_remote_pack_OVERWRITE(args->url, ibeans, DL());
		if (append) return m2v2_remote_pack_APPEND(args->url, ibeans, DL());
		if (change_policy) return m2v2_remote_pack_CHANGE_POLICY(args->url, ibeans, DL());
		if (restore_drained) return m2v2_remote_pack_RESTORE_DRAINED(args->url, ibeans, DL());
		return m2v2_remote_pack_PUT (args->url, ibeans, destinations, DL());
	}
	err = _resolve_meta2(args, _prefer_master(), _pack, &obeans, NULL);
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
			gchar **props = NULL;
			struct json_object *jprops = NULL;
			if (json_object_object_get_ex(jbody, "container_properties", &jprops)) {
				err = KV_read_usersys_properties(jprops, &props);
				if (err) {
					GRID_WARN("Failed to read container properties: %s",
							err->message);
					g_clear_error(&err);
				}
			}
			err = _m2_container_create_with_properties(args, props, NULL, NULL);
			g_strfreev(props);
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
		err = _resolve_meta2(args, _prefer_master(), _pack, &obeans, NULL);
	}
	_bean_cleanl2(obeans);
	_bean_cleanl2(ibeans);
	return _reply_m2_error (args, err);
}

static enum http_rc_e
action_m2_content_purge (struct req_args_s *args, struct json_object *j UNUSED)
{
	GError *err = NULL;
	const char *maxvers_str = OPT("maxvers");
	if (maxvers_str && !oio_str_is_number(maxvers_str, NULL)) {
		err = BADREQ("Invalid maxvers parameter: %s", maxvers_str);
	} else {
		PACKER_VOID(_pack) {
			return m2v2_remote_pack_PURGEC(args->url, maxvers_str, DL());
		}
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	}
	return _reply_m2_error(args, err);
}

/* CONTENT resources ------------------------------------------------------- */


// CONTENT{{
// POST /v3.0/{NS}/content/create?acct=<account_name>&ref=<container_name>&path=<file_path>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Create a new object. This method does not upload any data, it just
// registers object metadata in the database. It is supposed to be called
// after at least one call to the content/prepare2 route and a successful
// data upload to rawx services.
//
// Most of the required information is available in the content/prepare2
// response. Additional information must be computed by the client (object
// size and hash).
//
// Sample request:
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/create?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    x-oio-content-meta-id: 2996752DFD7205006B73F17AD315AA2B
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-size: 64
//    x-oio-content-meta-version: 554086800
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-hash: 2996752DFD7205006B73F17AD315AA2B
//    x-oio-content-meta-mime-type: application/octet-stream
//    Content-Length: 165
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: json
//
//    {
//      "chunks": [
//        {
//          "url":"http://127.0.0.1:6012/D3F2...",
//          "pos":"0",
//          "size":1048576,
//          "hash":"00000000000000000000000000000000"
//        }
//      ],
//      "properties": {
//        "category": "dogs"
//      }
//    }
//
// The following request headers are mandatory:
// content ID, storage policy, size and version.
//
// .. code-block:: text
//
//    x-oio-content-meta-id: 2996752DFD7205006B73F17AD315AA2B
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-size: 64
//    x-oio-content-meta-version: 554086800000000
//
// The following request headers are recommended:
// content hash (MD5), mime-type, chunk method.
//
// .. code-block:: text
//
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-hash: 2996752DFD7205006B73F17AD315AA2B
//    x-oio-content-meta-mime-type: application/octet-stream
//
// The following header allows to set the versioning policy of the
// container hosting the object:
//
// .. code-block:: text
//
//    "x-oio-force-versioning: -1"
//
// The following header tells that the object must be created
// as if the versioning was enabled and unlimited
// (this prevents the automatic garbage collection):
//
// .. code-block:: text
//
//    "x-oio-simulate-versioning: 1"
//
//
// Sample response:
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_put (struct req_args_s *args) {
	return rest_action(args, action_m2_content_create);
}

// CONTENT{{
// POST /v3.0/{NS}/content/update?acct=<account_name>&ref=<container_name>&path=<file_path>
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    [
//      {
//        "url":"http://127.0.0.1:6012/D3F2...",
//        "pos":"0",
//        "size":1048576,
//        "hash":"00000000000000000000000000000000"
//      }
//    ]
//
// You must specify content length and ID on header
//
// .. code-block:: text
//
//    "x-oio-content-meta-id: 2996752DFD7205006B73F17AD315AA2B"
//    "x-oio-content-meta-size: 64"
//
// Update existing object. This method does not upload any data, it just
// registers updated object metadata in the database.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/update?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    x-oio-content-meta-size: 64
//    x-oio-content-meta-id: 2996752DFD7205006B73F17AD315AA2B
//    Content-Length: 165
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_update(struct req_args_s *args) {
	return rest_action(args, _m2_content_update);
}


// CONTENT{{
// POST /v3.0/{NS}/content/truncate?acct={account}&ref={container}&path={file path}&size={int}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Truncate object at specified size.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/truncate?acct=my_account&ref=mycontainer&path=mycontent&size=180 HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
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
		err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	}
	return _reply_m2_error(args, err);
}

// CONTENT{{
// POST /v3.0/{NS}/content/prepare?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {
//      "size": 42,
//      "policy": "SINGLE"
//    }
//
// Prepare an upload: get URLs of chunks on available rawx.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/prepare?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 31
//    Content-Type: application/x-www-form-urlencoded
//
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 276
//    x-oio-ns-chunk-size: 1048576
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-ctime: 1533215985
//    x-oio-content-meta-deleted: False
//    x-oio-content-meta-hash-method: md5
//    x-oio-content-meta-id: B03A29AA737205002C4D414D4C12FDC5
//    x-oio-content-meta-size: 180
//    x-oio-content-meta-mime-type: application/octet-stream
//    x-oio-content-meta-name: mycontent
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-version: 1533215985187506
//
// }}CONTENT
enum http_rc_e action_content_prepare (struct req_args_s *args) {
	return rest_action (args, action_m2_content_prepare);
}

// CONTENT{{
// POST /v3.0/{NS}/content/prepare2?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Prepare an upload: get URLs of chunks on available rawx.
//
// Sample request:
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/prepare2?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 31
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: json
//
//    {
//      "size": 42,
//      "policy": "SINGLE",
//      "position": 0,
//      "append": false
//    }
//
//
// Sample response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 276
//    x-oio-ns-chunk-size: 1048576
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-ctime: 1533215985
//    x-oio-content-meta-deleted: False
//    x-oio-content-meta-hash-method: md5
//    x-oio-content-meta-id: B03A29AA737205002C4D414D4C12FDC5
//    x-oio-content-meta-size: 180
//    x-oio-content-meta-mime-type: application/octet-stream
//    x-oio-content-meta-name: mycontent
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-version: 1533215985187506
//
// }}CONTENT
enum http_rc_e action_content_prepare_v2(struct req_args_s *args) {
	return rest_action(args, action_m2_content_prepare_v2);
}

// CONTENT{{
// GET /v3.0/{NS}/content/show?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get a description of the content along with its user properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/show?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 272
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-ctime: 1533546157
//    x-oio-content-meta-deleted: False
//    x-oio-content-meta-hash: 26CBCBBF52F37322FAC57B8AC0E4E130
//    x-oio-content-meta-hash-method: md5
//    x-oio-content-meta-id: FB35FC89C072050065F28C69311740F6
//    x-oio-content-meta-size: 180
//    x-oio-content-meta-mime-type: application/octet-stream
//    x-oio-content-meta-name: mycontent
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-version: 1533546157848061
//
// .. code-block:: text
//
//    [{"url":"http://127.0.0.1:6012/BADD4...", ...}]
//
// }}CONTENT
enum http_rc_e action_content_show (struct req_args_s *args) {
	GSList *beans = NULL;
	guint32 flags = 0;

	/* Historical behaviour is to return properties as headers, but
	 * if there are too many, the client will fail decoding the request. */
	if (!oio_str_parse_bool(OPT("properties"), TRUE))
		flags |= M2V2_FLAG_NOPROPS;
	PACKER_VOID(_pack) { return m2v2_remote_pack_GET(args->url, flags, DL()); }
	GError *err = _resolve_meta2(args, _prefer_slave(), _pack, &beans, NULL);
	return _reply_simplified_beans_legacy(args, err, beans);
}

static GError *_m2_json_delete (struct req_args_s *args,
		struct json_object *jbody) {
	GError *err = NULL;
	const gboolean create_delete_marker =
			_request_get_flag(args, "delete_marker");
	gboolean bypass_governance = _request_get_flag(args, "bypass_governance");
	const gboolean dryrun = _request_get_flag(args, "dryrun");

	/* used from oio-swift for "sharding" in containers */
	const char* force_versioning = g_tree_lookup(args->rq->tree_headers,
			PROXYD_HEADER_FORCE_VERSIONING);
	oio_ext_set_force_versioning(force_versioning);

	struct json_object *jdests = NULL;
	json_object_object_get_ex(jbody, "replication_destinations", &jdests);
	const gchar *destinations = !jdests ? NULL : json_object_get_string(jdests);

	PACKER_VOID(_pack) { return m2v2_remote_pack_DEL (args->url,
			bypass_governance, create_delete_marker, dryrun, destinations, DL()); }
	gboolean delete_marker = FALSE;
	gint64 version = -1;
	struct list_result_s del_result = {0};
	m2v2_list_result_init(&del_result);
	err = _resolve_meta2(args, _prefer_master(), _pack,
			&del_result, m2v2_list_result_extract);

	for (GSList *l = del_result.beans; !err && l; l = l->next) {
		gpointer bean = l->data;
		if (DESCR(bean) != &descr_struct_ALIASES) {
			continue;
		}

		delete_marker = ALIASES_get_deleted(bean);
		version = ALIASES_get_version(bean);
	}

	if (!err) {
		gchar *version_str = NULL;
		if (version == -1) {
			/* XXX: we did not receive any alias bean.
			 * This happens when we remove a delete marker: the meta2 does not
			 * want to emit any object event because both the object creation
			 * and "removal" have already been notified. */
			if (!oio_url_has(args->url, OIOURL_VERSION)) {
				GRID_WARN("BUG: a deletion without version id did not return "
						"the deleted alias or any delete marker (reqid=%s)",
						oio_ext_get_reqid());
				version_str = g_strdup("-1");
			} else {
				delete_marker = TRUE;
				version_str = g_strdup(oio_url_get(args->url, OIOURL_VERSION));
			}
		} else {
			version_str = g_strdup_printf("%"G_GUINT64_FORMAT, version);
		}
		if (delete_marker)
			args->rp->add_header(PROXYD_HEADER_DELETE_MARKER, g_strdup("true"));
		args->rp->add_header(PROXYD_HEADER_VERSION_ID, version_str);
	}

	m2v2_list_result_clean(&del_result);
	return err;
}

static enum http_rc_e action_m2_content_delete (struct req_args_s *args,
		struct json_object *jbody) {
	GError *err = NULL;
	err = _m2_json_delete(args, jbody);
	return _reply_m2_error (args, err);
}

// CONTENT{{
// POST /v3.0/{NS}/content/delete?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// If the versioning is enabled, you can create a delete marker over a specific version
//
// .. code-block:: text
//
//    POST /v3.0/OPENIO/content/delete?acct=my_account&ref=mycontainer&path=mycontent&version=9876543210&delete_marker=1 HTTP/1.1
//
// Unreference object from container
//
// .. code-block:: text
//
//    "x-oio-force-versioning: -1"
//
// You can delete this object as if the versioning is enabled
//
// .. code-block:: text
//
//    "x-oio-simulate-versioning: 1"
//
// Unreference object from container
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/delete?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_delete (struct req_args_s *args) {
	return rest_action(args, action_m2_content_delete);
}

static enum http_rc_e
_m2_content_delete_many (struct req_args_s *args, struct json_object * jbody) {
	const gboolean create_delete_marker =
			_request_get_flag(args, "delete_marker");
	const gboolean bypass_governance =
			_request_get_flag(args, "bypass_governance");
	const gboolean dryrun = _request_get_flag(args, "dryrun");
	/* used from oio-swift for "sharding" in containers */
	const char* force_versioning = g_tree_lookup(args->rq->tree_headers,
			PROXYD_HEADER_FORCE_VERSIONING);
	oio_ext_set_force_versioning(force_versioning);

	json_object *jarray = NULL;
	PACKER_VOID(_pack) { return m2v2_remote_pack_DEL (args->url,
			bypass_governance, create_delete_marker, dryrun, NULL, DL()); }

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

	if (jarray_len > proxy_bulk_max_delete_many)
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

		struct json_object *jname = NULL, *jversion = NULL;
		json_object_object_get_ex(jcontent, "name", &jname);
		json_object_object_get_ex(jcontent, "version", &jversion);
		const gchar *name = json_object_get_string(jname);
		oio_url_set(args->url, OIOURL_PATH, name);
		const gchar *version = jversion? json_object_get_string(jversion) : "";
		oio_url_set(args->url, OIOURL_VERSION, version);
		GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
		_bulk_item_result(gresponse, i, name, version, err, HTTP_CODE_NO_CONTENT);
		if (err) g_clear_error(&err);
	}

	g_string_append(gresponse, "]}");
	return _reply_success_json(args, gresponse);
}

// CONTENT{{
// POST /v3.0/{NS}/content/delete_many?acct={account}&ref={container}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// You can update system property policy.version of container
//
// .. code-block:: json
//
//    {
//      "contents":[{"name":"content0"}, {"name":"content1"}]
//    }
//
// Unreference many object from container
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/delete_many?acct=my_account&ref=mycontainer HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 55
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 146
//
// .. code-block:: json
//
//    {
//      "contents":[{"name":"content0","status":204,"message":"ok"},{"name":"content1","status":204,"message":"ok"}]
//    }
//
// }}CONTENT
enum http_rc_e action_content_delete_many (struct req_args_s *args) {
	return rest_action(args, _m2_content_delete_many);
}

// CONTENT{{
// POST /v3.0/{NS}/content/touch?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Send an event to update object and object size on container.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/touch?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_touch (struct req_args_s *args) {
	return rest_action (args, action_m2_content_touch);
}

// CONTENT{{
// POST /v3.0/{NS}/content/spare?acct={account_name}&ref={container_name}&path={file_path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Get spare chunk addresses, in order to replace broken or missing chunks.
// Doesn't work with "single" storage policy.
//
// Sample request:
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/spare?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    x-oio-content-meta-size: 64
//    x-oio-content-meta-id: 2996752DFD7205006B73F17AD315AA2B
//    Content-Length: 182
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: text
//
//    {
//      "notin": <list of current chunks>,
//      "broken": <list of broken chunks>
//    }
//
//
// Sample response:
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 292
//
// .. code-block:: json
//
//    {
//      "aliases":[],
//      "headers":[],
//      "chunks":[{"id":"http:\/\/127.0.0.1:6011\/FFD794D6527AC176..."}]
//    }
//
// }}CONTENT
enum http_rc_e action_content_spare (struct req_args_s *args) {
	return rest_action (args, action_m2_content_spare);
}

// CONTENT{{
// POST /v3.0/{NS}/content/get_properties?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Get object properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/get_properties?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 200 OK
//    Connection: Close
//    Content-Type: application/json
//    Content-Length: 17
//    x-oio-content-meta-chunk-method: plain/nb_copy=1
//    x-oio-content-meta-ctime: 1533215985
//    x-oio-content-meta-deleted: False
//    x-oio-content-meta-hash: 26CBCBBF52F37322FAC57B8AC0E4E130
//    x-oio-content-meta-hash-method: md5
//    x-oio-content-meta-id: B03A29AA737205002C4D414D4C12FDC5
//    x-oio-content-meta-size: 180
//    x-oio-content-meta-mime-type: application/octet-stream
//    x-oio-content-meta-name: mycontent
//    x-oio-content-meta-policy: SINGLE
//    x-oio-content-meta-version: 1533215985187506
//
//    {"properties":{}}
//
// }}CONTENT
enum http_rc_e action_content_prop_get (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propget);
}

// CONTENT{{
// POST /v3.0/{NS}/content/set_properties?acct={account}&ref={container}?&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    {
//      "properties":{"test":"1"}
//    }
//
// Set object properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/set_properties?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 27
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_prop_set (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propset);
}

// CONTENT{{
// POST /v3.0/{NS}/content/del_properties?acct={account}&ref={container}?&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// .. code-block:: json
//
//    ["test"]
//
// Delete object properties.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/del_properties?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//    Content-Length: 8
//    Content-Type: application/x-www-form-urlencoded
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_prop_del (struct req_args_s *args) {
	return rest_action (args, action_m2_content_propdel);
}

// CONTENT{{
// POST /v3.0/{NS}/content/drain?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Remove all the chunks of a content but keep the properties. We can replace the
// data or the properties of the content but no action needing the removed chunks
// are accepted
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/drain?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_drain(struct req_args_s *args) {
	PACKER_VOID(_pack) {return m2v2_remote_pack_content_DRAIN(args->url, DL());}
	GError *err = _resolve_meta2(args, _prefer_master(), _pack, NULL, NULL);
	return _reply_m2_error(args, err);
}

// CONTENT{{
// POST /v3.0/{NS}/content/purge?acct={account}&ref={container}&path={file path}
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Purge object content.
//
// .. code-block:: http
//
//    POST /v3.0/OPENIO/content/purge?acct=my_account&ref=mycontainer&path=mycontent HTTP/1.1
//    Host: 127.0.0.1:6000
//    User-Agent: curl/7.47.0
//    Accept: */*
//
// .. code-block:: http
//
//    HTTP/1.1 204 No Content
//    Connection: Close
//    Content-Length: 0
//
// }}CONTENT
enum http_rc_e action_content_purge (struct req_args_s *args) {
	return rest_action (args, action_m2_content_purge);
}
