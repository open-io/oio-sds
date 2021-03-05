/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS
Copyright (C) 2021 OVH SAS

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

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_utils.h>

#include <core/oiolb.h>
#include <core/lb_variables.h>
#include <core/url_ext.h>
#include <glib.h>

static GError*
location_from_chunk_id(const gchar *chunk_id, const gchar *ns_name,
		struct oio_lb_pool_s *pool, oio_location_t *location)
{
	g_assert_nonnull(location);
	GError *err = NULL;
	if (chunk_id == NULL || strlen(chunk_id) <= 0)
		return NEWERROR(CODE_INTERNAL_ERROR, "emtpy chunk id");

	gchar *netloc = NULL;
	oio_parse_chunk_url(chunk_id, NULL, &netloc, NULL);

	if (pool) {
		gchar *key = oio_make_service_key(ns_name, NAME_SRVTYPE_RAWX, netloc);
		struct oio_lb_item_s *item = oio_lb_pool__get_item(pool, key);
		g_free(key);
		if (item) {
			*location = item->location;
			g_free(item);
			goto out;
		}
	}

	addr_info_t ai = {{0}, 0, 0};
	if (!err && !grid_string_to_addrinfo(netloc, &ai))
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"could not parse [%s] to addrinfo", netloc);
	if (!err)
		*location = location_from_addr_info(&ai);

out:
	g_free(netloc);
	return err;
}

/* ------------------------------------------------------------------------- */

GError*
get_spare_chunks_focused(struct oio_url_s *url, const gchar *pos,
		struct oio_lb_s *lb, struct storage_policy_s *policy,
		oio_location_t pin, int mode,
		GSList **result)
{
	GError *err = NULL;
	GSList *beans = NULL;
	const gchar *pool = storage_policy_get_service_pool(policy);

	GRID_TRACE("%s pin=%"G_GINT64_MODIFIER"x mode=%d", __FUNCTION__, pin, mode);

	void _on_id(struct oio_lb_selected_item_s *sel, gpointer u UNUSED)
	{
		struct bean_CHUNKS_s *chunk = generate_chunk_bean(url, pos, sel, policy);
		struct bean_PROPERTIES_s *prop = generate_chunk_quality_bean(
				sel, CHUNKS_get_id(chunk)->str, NULL);
		beans = g_slist_prepend(beans, prop);
		beans = g_slist_prepend(beans, chunk);
	}
	err = oio_lb__poll_pool_around(lb, pool, pin, mode, _on_id, NULL);
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria (pool=%s): ",
				g_slist_length(beans) / 2, pool);
		_bean_cleanl2(beans);
	} else {
		*result = beans;
	}
	return err;
}

/* ------------------------------------------------------------------------- */

static oio_location_t *
convert_chunks_to_locations(struct oio_lb_pool_s *pool, const gchar *ns_name,
		GSList *src)
{
	GError *err = NULL;
	GArray *result = g_array_new(TRUE, TRUE, sizeof(oio_location_t));

	for (GSList *l = src; l; l = l->next) {
		if (!l->data || DESCR(l->data) != &descr_struct_CHUNKS)
			continue;

		oio_location_t loc = 0;
		err = location_from_chunk_id(CHUNKS_get_id(l->data)->str,
				ns_name, pool, &loc);
		if (err) {
			GRID_WARN("CHUNK -> location conversion error: (%d) %s",
					err->code, err->message);
			g_clear_error(&err);
			continue;
		}
		g_array_append_val(result, loc);
	}

	return (oio_location_t*) g_array_free(result, FALSE);
}

GError*
get_conditioned_spare_chunks(struct oio_url_s *url, const gchar *pos,
		struct oio_lb_s *lb,
		struct storage_policy_s *policy,
		const gchar *ns_name, GSList *already, GSList *broken,
		GSList **result)
{
	GError *err = NULL;
	GSList *beans = NULL;
	const gchar *pool = storage_policy_get_service_pool(policy);

	GRID_TRACE("%s", __FUNCTION__);

	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool_obj = g_hash_table_lookup(lb->pools, pool);
	oio_location_t *avoid = convert_chunks_to_locations(pool_obj,
			ns_name, broken);
	oio_location_t *known = convert_chunks_to_locations(pool_obj,
			ns_name, already);
	g_rw_lock_reader_unlock(&lb->lock);

	void _on_id(struct oio_lb_selected_item_s *sel, gpointer u UNUSED)
	{
		struct bean_CHUNKS_s *chunk = generate_chunk_bean(url, pos, sel,
				policy);
		struct bean_PROPERTIES_s *prop = generate_chunk_quality_bean(
				sel, CHUNKS_get_id(chunk)->str, NULL);
		beans = g_slist_prepend(beans, prop);
		beans = g_slist_prepend(beans, chunk);
	}
	err = oio_lb__patch_with_pool(lb, pool, avoid, known, _on_id, NULL);
	guint chunks_count = g_slist_length(beans) / 2;
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria (pool=%s): ",
				chunks_count, pool);
		_bean_cleanl2(beans);
	} else if (chunks_count == 0) {
		err = NEWERROR(CODE_BAD_REQUEST,
			"too many locations in the blacklist "
			"(%u already used, %u to avoid)",
			g_slist_length(already), g_slist_length(broken));
		_bean_cleanl2(beans);
	} else {
		*result = beans;
	}

	g_free(avoid);
	g_free(known);
	return err;
}

/* ------------------------------------------------------------------------- */

static gchar*
m2v2_build_chunk_url (const char *srv, const char *id)
{
	return g_strconcat("http://", srv, "/", id, NULL);
}

void
m2v2_extend_chunk_url(struct oio_url_s *url, const gchar *policy,
		struct bean_CHUNKS_s *chunk)
{
	GString *chunk_id = CHUNKS_get_id(chunk);
	if (chunk_id && chunk_id->len > 0 &&
			g_str_has_prefix(chunk_id->str, "http")) {
		return;
	}
	EXTRA_ASSERT(policy != NULL);
	GString *chunk_url = g_string_sized_new(LIMIT_LENGTH_CHUNKURL);
	g_string_append_static(chunk_url, "http://");
	g_string_append(chunk_url, chunk_id->str);
	g_string_append_c(chunk_url, '/');
	/* Use the internal buffer to avoid string copies. */
	gchar *id_offset = chunk_url->str + chunk_url->len;
	size_t id_max_len = LIMIT_LENGTH_CHUNKURL - chunk_url->len;
	oio_url_compute_chunk_id(url, CHUNKS_get_position(chunk)->str, policy,
			id_offset, id_max_len);
	/* We need to update the length or the next operation won't copy
	 * the whole URL. */
	g_string_set_size(chunk_url, strlen(chunk_url->str));
	CHUNKS_set_id(chunk, chunk_url);
	g_string_free(chunk_url, TRUE);
}

struct gen_ctx_s
{
	struct oio_url_s *url;
	const struct storage_policy_s *pol;
	struct oio_lb_s *lb;
	guint8 *uid;
	gsize uid_size;
	guint8 h[16];
	gint64 size;
	gint64 chunk_size;
	gint64 pos;
	gint64 version;

	/* location focused mode */
	oio_location_t pin;
	int mode;

	GSList **out;
};

static void
_collect_bean(struct gen_ctx_s *ctx, gpointer bean)
{
	*ctx->out = g_slist_prepend(*ctx->out, bean);
}

static void
_m2_generate_alias_header(struct gen_ctx_s *ctx)
{
	const gchar *p;
	p = ctx->pol ? storage_policy_get_name(ctx->pol) : "none";

	GRID_TRACE2("%s(%s)", __FUNCTION__, oio_url_get(ctx->url, OIOURL_WHOLE));
	const gint64 now = oio_ext_real_time ();

	struct bean_ALIASES_s *alias = _bean_create(&descr_struct_ALIASES);
	ALIASES_set2_alias(alias, oio_url_get(ctx->url, OIOURL_PATH));
	gint64 version;
	if (!oio_url_has(ctx->url, OIOURL_VERSION) ||
			(version = g_ascii_strtoll(
				oio_url_get(ctx->url, OIOURL_VERSION), NULL, 10)) <= 0) {
		version = now;
		gchar sver[LIMIT_LENGTH_VERSION] = {0};
		g_snprintf(sver, sizeof(sver), "%"G_GINT64_FORMAT, version);
		oio_url_set(ctx->url, OIOURL_VERSION, sver);
	}
	ALIASES_set_version(alias, version);
	ALIASES_set_ctime(alias, now / G_TIME_SPAN_SECOND);
	ALIASES_set_mtime(alias, now / G_TIME_SPAN_SECOND);
	ALIASES_set_deleted(alias, FALSE);
	ALIASES_set2_content(alias, ctx->uid, ctx->uid_size);
	_collect_bean(ctx, alias);

	struct bean_CONTENTS_HEADERS_s *header;
	header = _bean_create(&descr_struct_CONTENTS_HEADERS);
	CONTENTS_HEADERS_set_size(header, ctx->size);
	CONTENTS_HEADERS_set2_id(header, ctx->uid, ctx->uid_size);
	CONTENTS_HEADERS_set2_policy(header, p);
	CONTENTS_HEADERS_nullify_hash(header);
	CONTENTS_HEADERS_set_ctime(header, now / G_TIME_SPAN_SECOND);
	CONTENTS_HEADERS_set_mtime(header, now / G_TIME_SPAN_SECOND);
	CONTENTS_HEADERS_set2_mime_type(header, OIO_DEFAULT_MIMETYPE);

	GString *chunk_method = storage_policy_to_chunk_method(ctx->pol);
	// TODO(FVE): store the name of the algorithm used to generate chunk IDs
	CONTENTS_HEADERS_set_chunk_method(header, chunk_method);
	g_string_free(chunk_method, TRUE);
	_collect_bean(ctx, header);
}

struct bean_CHUNKS_s *
generate_chunk_bean(struct oio_url_s *url, const gchar *pos,
		struct oio_lb_selected_item_s *sel,
		const struct storage_policy_s *policy)
{
	guint8 binid[32];
	gchar *chunkid = NULL, strid[65];

	if (oio_lb_random_chunk_ids) {
		oio_buf_randomize(binid, sizeof(binid));
		oio_str_bin2hex(binid, sizeof(binid), strid, sizeof(strid));
	} else {
		GError *err = oio_url_compute_chunk_id(
				url, pos, storage_policy_get_name(policy),
				strid, sizeof(strid));
		if (err != NULL) {
			GRID_WARN("Cannot compute chunk ID, will generate a random one: "
					"%s (reqid=%s)",
					err->message, oio_ext_get_reqid());
			oio_buf_randomize(binid, sizeof(binid));
			oio_str_bin2hex(binid, sizeof(binid), strid, sizeof(strid));
			g_clear_error(&err);
		}
	}

	if (sel->item->id) {
		gchar shifted_id[LIMIT_LENGTH_SRVID];
		g_strlcpy(shifted_id, sel->item->id, sizeof(shifted_id));
		meta1_url_shift_addr(shifted_id);
		chunkid = m2v2_build_chunk_url(shifted_id, strid);
	} else {
		/* legacy function called here to build URL
		 * when chunks were stored on
		 * other backend than SDS */
		GRID_ERROR("Deprecated code path called");
		EXTRA_ASSERT(policy != NULL);
	}

	struct bean_CHUNKS_s *chunk = _bean_create(&descr_struct_CHUNKS);
	CHUNKS_set2_id(chunk, chunkid);
	CHUNKS_set_ctime(chunk, oio_ext_real_time() / G_TIME_SPAN_SECOND);
	g_free(chunkid);

	return chunk;
}

struct bean_PROPERTIES_s *
generate_chunk_quality_bean(struct oio_lb_selected_item_s *sel,
		const gchar *chunkid, struct oio_url_s *url)
{
	GString *qual = oio_selected_item_quality_to_json(NULL, sel);
	struct bean_PROPERTIES_s *prop = _bean_create(&descr_struct_PROPERTIES);
	gchar *prop_key = g_alloca(
			sizeof(OIO_CHUNK_SYSMETA_PREFIX) + strlen(chunkid));
	sprintf(prop_key, OIO_CHUNK_SYSMETA_PREFIX"%s", chunkid);
	PROPERTIES_set2_key(prop, prop_key);
	PROPERTIES_set2_value(prop, (guint8*)qual->str, qual->len);
	if (url && oio_url_has(url, OIOURL_PATH))
		PROPERTIES_set2_alias(prop, oio_url_get(url, OIOURL_PATH));

	g_string_free(qual, TRUE);
	return prop;
}

static void
_gen_chunk(struct gen_ctx_s *ctx, struct oio_lb_selected_item_s *sel,
		gint64 cs, guint pos, gint subpos)
{
	gchar strpos[24];

	if (subpos < 0)
		g_snprintf(strpos, sizeof(strpos), "%u", pos);
	else
		g_snprintf(strpos, sizeof(strpos), "%u.%d", pos, subpos);

	struct bean_CHUNKS_s *chunk = generate_chunk_bean(
			ctx->url, strpos, sel, ctx->pol);
	CHUNKS_set2_content(chunk, ctx->uid, ctx->uid_size);
	CHUNKS_set2_hash(chunk, ctx->h, sizeof(ctx->h));
	CHUNKS_set_size(chunk, cs);
	CHUNKS_set2_position(chunk, strpos);
	_collect_bean(ctx, chunk);

	/* Create a property to represent the quality of the selected chunk. */
	struct bean_PROPERTIES_s *prop = generate_chunk_quality_bean(
			sel, CHUNKS_get_id(chunk)->str, ctx->url);
	_collect_bean(ctx, prop);

}

static GError*
_m2_generate_chunks(struct gen_ctx_s *ctx,
		gint64 mcs /* actual metachunk size */,
		gboolean subpos)
{
	GError *err = NULL;

	_m2_generate_alias_header(ctx);

	guint pos = ctx->pos;
	gint64 esize = MAX(ctx->size, 1);
	for (gint64 s = 0; s < esize && !err; s += mcs, ++pos) {
		int i = 0;
		void _on_id(struct oio_lb_selected_item_s *sel, gpointer u UNUSED)
		{
			_gen_chunk(ctx, sel, ctx->chunk_size, pos, subpos? i : -1);
			i++;
		}
		const char *pool = storage_policy_get_service_pool(ctx->pol);
		// FIXME(FVE): set last argument

		err = oio_lb__poll_pool_around(ctx->lb, pool,
				ctx->pin, ctx->mode, _on_id, NULL);

		if (err != NULL) {
			g_prefix_error(&err, "at position %u: did not find enough "
					"services matching the criteria for pool [%s]: ",
					pos, pool);
		}
	}

	return err;
}

GError*
oio_generate_beans(struct oio_url_s *url, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		GSList **out)
{
	return oio_generate_focused_beans(url, 0, size, chunk_size, pol, lb, 0, 0, out);
}

GError *
oio_generate_focused_beans(
		struct oio_url_s *url, gint64 pos, gint64 size, gint64 chunk_size,
		struct storage_policy_s *pol, struct oio_lb_s *lb,
		oio_location_t pin, int mode,
		GSList **out)
{
	EXTRA_ASSERT(url != NULL);

	GRID_TRACE("%s pin=%"G_GINT64_MODIFIER"x mode=%d", __FUNCTION__, pin, mode);

	if (!oio_url_has(url, OIOURL_PATH))
		return BADREQ("Missing path");
	if (size < 0)
		return BADREQ("Invalid size");
	if (chunk_size <= 0)
		return BADREQ("Invalid chunk size");

	RANDOM_UID(_uid, uid_size);
	guint8 *uid = (guint8 *) &_uid;
	const gchar *content_id = oio_url_get(url, OIOURL_CONTENTID);
	if (content_id) {
		gsize len = strlen(content_id);
		uid_size = len/2;
		oio_str_hex2bin(content_id, uid, uid_size);
	}

	struct gen_ctx_s ctx = {};
	ctx.url = oio_url_dup(url);
	ctx.pol = pol;
	ctx.uid = uid;
	ctx.uid_size = uid_size;
	ctx.size = size;
	ctx.chunk_size = chunk_size;
	ctx.pos = pos;
	ctx.lb = lb;
	ctx.out = out;
	ctx.pin = pin;
	ctx.mode = mode;

	GError *err = NULL;
	if (!pol) {
		err = _m2_generate_chunks(&ctx, chunk_size, 0);
	} else {
		gint64 k;
		switch (data_security_get_type(storage_policy_get_data_security(pol))) {
			case STGPOL_DS_PLAIN:
				err = _m2_generate_chunks(&ctx, chunk_size, 0);
				break;
			case STGPOL_DS_EC:
				k = storage_policy_parameter(pol, DS_KEY_K, 6);
				err = _m2_generate_chunks(&ctx, k*chunk_size, TRUE);
				break;
			default:
				err = NEWERROR(CODE_POLICY_NOT_SUPPORTED, "Invalid policy type");
				break;
		}
	}

	oio_url_clean(ctx.url);
	return err;
}
