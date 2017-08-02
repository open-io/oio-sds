/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

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

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_utils.h>

#include <core/oiolb.h>
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

	addr_info_t ai = {{0}};
	if (!err && !grid_string_to_addrinfo(netloc, &ai))
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"could not parse [%s] to addrinfo", netloc);
	if (!err)
		*location = location_from_addr_info(&ai);

out:
	g_free(netloc);
	return err;
}

//------------------------------------------------------------------------------

// TODO: factorize with _gen_chunk() from meta2_utils.c
static gpointer
_gen_chunk_bean(const char *straddr)
{
	guint8 binid[32];
	gchar strid[65];
	gchar *chunkid = NULL;
	struct bean_CHUNKS_s *chunk = NULL;

	oio_buf_randomize (binid, sizeof(binid));
	oio_str_bin2hex (binid, sizeof(binid), strid, sizeof(strid));
	chunk = _bean_create(&descr_struct_CHUNKS);
	chunkid = m2v2_build_chunk_url (straddr, strid);
	CHUNKS_set2_id(chunk, chunkid);

	g_free(chunkid);
	return (gpointer)chunk;
}

//------------------------------------------------------------------------------

GError*
get_spare_chunks(struct oio_lb_s *lb, const char *pool,
		GSList **result)
{
	GError *err = NULL;
	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
	void _on_id(oio_location_t loc, const char *id)
	{
		(void)loc;
		char *shifted = g_strdup(id);
		meta1_url_shift_addr(shifted);
		g_ptr_array_add(ids, shifted);
	}
	err = oio_lb__poll_pool(lb, pool, NULL, _on_id, NULL);
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria (pool=%s): ",
				ids->len, pool);
	} else {
		for (int i = 0; i < (int)ids->len; i++) {
			*result = g_slist_prepend(*result,
					_gen_chunk_bean(g_ptr_array_index(ids, i)));
		}
	}
	g_ptr_array_free(ids, TRUE);
	return err;
}

//------------------------------------------------------------------------------

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
get_conditioned_spare_chunks(struct oio_lb_s *lb, const char *pool,
		const gchar *ns_name, GSList *already, GSList *broken,
		GSList **result)
{
	GError *err = NULL;
	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);

	g_rw_lock_reader_lock(&lb->lock);
	struct oio_lb_pool_s *pool_obj = g_hash_table_lookup(lb->pools, pool);
	oio_location_t *avoid = convert_chunks_to_locations(pool_obj,
			ns_name, broken);
	oio_location_t *known = convert_chunks_to_locations(pool_obj,
			ns_name, already);
	g_rw_lock_reader_unlock(&lb->lock);

	void _on_id(oio_location_t loc, const char *id)
	{
		(void)loc;
		char *shifted = g_strdup(id);
		meta1_url_shift_addr(shifted);
		g_ptr_array_add(ids, shifted);
	}
	err = oio_lb__patch_with_pool(lb, pool, avoid, known, _on_id, NULL);
	if (err) {
		g_prefix_error(&err,
				"found only %u services matching the criteria: ",
				ids->len);
	}
	if (!err) {
		if ((int)ids->len == 0)
			err = NEWERROR(CODE_BAD_REQUEST,
				"too much beans in the blacklist");
		for (int i = 0; i < (int)ids->len; i++) {
			*result = g_slist_prepend(*result,
					_gen_chunk_bean(g_ptr_array_index(ids, i)));
		}
	}

	g_ptr_array_free(ids, TRUE);
	g_free(avoid);
	g_free(known);
	return err;
}

