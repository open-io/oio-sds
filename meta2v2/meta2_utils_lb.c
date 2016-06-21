/*
OpenIO SDS meta2v2
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

#include <stdlib.h>
#include <string.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_utils_lb.h>
#include <meta2v2/meta2_utils.h>

#include <glib.h>

static GError*
location_from_chunk_id(const gchar *chunk_id, oio_location_t *location)
{
	g_assert_nonnull(location);

	GError *err = NULL;
	if (chunk_id == NULL || strlen(chunk_id) <= 0)
		return NEWERROR(CODE_INTERNAL_ERROR, "emtpy chunk id");

	// TODO(srvid): do not suppose url contains an IP address
	char **tok = g_regex_split_simple(
			"(([[:digit:]]{1,3}\\.){3}[[:digit:]]{1,3}:[[:digit:]]{1,5})",
			chunk_id, 0, 0);
	if (!tok || g_strv_length(tok) < 3)
		err = NEWERROR(CODE_INTERNAL_ERROR, "could not parse chunk id");

	addr_info_t ai = {{0}};
	if (!err && !grid_string_to_addrinfo(tok[1], &ai))
		err = NEWERROR(CODE_INTERNAL_ERROR,
				"could not parse [%s] to addrinfo", tok[1]);
	if (!err)
		*location = location_from_addr_info(&ai);

	g_strfreev(tok);
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
get_spare_chunks(struct oio_lb_s *lb, const char *stgpol_name,
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
	if (!oio_lb__poll_pool(lb, stgpol_name, NULL, _on_id)) {
		err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE,
				"found only %u services matching the criteria",
				ids->len);
	}
	if (!err) {
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
convert_chunks_to_locations(GSList *src)
{
	GError *err = NULL;
	GArray *result = g_array_new(TRUE, TRUE, sizeof(oio_location_t));

	for (GSList *l = src; l; l = l->next) {
		if (!l->data || DESCR(l->data) != &descr_struct_CHUNKS)
			continue;

		oio_location_t loc = 0;
		err = location_from_chunk_id(CHUNKS_get_id(l->data)->str, &loc);
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
get_conditioned_spare_chunks(struct oio_lb_s *lb, const char *stgpol,
		GSList *already, GSList *broken, GSList **result)
{
	GError *err = NULL;
	GPtrArray *ids = g_ptr_array_new_with_free_func(g_free);
	oio_location_t *avoid = convert_chunks_to_locations(broken);
	oio_location_t *known = convert_chunks_to_locations(already);

	void _on_id(oio_location_t loc, const char *id)
	{
		(void)loc;
		char *shifted = g_strdup(id);
		meta1_url_shift_addr(shifted);
		g_ptr_array_add(ids, shifted);
	}
	if (!oio_lb__patch_with_pool(lb, stgpol, avoid, known, _on_id)) {
		err = NEWERROR(CODE_POLICY_NOT_SATISFIABLE,
				"found only %u services matching the criteria",
				ids->len);
	}
	if (!err) {
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

