/*
OpenIO SDS sqliterepo
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO SAS, as part of OpenIO SDS

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 3.0 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library.
*/

#include <stddef.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <metautils/lib/metautils.h>
#include <metautils/lib/metacomm.h>
#include <metautils/lib/codec.h>

#include "sqliterepo.h"
#include "sqlx_remote.h"
#include "version.h"
#include "hash.h"
#include "cache.h"
#include "election.h"
#include "internals.h"

#define OV(v) ((struct object_version_s*)(v))

static struct object_version_s*
version_get(gboolean init, GTree *t, const struct hashstr_s *k)
{
	struct object_version_s *o;
	o = g_tree_lookup(t, k);
	if (!o && init) {
		o = g_malloc0(sizeof(struct object_version_s));
		o->version = 1;
		g_tree_replace(t, hashstr_dup(k), o);
	}
	return o;
}

static struct object_version_s *
version_getslen(gboolean init, GTree *t, const guint8 *ks, gsize ks_len)
{
	hashstr_t *k = hashstr_printf("%.*s", (int)ks_len, ks);
	struct object_version_s *o = version_get(init, t, k);
	g_free(k);
	return o;
}

GTree*
version_extract_from_admin(struct sqlx_sqlite3_s *sq3)
{
	return version_extract_from_admin_tree(sq3 ? sq3->admin : NULL);
}

static gboolean
hook_dump(gpointer k, gpointer v, gpointer u)
{
	GString *gstr = u;
	if (hashstr_len(k) <= 0 || !*hashstr_str(k))
		return FALSE;
	if (gstr->len > 0)
		g_string_append_c(gstr, ',');
	g_string_append_printf(gstr,
			"(%.*s,%"G_GINT64_FORMAT",%"G_GINT64_FORMAT")",
			(int)hashstr_len(k), hashstr_str(k),
			OV(v)->version, OV(v)->when);
	return FALSE;
}

gchar*
version_dump(GTree *t)
{
	EXTRA_ASSERT(t != NULL);
	GString *gstr = g_string_sized_new(128);
	if (t)
		g_tree_foreach(t, hook_dump, gstr);
	return g_string_free(gstr, FALSE);
}

#include <TableVersion.h>
#include <BaseVersion.h>
#include <asn_codecs.h>
#include <der_encoder.h>
#include <ber_decoder.h>

GByteArray*
version_encode(GTree *t)
{
	asn_enc_rval_t rv;
	GByteArray *encoded;
	struct BaseVersion bv = {{0}};

	gboolean runner(gpointer _k, gpointer _v, gpointer _u) {
		(void) _u;
		if (_k && _v && hashstr_len(_k) > 0) {
			struct object_version_s *v = _v;
			struct TableVersion *tv = ASN1C_CALLOC(1, sizeof(*tv));
			OCTET_STRING_fromBuf(&(tv->name), hashstr_str(_k), hashstr_len(_k));
			asn_int64_to_INTEGER(&(tv->version), v->version);
			asn_int64_to_INTEGER(&(tv->when), v->when);
			asn_sequence_add(&(bv.list), tv);
		}
		return FALSE;
	}

	GRID_TRACE2("%s(%p)", __FUNCTION__, t);
	g_tree_foreach(t, runner, NULL);

	encoded = g_byte_array_sized_new(128);
	rv = der_encode(&asn_DEF_BaseVersion, &bv, metautils_asn1c_write_gba, encoded);
	asn_DEF_BaseVersion.free_struct(&asn_DEF_BaseVersion, &bv, TRUE);

	if (0 >= rv.encoded) {
		g_byte_array_free(encoded, TRUE);
		GRID_WARN("BaseVersion encoding error : %s", rv.failed_type->name);
		return NULL;
	}

	return encoded;
}

GTree*
version_decode(guint8 *raw, gsize rawsize)
{
	struct BaseVersion *bv = NULL;
	asn_dec_rval_t rv;
	asn_codec_ctx_t ctx = {0};

	GRID_TRACE2("%s(%p,%"G_GSIZE_FORMAT")", __FUNCTION__, raw, rawsize);

	ctx.max_stack_size = ASN1C_MAX_STACK;
	rv = ber_decode(&ctx, &asn_DEF_BaseVersion, (void**)&bv, raw, rawsize);
	if (rv.code != RC_OK) {
		GRID_WARN("Decoder error (BaseVersion)");
		return NULL;
	}
	else {
		int i;
		GTree *t;

		EXTRA_ASSERT(bv != NULL);
		t = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

		for (i=0; i<bv->list.count; i++) {
			struct TableVersion *tv = bv->list.array[i];
			struct object_version_s *o;

			if (!tv || !tv->name.buf || tv->name.size <= 0) {
				GRID_TRACE2("%s table with no name", __FUNCTION__);
				continue;
			}

			o = version_getslen(1, t, tv->name.buf, tv->name.size);
			asn_INTEGER_to_int64(&(tv->version), &(o->version));
			asn_INTEGER_to_int64(&(tv->when), &(o->when));
		}

		asn_DEF_BaseVersion.free_struct(&asn_DEF_BaseVersion, bv, FALSE);
		return t;
	}
}

static GTree*
version_extract_effective_diff(TableSequence_t *seq)
{
	gint i;

	GTree *t = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);

	for (i=0; i<seq->list.count ;i++) {
		Table_t *table = seq->list.array[i];
		struct object_version_s *o = version_getslen(1, t,
				table->name.buf, table->name.size);
		o->version = 1;
	}

	return t;
}

static GTree*
version_apply_diff(GTree *src, GTree *diff)
{
	GTree *result;

	gboolean runner_init(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o;
		(void) u;
		o = version_get(1, result, k);
		o->when = ((struct object_version_s*)v)->when;
		o->version = ((struct object_version_s*)v)->version;
		return FALSE;
	}
	gboolean runner_diff(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o;
		(void) u;
		o = version_get(1, result, k);
		o->when = ((struct object_version_s*)v)->when;
		o->version += ((struct object_version_s*)v)->version;
		return FALSE;
	}

	result = g_tree_new_full(hashstr_quick_cmpdata, NULL, g_free, g_free);
	g_tree_foreach(src, runner_init, NULL);
	g_tree_foreach(diff, runner_diff, NULL);
	return result;
}

GTree*
version_extract_expected(GTree *current, TableSequence_t *changes)
{
	GTree *effective_diff, *expected_version;

	effective_diff = version_extract_effective_diff(changes);
	expected_version = version_apply_diff(current, effective_diff);
	g_tree_destroy(effective_diff);

	return expected_version;
}

GError*
version_validate_diff(GTree *current, GTree *expected, gint64 *worst)
{
	gboolean schema_change = FALSE;
	gint64 delta_max = 0, delta_min = 0;

	gboolean runner_schema(gpointer k, gpointer v, gpointer u) {
		(void) v;
		if (NULL == g_tree_lookup(u, k))
			schema_change = TRUE;
		return FALSE;
	}

	gboolean runner_diff(gpointer k, gpointer v, gpointer u) {
		struct object_version_s *o = g_tree_lookup(u, k);
		if (NULL != o) {
			gint64 d = OV(v)->version - o->version;
			if (d < 0) {
				if (d < delta_min)
					delta_min = MIN(d, delta_min);
			}
			else if (d > 0) {
				if (d > delta_max)
					delta_max = MAX(d, delta_max);
			}
		}
		return FALSE;
	}

	// check for schema changes
	g_tree_foreach(current, runner_schema, expected);
	g_tree_foreach(expected, runner_schema, current);
	// Now check the versions
	g_tree_foreach(current, runner_diff, expected);

	if (worst)
		*worst = 0;

	if (delta_max != 0 && delta_min != 0)
		return NEWERROR(CODE_CONCURRENT, "Concurrent content changes");

	if (delta_min < 0) {
		if (worst)
			*worst = delta_min;
		if (schema_change || delta_min < -1)
			return NEWERROR(CODE_PIPEFROM, "Local diff missed");
	}
	else if (delta_max > 0) {
		if (worst)
			*worst = delta_max;
		if (schema_change || delta_max > 1)
			return NEWERROR(CODE_PIPETO, "Remote diff missed");
	}

	return NULL;
}

