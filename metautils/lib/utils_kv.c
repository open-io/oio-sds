/*
OpenIO SDS metautils
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

#include "metautils.h"

struct kv_convert_ctx_s
{
	gboolean error_met;
	GSList *pairs;
	GError **err;
	gboolean copy;
};

static void
ht_iterator(gpointer k, gpointer v, gpointer u)
{
	struct kv_convert_ctx_s *ctx;
	key_value_pair_t *pair;

	ctx = u;
	if (!ctx || ctx->error_met)
		return;
	if (!(pair = g_try_malloc0(sizeof(key_value_pair_t)))) {
		GSETERROR(ctx->err, "Memory allocation failure");
		ctx->error_met = TRUE;
		return;
	}
	if (ctx->copy) {
		pair->key = g_strdup(k);
		pair->value = metautils_gba_dup(v);
	}
	else {
		pair->key = k;
		pair->value = (GByteArray *) v;
	}
	ctx->pairs = g_slist_append(ctx->pairs, pair);
}

GSList *
key_value_pairs_convert_from_map(GHashTable * ht, gboolean copy, GError ** err)
{
	struct kv_convert_ctx_s ctx;

	ctx.error_met = FALSE;
	ctx.pairs = NULL;
	ctx.err = err;
	ctx.copy = copy;

	if (!ht) {
		GSETERROR(err, "Invalid parameter");
		return NULL;
	}
	g_hash_table_foreach(ht, ht_iterator, &ctx);
	if (ctx.error_met) {
		if (ctx.pairs) {
			g_slist_foreach(ctx.pairs, key_value_pair_gclean, NULL);
			g_slist_free(ctx.pairs);
		}
		GSETERROR(err, "conversion error");
		return NULL;
	}

	return ctx.pairs;
}

void
key_value_pair_clean(key_value_pair_t * kv)
{
	if (!kv)
		return;
	if (kv->key) {
		g_free(kv->key);
		kv->key = NULL;
	}
	if (kv->value) {
		g_byte_array_free(kv->value, TRUE);
		kv->value = NULL;
	}
	g_free(kv);
}

void
key_value_pair_gclean(gpointer p, gpointer u)
{
	(void) u;
	key_value_pair_clean((key_value_pair_t *) p);
}

