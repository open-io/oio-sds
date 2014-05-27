#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metautils"
#endif

#include "metautils.h"


struct key_value_pair_s*
key_value_pair_create(const gchar *k, const guint8 *v, gsize vs)
{
	struct key_value_pair_s *kv;
	kv = g_malloc0(sizeof(*kv));
	kv->key = g_strdup(k);
	kv->value = g_byte_array_append(g_byte_array_new(), v, vs);
	return kv;
}

GHashTable *
key_value_pairs_convert_to_map(GSList * pairs, gboolean copy, GError ** err)
{
	GSList *pair;
	GHashTable *result;

	result = g_hash_table_new_full(g_str_hash, g_str_equal,
			copy ? g_free : NULL,
			copy ? metautils_gba_clean : NULL);
	if (!result) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	for (pair = pairs; pair; pair = g_slist_next(pair)) {
		if(!pair->data)
			continue;
		key_value_pair_t *p = (key_value_pair_t *) pair->data;
		gchar *key = p->key;
		GByteArray *value = p->value;

		if (copy) {
			key = g_strdup(p->key);
			value = metautils_gba_dup(p->value);
		}
		g_hash_table_insert(result, key, value);
	}

	return result;
}

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

