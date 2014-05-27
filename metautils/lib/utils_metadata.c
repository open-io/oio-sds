#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "grid.metautils"
#endif

#include "metautils.h"

#define METADATA_HT_CREATE() g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free)

GHashTable*
metadata_create_empty(void)
{
	return METADATA_HT_CREATE();
}

GHashTable*
metadata_unpack_buffer(const guint8 *data, gsize size, GError **error)
{
	GHashTable *ht;
	gchar **tokens, **tok;

	if (!data) {
		GSETERROR(error, "Invalid paramater (%p)", data);
		return NULL;
	}

	if (!size)
		return METADATA_HT_CREATE();

	tokens = buffer_split(data, size, ";", 0);
	if (!tokens) {
		GSETERROR(error,"split error");
		return NULL;
	}

	ht = METADATA_HT_CREATE();
	for (tok=tokens; *tok && **tok ;tok++) {
		gchar **pair_tokens, *stripped;

		pair_tokens = g_strsplit(*tok, "=", 2);
		if (!pair_tokens)/*skip this empty pair*/
			continue;
		switch (g_strv_length(pair_tokens)) {
		case 0U:/*strange case, let's happily ignore it*/
			break;
		case 1U:/*single key with no value*/
			stripped = g_strstrip(pair_tokens[0]);
			if (stripped && *stripped)
				g_hash_table_insert(ht, g_strdup(stripped), g_strdup(""));
			break;
		case 2U:
			stripped = g_strstrip(pair_tokens[0]);
			if (stripped && *stripped)
				g_hash_table_insert(ht, g_strdup(stripped), g_strdup(pair_tokens[1]));
			break;
		}
		g_strfreev(pair_tokens);
	}

	g_strfreev(tokens);
	return ht;
}

GHashTable*
metadata_unpack_gba(GByteArray *gba, GError **error)
{
	if (!gba) {
		GSETERROR(error,"Inavalid parameter (gba==NULL)");
		return NULL;
	}
	return metadata_unpack_buffer(gba->data, gba->len, error);
}

GHashTable*
metadata_unpack_string(const gchar *data, GError **error)
{
	if (!data) {
		GSETERROR(error,"Inavalid parameter (str==NULL)");
		return NULL;
	}
	return metadata_unpack_buffer((guint8*)data, strlen(data), error);
}

GByteArray*
metadata_pack(GHashTable *unpacked, GError **error)
{
	gboolean first;
	GByteArray *gba;
	GHashTableIter iter;
	gpointer k, v;
	
	if (!unpacked) {
		GSETERROR(error,"NULL unpacked form");
		return NULL;
	}
	gba = g_byte_array_sized_new(1+(32 * g_hash_table_size(unpacked)));
	g_hash_table_iter_init(&iter, unpacked);
	for (first=TRUE; g_hash_table_iter_next(&iter, &k, &v) ;) {
		if (first)
			first = FALSE;
		else
			g_byte_array_append(gba, (guint8*)";", 1);
		g_byte_array_append(gba, (guint8*)k, strlen((gchar*)k));
		g_byte_array_append(gba, (guint8*)"=", 1);
		g_byte_array_append(gba, (guint8*)v, strlen((gchar*)v));
	}
	return gba;
}

gboolean
metadata_equal(const gchar *md1, const gchar *md2, GSList **diff)
{
	gboolean ret = TRUE;
	GHashTable *unpacked1, *unpacked2, *tmp;
	GHashTableIter iter1;
	gpointer k1, v1, v2;

	// if both metadata are NULL, return TRUE
	if (!md1 && !md2)
		return TRUE;

	// special cases when we do not need diff
	if (!diff) {
		// if only one of the metadata is not NULL, return FALSE
		if (!md1 || !md2)
			return FALSE;
		// if length of metadata is different, return FALSE
		if (strlen(md1) != strlen(md2))
			return FALSE;
	}

	// unpack metadata to hashtables
	unpacked1 = md1 ? metadata_unpack_string(md1, NULL) : METADATA_HT_CREATE();
	unpacked2 = md2 ? metadata_unpack_string(md2, NULL) : METADATA_HT_CREATE();

	// if unpacked2 has more keys than unpacked1, swap them so we always
	// iterate over the biggest one
	if (g_hash_table_size(unpacked2) > g_hash_table_size(unpacked1)) {
		tmp = unpacked2;
		unpacked2 = unpacked1;
		unpacked1 = tmp;
	}

	// look for all keys of table 1 in table 2
	g_hash_table_iter_init(&iter1, unpacked1);
	while (g_hash_table_iter_next(&iter1, &k1, &v1)) {
		v2 = g_hash_table_lookup(unpacked2, k1);
		if (!v2 || 0 != g_strcmp0(v2, v1)) {
			ret = FALSE;
			if (diff)
				*diff = g_slist_prepend(*diff, g_strdup(k1));
			else
				break;
		}
	}

	g_hash_table_destroy(unpacked1);
	g_hash_table_destroy(unpacked2);

	return ret;
}

GHashTable*
metadata_remove_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error)
{
	GHashTable *ht_result;
	GHashTableIter iter;
	gpointer k, v;
	
	if (!unpacked) {
		GSETERROR(error,"NULL unpacked form");
		return NULL;
	}
	ht_result = METADATA_HT_CREATE();
	g_hash_table_iter_init(&iter, unpacked);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		if (!g_str_has_prefix(k, prefix)) {
			g_hash_table_insert(ht_result, g_strdup(k), g_strdup(v));
		}
	}
	return ht_result;
}

GHashTable*
metadata_extract_prefixed(GHashTable *unpacked, const gchar *prefix, GError **error)
{
	GHashTable *ht_result;
	GHashTableIter iter;
	gpointer k, v;
	
	if (!unpacked) {
		GSETERROR(error,"NULL unpacked form");
		return NULL;
	}
	ht_result = METADATA_HT_CREATE();
	g_hash_table_iter_init(&iter, unpacked);
	while (g_hash_table_iter_next(&iter, &k, &v)) {
		if (g_str_has_prefix(k, prefix)) {
			g_hash_table_insert(ht_result, g_strdup(k), g_strdup(v));
		}
	}
	return ht_result;
}

void
metadata_merge(GHashTable *base, GHashTable *complement)
{
	GHashTableIter iter;
	gpointer k, v;
	
	if (!base || complement)
		return;

	g_hash_table_iter_init(&iter, complement);
	while (g_hash_table_iter_next(&iter, &k, &v))
		g_hash_table_insert(base, g_strdup(k), g_strdup(v));
}

void
metadata_add_time(GHashTable *md, const gchar *key, GTimeVal *t) 
{
	GTimeVal time_used;
	
	if (!md || !key)
		return;

	if (t == NULL)
		g_get_current_time(&time_used);
	else
		memcpy(&time_used, t, sizeof(GTimeVal));

	g_hash_table_insert(md, g_strdup(key), g_strdup_printf("%li", time_used.tv_sec));
}

void
metadata_add_printf(GHashTable *md, const gchar *key, const gchar * format, ...)
{
	va_list args;
	gchar *str_formated;
	
	if (!md || !key || !format)
		return;

	va_start(args,format);
	str_formated = g_strdup_vprintf(format, args);
	va_end(args);

	g_hash_table_insert(md, g_strdup(key), str_formated);
}

