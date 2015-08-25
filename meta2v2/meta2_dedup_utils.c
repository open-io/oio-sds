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

#include <metautils/lib/metautils.h>
#include <sqliterepo/sqlite_utils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>
#include <meta2v2/meta2_dedup_utils.h>

#include <glib.h>

/**
 * Inserts a bean (chunk or contents_headers) in a hashtable,
 * the key being the hash of the bean
 */
static void _add_to_hashtable_cb(gpointer hashtable, gpointer bean)
{
	GHashTable *_chunks_by_hash = (GHashTable *)hashtable;
	GByteArray *hash = NULL;
	if (DESCR(bean) == &descr_struct_CHUNK) {
		hash = CHUNK_get_hash(bean);
	} else if (DESCR(bean) == &descr_struct_CONTENT) {
		hash = CONTENT_get_hash(bean);
	} else {
		g_assert_not_reached();
	}
	GSList *chunk_list = g_hash_table_lookup(_chunks_by_hash, hash);
	if (chunk_list != NULL) {
		/* Remove it without freeing it */
		g_hash_table_steal(_chunks_by_hash, hash);
	}
	/* No problem if the key was not found: NULL is a valid GSList* */
	g_hash_table_insert(_chunks_by_hash, hash, g_slist_prepend(chunk_list, bean));
}

/**
 * Compare two chunk hashes.
 *
 * @return TRUE if both hashes are equal, FALSE otherwise
 */
gboolean
hash_equals(gconstpointer a, gconstpointer b)
{
	int res = metautils_gba_cmp((GByteArray *)a, (GByteArray *)b);
	return (res == 0);
}

/**
 * Make a guint32 hash as required by GHashTable constructor
 * from a GByteArray pointer to a bean hash (chunk or content).
 *
 * @param key The pointer to the GByteArray, as a gconstpointer
 * @return The first 4 bytes of the hash, as a guint32
 */
guint32
bean_hash_to_guint32(gconstpointer key)
{
	GByteArray *hash = (GByteArray*)key;
	return *((guint32*)(*hash).data);
}

/**
 * Remove from the hash table the chunks whose hash is unique.
 */
static guint
_remove_unique_beans(GHashTable *chunks_by_hash)
{
	/* Test if a list has one and only one element */
	gboolean _has_only_one_element(gpointer k, gpointer v, gpointer d) {
		(void) d;
		GSList *chunk_list = (GSList *) v;
		guint length = g_slist_length(chunk_list);
		if (GRID_DEBUG_ENABLED()) {
			GString *hash_str = metautils_gba_to_hexgstr(NULL, (GByteArray *) k);
			if (length == 1) {
				GRID_TRACE("Removing bean of hash '%s' from hash table", hash_str->str);
			} else {
				GRID_DEBUG("Found % 4d beans with hash '%s'", length, hash_str->str);
			}
			g_string_free(hash_str, TRUE);
		}
		return (length == 1);
	}

	return g_hash_table_foreach_remove(chunks_by_hash,
			_has_only_one_element, NULL);
}

GHashTable*
get_dup_contents_headers_by_hash(sqlite3 *db, GError **err)
{
	GHashTable *contents_by_hash = g_hash_table_new_full(bean_hash_to_guint32,
			hash_equals, NULL, (GDestroyNotify)_bean_cleanl2);
	const gchar *sql = " hash is not NULL ";
	GVariant *params[1] = {NULL};

	GError *err_local = NULL;

	err_local = CONTENT_load(db, sql, params, _add_to_hashtable_cb, contents_by_hash);
	if (err_local != NULL) {
		*err = err_local;
		g_prefix_error(err, "Failed to build content headers hash table: ");
		g_hash_table_destroy(contents_by_hash);
		contents_by_hash = NULL;
		return NULL;
	}

	_remove_unique_beans(contents_by_hash);

	return contents_by_hash;
}

static guint64
substitute_content(sqlite3 *db, struct bean_CONTENT_s *new_ch,
		GSList *old_ch, gboolean dry_run, GSList **impacted_aliases ,GError **err)
{
	const gchar *clause = " content = ? ";
	GVariant *params[2] = {NULL, NULL};
	guint64 saved_space = 0;

	void _substitute_ch_cb(gpointer ch, gpointer alias)
	{
		GError *err2 = NULL;
		struct bean_ALIAS_s *new_alias = NULL;
		if (!dry_run) {
			new_alias = _bean_dup(alias);
			ALIAS_set_content(new_alias, CONTENT_get_id(ch));
			err2 = ALIAS_save(db, new_alias);
		}
		if (err2 != NULL) {
			GString *orig_ch_str = metautils_gba_to_hexgstr(NULL, ALIAS_get_content(alias));
			GString *new_ch_str = metautils_gba_to_hexgstr(NULL, CONTENT_get_id(ch));
			GRID_WARN("Failed to substitute content '%s' by '%s' in alias '%s'",
					orig_ch_str->str, new_ch_str->str, ALIAS_get_alias(alias)->str);
			g_string_free(orig_ch_str, TRUE);
			g_string_free(new_ch_str, TRUE);
			g_clear_error (&err2);
		} else {
			*impacted_aliases = g_slist_prepend(*impacted_aliases,
					g_strdup(ALIAS_get_alias(alias)->str));
			saved_space += CONTENT_get_size(ch);
		}
		if (new_alias) _bean_clean(new_alias);
		_bean_clean(alias);
	}

	for (GSList *cursor = old_ch ; cursor; cursor = cursor->next) {
		params[0] = _gba_to_gvariant(CONTENT_get_id(cursor->data));
		/* Apply _substitute_ch_cb on aliases beans which reference
		 * the current content header */
		*err = ALIAS_load(db, clause, params, _substitute_ch_cb, new_ch);
		if (*err != NULL) {
			g_prefix_error(err, "Failed to deduplicate content headers (%d remaining): ",
					g_slist_length(cursor));
			break;
		}

		g_variant_unref(params[0]);
		params[0] = NULL;
	}

	if (params[0] != NULL) {
		g_variant_unref(params[0]);
	}
	return saved_space;
}

guint64
dedup_aliases(sqlite3 *db, struct hc_url_s *url, gboolean dry_run, GSList **impacted_aliases,
		GError **err)
{
	(void) url;
	GRID_DEBUG("Starting alias deduplication");
	GHashTable *ch_by_h = get_dup_contents_headers_by_hash(db, err);
	GRID_DEBUG("Found %d different content hashes", g_hash_table_size(ch_by_h));
	guint64 saved_space = 0;

	void _dedup_ch_cb(gpointer k, gpointer v, gpointer d)
	{
		(void) k;
		(void) d;
		// build content header lists that share same storage policy
		GHashTable *by_sp = g_hash_table_new(g_str_hash, g_str_equal);
		for (GSList *cursor = v; cursor; cursor = cursor->next) {
			gchar *policy = CONTENT_get_policy(cursor->data)->str;
			GSList *ch_list = g_hash_table_lookup(by_sp, policy);
		    if (ch_list != NULL) {
				g_hash_table_steal(by_sp, policy);
			}
			g_hash_table_insert(by_sp, policy,
					g_slist_prepend(ch_list, cursor->data));
		}

		void _dedup_ch_cb2(gpointer k2, gpointer v2, gpointer d2) {
			(void) k2;
			(void) d2;
			GSList *ch_list2 = (GSList *) v2;
			saved_space += substitute_content(db, ch_list2->data,
					ch_list2->next, dry_run, impacted_aliases, err);
		}
		g_hash_table_foreach(by_sp, _dedup_ch_cb2, NULL);
		g_hash_table_destroy(by_sp);
	}

	g_hash_table_foreach(ch_by_h, _dedup_ch_cb, NULL);
	g_hash_table_destroy(ch_by_h);

	return saved_space;
}

