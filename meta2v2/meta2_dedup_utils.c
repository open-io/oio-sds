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
	if (DESCR(bean) == &descr_struct_CHUNKS) {
		hash = CHUNKS_get_hash(bean);
	} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
		hash = CONTENTS_HEADERS_get_hash(bean);
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
				GRID_DEBUG("Found % 4d beans with hash '%s'",
						length, hash_str->str);
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

	err_local = CONTENTS_HEADERS_load(db, sql, params, _add_to_hashtable_cb,
		contents_by_hash);
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
			gchar *policy = CONTENTS_HEADERS_get_policy(cursor->data)->str;
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
			saved_space += substitute_content_header(db, ch_list2->data,
					ch_list2->next, dry_run, impacted_aliases, err);
		}
		g_hash_table_foreach(by_sp, _dedup_ch_cb2, NULL);
		g_hash_table_destroy(by_sp);
	}

	g_hash_table_foreach(ch_by_h, _dedup_ch_cb, NULL);
	g_hash_table_destroy(ch_by_h);

	return saved_space;
}

guint64
substitute_content_header(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *new_ch,
		GSList *old_ch, gboolean dry_run, GSList **impacted_aliases ,GError **err)
{
	const gchar *clause = " content_id = ? ";
	GVariant *params[2] = {NULL, NULL};
	guint64 saved_space = 0;

	void _substitute_ch_cb(gpointer ch, gpointer alias)
	{
		GError *err2 = NULL;
		struct bean_ALIASES_s *new_alias = NULL;
		if (!dry_run) {
			new_alias = _bean_dup(alias);
			ALIASES_set_content_id(new_alias, CONTENTS_HEADERS_get_id(ch));
			err2 = ALIASES_save(db, new_alias);
		}
		if (err2 != NULL) {
			GString *orig_ch_str = metautils_gba_to_hexgstr(NULL,
					ALIASES_get_content_id(alias));
			GString *new_ch_str = metautils_gba_to_hexgstr(NULL,
					CONTENTS_HEADERS_get_id(ch));
			GRID_WARN("Failed to substitute content '%s' by '%s' in alias '%s'",
					orig_ch_str->str, new_ch_str->str, ALIASES_get_alias(alias)->str);
			g_string_free(orig_ch_str, TRUE);
			g_string_free(new_ch_str, TRUE);
		} else {
			*impacted_aliases = g_slist_prepend(*impacted_aliases,
					g_strdup(ALIASES_get_alias(alias)->str));
			saved_space += CONTENTS_HEADERS_get_size(ch);
		}
		if (new_alias) _bean_clean(new_alias);
		_bean_clean(alias);
	}

	for (GSList *cursor = old_ch ; cursor; cursor = cursor->next) {
		params[0] = _gba_to_gvariant(CONTENTS_HEADERS_get_id(cursor->data));
		/* Apply _substitute_ch_cb on aliases beans which reference
		 * the current content header */
		*err = ALIASES_load(db, clause, params, _substitute_ch_cb, new_ch);
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

guint
substitute_chunk(sqlite3 *db, struct bean_CHUNKS_s *new_chunk,
		GSList *old_chunks, GError **err)
{
	/* Content of the WHERE clause */
	const gchar *sql = " chunk_id is ? ";
	/* Values to substitute to '?' occurences */
	GVariant *params[2] = {NULL, NULL};

	/* Number of chunks that have been deduplicated */
	guint chunk_counter = 0;

	/* Substitute the chunk id in a content bean */
	void _substitute_chunk_cb(gpointer chunk_pointer, gpointer content_pointer)
	{
		struct bean_CHUNKS_s *chunk = (struct bean_CHUNKS_s *) chunk_pointer;
		struct bean_CONTENTS_s *content = (struct bean_CONTENTS_s *) content_pointer;
		GError *err_local = NULL;
		if (GRID_DEBUG_ENABLED()) {
			GString *content_str = metautils_gba_to_hexgstr(NULL,
					CONTENTS_get_content_id(content));
			GRID_DEBUG("Replacing chunk %s by %s in content %s",
					CONTENTS_get_chunk_id(content)->str,
					CHUNKS_get_id(chunk)->str, content_str->str);
			g_string_free(content_str, TRUE);
		}

		/* Copy the bean before doing modifications */
		struct bean_CONTENTS_s *new_content = _bean_dup(content);
		CONTENTS_set_chunk_id(new_content, CHUNKS_get_id(chunk));
		err_local = CONTENTS_save(db, new_content);
		if (err_local != NULL) {
			GString *content_str = metautils_gba_to_hexgstr(NULL,
					CONTENTS_get_content_id(new_content));
			GRID_WARN("Failed to save content %s: %s",
					content_str->str, err_local->message);
			g_string_free(content_str, TRUE);
			goto clean_beans;
		}

		/* Now delete the old content bean */
		err_local = _db_delete_bean(db, content);
		if (err_local != NULL) {
			GString *content_str = metautils_gba_to_hexgstr(NULL,
			                    CONTENTS_get_content_id(content));
			GRID_WARN("Failed to delete old content %s: %s",
					content_str->str, err_local->message);
			g_string_free(content_str, TRUE);
		}

clean_beans:
		_bean_clean(content);
		_bean_clean(new_content);
	}

	for (GSList *cursor = old_chunks ; cursor; cursor = cursor->next) {
		struct bean_CHUNKS_s *old_chunk = (struct bean_CHUNKS_s *) cursor->data;
		params[0] = g_variant_new_string(CHUNKS_get_id(old_chunk)->str);
		/* Apply _substitute_chunk_cb on content beans which reference
		 * the current chunk */
		*err = CONTENTS_load(db, sql, params, _substitute_chunk_cb, new_chunk);
		if (*err != NULL) {
			g_prefix_error(err, "Failed to deduplicate chunks (%d remaining): ",
					g_slist_length(cursor));
			break;
		}

		g_variant_unref(params[0]);
		params[0] = NULL;
		chunk_counter++;
	}

	if (params[0] != NULL) {
		g_variant_unref(params[0]);
	}

	return chunk_counter;
}

void
dedup_chunks_of_alias(sqlite3 *db, GString *alias, guint copy_count, GError **err)
{
	// FIXME: this function deduplicates more than it should

	/* Extended content_v2 with copy count */
	gchar *create_xcv2 = ("CREATE VIEW xcv2 AS "
		"SELECT content_id,chunk_id,position,"
		"  (SELECT COUNT(*) FROM content_v2 AS c2 "
		"   WHERE c2.ROWID < c1.ROWID"
		"   AND c1.content_id=c2.content_id"
		"   AND c1.position=c2.position) AS copy "
		"FROM content_v2 AS c1");
	gchar *del_xcv2 = "DROP VIEW xcv2";

	/* Associate chunk id to alias, version, position and copy */
	gchar *create_aivpch = ("CREATE VIEW aivpch AS "
		"SELECT alias,id,version,position,copy,chunk_v2.hash "
		"FROM chunk_v2 "
		"INNER JOIN xcv2 ON chunk_v2.id=xcv2.chunk_id "
		"INNER JOIN alias_v2 ON xcv2.content_id=alias_v2.content_id;");
	gchar *del_aivpch = "DROP VIEW aivpch";

	GRID_TRACE("Creating views required for chunk deduplication");
	// TODO: create/delete the views in the calling function
	sqlx_exec(db, create_xcv2);
	sqlx_exec(db, create_aivpch);

	/* Get all chunks of a specific alias (but only the first copy) */
	gchar *clause = (" id IN (SELECT id FROM aivpch "
			"WHERE alias = ? and copy = 0)");
	GVariant *params[2] = {NULL, NULL};
	params[0] = g_variant_new_string(alias->str);
	GPtrArray *chunk_array = g_ptr_array_new_with_free_func(_bean_clean);
	*err = CHUNKS_load_buffered(db, clause, params, chunk_array);
	if (*err != NULL) {
		g_prefix_error(err, "Failed to get chunk list of alias '%s': ",
				alias->str);
		goto end_label;
	}

	if (GRID_TRACE_ENABLED()) {
		GRID_TRACE("Found %d chunks for alias '%s'",
				chunk_array->len, alias->str);
	}

	GHashTable *already_dedup = g_hash_table_new_full(g_str_hash, g_str_equal,
			g_free, NULL);

	/* Run the deduplication alogorithm on each chunk */
	for (guint i = 0; i < chunk_array->len; i++) {

		GRID_TRACE("- Finding duplicate chunks of %s (%s)",
				CHUNKS_get_id(chunk_array->pdata[i])->str, alias->str);

		if (g_hash_table_lookup(already_dedup,
				CHUNKS_get_id(chunk_array->pdata[i])->str) != NULL) {
			continue;
		}

		GSList *chunk_groups = NULL;

		GByteArray *hash = CHUNKS_get_hash(chunk_array->pdata[i]);
		gchar *clause2 = (" id IN (SELECT id FROM aivpch "
				"WHERE hash = ? and alias = ? and copy = ? )");
		GVariant *params2[4] = {NULL, NULL, NULL, NULL};
		params2[0] = _gba_to_gvariant(hash);
		params2[1] = g_variant_new_string(alias->str);

		/* Iterate over deliberate copies of the chunk.*/
		for (guint copy = 0; copy < copy_count; copy++) {
			if (GRID_TRACE_ENABLED()) {
				GRID_TRACE("-- copy %d", copy);
			}
			params2[2] = g_variant_new_uint32(copy);

			GSList *same_hash = NULL;
			void _build_list_cb(gpointer data, gpointer bean) {
				(void) data;
				GString *id_str2 = CHUNKS_get_id(bean);
				if (GRID_TRACE_ENABLED()) {
					GRID_TRACE("--- %s", id_str2->str);
				}
				if (g_hash_table_lookup(already_dedup, id_str2->str) == NULL) {
					same_hash = g_slist_prepend(same_hash, bean);
					g_hash_table_insert(already_dedup, g_strdup(id_str2->str),
							(gpointer)1);
				}
			}
			*err = CHUNKS_load(db, clause2, params2, _build_list_cb, NULL);
			g_variant_unref(params2[2]);
			if (*err != NULL) {
				goto end_label;
			}

			/* Here we should have a list of all chunks of a specific copy
			 * sharing the same hash. The list may be empty (if we got
			 * over the actual number of copies) or have only one element
			 * (the chunk is not duplicated). */

			if (g_slist_length(same_hash) < 2) {
				_bean_cleanl2(same_hash);
				continue;
			}
			same_hash = g_slist_reverse(same_hash);
			chunk_groups = g_slist_prepend(chunk_groups, same_hash);
		}
		for (GSList *cursor = chunk_groups; cursor; cursor = cursor->next) {
			GSList *same_hash = cursor->data;
			substitute_chunk(db, same_hash->data, same_hash->next, err);
			_bean_cleanl2(same_hash);
			if (*err != NULL) {
				g_prefix_error(err, "Failed to substitute some chunks: ");
				goto end_label;
			}
		}
		g_slist_free(chunk_groups);
		g_variant_unref(params2[0]);
		g_variant_unref(params2[1]);
		params2[0] = NULL;
		params2[1] = NULL;
	}

end_label:
	// FIXME: free hash table
	GRID_TRACE("Cleaning views");
	sqlx_exec(db, del_xcv2);
	sqlx_exec(db, del_aivpch);

	g_variant_unref(params[0]);

	g_ptr_array_free(chunk_array, TRUE);
}


void
print_bean_hashtable(GHashTable *hashtable)
{
	void print_entry(gpointer key, gpointer value, gpointer user_data) {
		(void) user_data;
		GByteArray *hash = (GByteArray *)key;
		GSList *chunk_list = (GSList *)value;
		GString *hash_str = metautils_gba_to_hexgstr(NULL, hash);
		g_print("%d beans share same hash %s:\n", g_slist_length(chunk_list),
				hash_str->str);
		for (GSList *current = chunk_list; current; current = current->next) {
			gpointer bean = current->data;
			if (bean == NULL) {
				g_print("NULL, ");
			} else if (DESCR(bean) == &descr_struct_CHUNKS) {
				GString *bid = CHUNKS_get_id(bean);
				g_print("\t%s\n", bid->str);
			} else if (DESCR(bean) == &descr_struct_CONTENTS_HEADERS) {
				GString *bid = metautils_gba_to_hexgstr(NULL, CONTENTS_HEADERS_get_id(bean));
				g_print("\t%s\n", bid->str);
				g_string_free(bid, TRUE);
			}
		}
		g_print("\n");
		g_string_free(hash_str, TRUE);
	}
	g_hash_table_foreach(hashtable, print_entry, NULL);
}

