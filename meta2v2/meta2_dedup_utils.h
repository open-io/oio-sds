#ifndef HC_M2V2_meta2_dedup_utils__h
# define HC_M2V2_meta2_dedup_utils__h 1

#include <metautils/lib/metautils.h>
#include <meta2v2/generic.h>
#include <meta2v2/autogen.h>

#include <glib.h>

/**
 * Compare two chunk hashes.
 *
 * @return TRUE if both hashes are equal, FALSE otherwise
 */
gboolean hash_equals(gconstpointer a, gconstpointer b);

/**
 * Make a guint32 hash as required by GHashTable constructor
 * from a GByteArray pointer to a bean hash (chunk or content).
 *
 * @param key The pointer to the GByteArray, as a gconstpointer
 * @return The first 4 bytes of the hash, as a guint32
 */
guint32 bean_hash_to_guint32(gconstpointer key);

/**
 * Substitute `new_chunk` in place of chunks of `old_chunks` in all matching
 * contents.
 *
 * @param db A pointer to the meta2 database
 * @param new_chunk The chunk to substitute
 * @param old_chunks The list of chunks that can be replaced by `new_chunk`
 * @param err A pointer to a GError
 * @return The number of deduplicated chunks
 */
guint substitute_chunk(sqlite3 *db, struct bean_CHUNKS_s *new_chunk,
		GSList *old_chunks, GError **err);

GHashTable* get_dup_contents_headers_by_hash(sqlite3 *db, GError **err);

guint64 substitute_content_header(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *new_ch,
		GSList *old_ch, gboolean dry_run, GSList **impacted_aliases, GError **err);

void dedup_chunks_of_alias(sqlite3 *db, GString *alias, guint nb_copy, GError **err);

void print_bean_hashtable(GHashTable *hashtable);

/**
 * Find content headers sharing the same hash and content policy,
 * and substitute them in aliases where they are referenced.
 *
 * @param db A pointer to the meta2 database
 * @param url The URL to the container to process deduplication on
 * @param impacted_aliases A GSList of aliases (gchar*) which have
 *      been impacted by the deduplication
 * @param err A pointer to a GError
 * @return The storage space saved thanks to deduplication
 */
guint64 dedup_aliases(sqlite3 *db, struct hc_url_s *url, gboolean dry_run,
		GSList **impacted_aliases, GError **err);

#endif /* HC_M2V2_meta2_dedup_utils__h */
