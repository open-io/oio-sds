/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef HC_M2V2_meta2_dedup_utils__h
# define HC_M2V2_meta2_dedup_utils__h 1

#include <glib.h>

#include <generic.h>
#include <autogen.h>
#include <hc_url.h>

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
 * Get the cumulated size of contents in the database.
 */
guint64 get_container_size(sqlite3 *db);

/**
 * Substitute `new_chunk` in place of chunks of `old_chunks` in all matching contents.
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
		GSList *old_ch, GSList **impacted_aliases, GError **err);

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
guint64 dedup_aliases(sqlite3 *db, struct hc_url_s *url,
		GSList **impacted_aliases, GError **err);

#endif /* HC_M2V2_meta2_dedup_utils__h */
