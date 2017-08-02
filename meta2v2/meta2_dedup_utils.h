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

#ifndef OIO_SDS__meta2v2__meta2_dedup_utils_h
# define OIO_SDS__meta2v2__meta2_dedup_utils_h 1

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

GHashTable* get_dup_contents_headers_by_hash(sqlite3 *db, GError **err);

guint64 substitute_content_header(sqlite3 *db, struct bean_CONTENTS_HEADERS_s *new_ch,
		GSList *old_ch, GSList **impacted_aliases, GError **err);

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
guint64 dedup_aliases(sqlite3 *db, struct oio_url_s *url,
		GSList **impacted_aliases, GError **err);

#endif /*OIO_SDS__meta2v2__meta2_dedup_utils_h*/
