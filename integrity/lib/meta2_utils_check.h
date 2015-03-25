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

#ifndef OIO_SDS__meta2v2__meta2_utils_check_h
# define OIO_SDS__meta2v2__meta2_utils_check_h 1

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

# include <sqlite3.h>
# include <metautils/lib/metautils.h>
# include <meta2v2/autogen.h>
# include <meta2v2/meta2_utils.h>

struct m2v2_check_error_s
{
	GError *original_error; // The optional error that raised this flaw.
	struct bean_ALIASES_s *alias;
	struct bean_CONTENTS_HEADERS_s *header;

	enum m2v2_check_error_type_e {
		M2CHK_CHUNK_DUPLI_BADPOS, // Bad format for position
		M2CHK_CHUNK_DUPLI_GAP, // One position has no chunk at all
		M2CHK_CHUNK_DUPLI_SIZE, // Size mismatch for the given position
		M2CHK_CHUNK_DUPLI_HASH, // Hash mismatch for the given position
		M2CHK_CHUNK_DUPLI_TOOMUCH, // Too many chunk at the same position
		M2CHK_CHUNK_DUPLI_TOOFEW, // Too few chunk at the same position
		M2CHK_CHUNK_DUPLI_BAD_DISTANCE,

		M2CHK_CHUNK_RAIN_BADPOS, // Bad format for position
		M2CHK_CHUNK_RAIN_TOOMUCH, // does not match the policy
		M2CHK_CHUNK_RAIN_TOOFEW, // Too few but repairable
		M2CHK_CHUNK_RAIN_LOST, // Too many chunks missing, reconstruction not possible
		M2CHK_CHUNK_RAIN_BAD_DISTANCE,
		M2CHK_CHUNK_RAIN_BAD_ALGO,

		M2CHK_CONTENT_SIZE_MISMATCH,
		M2CHK_CONTENT_STGCLASS,
		M2CHK_RAWX_UNKNOWN, // RAWX not found in services
	} type;

	union {
		// Duplication
		struct {
			m2v2_chunk_pair_t pair;
		} dupli_badpos;
		struct {
			gint first_missing;
			gint last_missing;
		} dupli_gap;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_hashes;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_sizes;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
			gint count; // nb exceeding chunks
		} chunk_dupli_toomuch;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
			gint count; // nb missing chunks
			guint dist; // nb missing chunks
		} chunk_dupli_toofew;
		struct {
			GArray *pairs; // m2v2_chunk_pair_t
		} chunk_dupli_dist;

		// RAIN
		struct {
			m2v2_chunk_pair_t pair;
		} rain_badpos;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_toomuch;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
			GArray *pairs_unavailable; // m2v2_chunk_pair_t
			gint64 metachunk_pos;
		} rain_toofew;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_lost;
		struct {
			GArray *pairs_data; // m2v2_chunk_pair_t
			GArray *pairs_parity; // m2v2_chunk_pair_t
		} rain_dist;

		// COMMON
		struct {
			m2v2_chunk_pair_t pair;
		} rawx_unknown;
		struct {
			GArray *bad_pairs; // m2v2_chunk_pair_t
			GArray *all_pairs; // m2v2_chunk_pair_t
		} stgclass;

	} param;
};

#define M2V2_CHECK_GAPS 0x01
#define M2V2_CHECK_DIST 0x02
#define M2V2_CHECK_STGCLS 0x04
#define M2V2_CHECK_SRVINFO 0x08

struct check_args_s
{
	struct grid_lbpool_s *lbpool;
	struct namespace_info_s *ns_info;
	guint32 mask_checks;
};

struct m2v2_check_s
{
	struct namespace_info_s *ns_info;
	struct grid_lbpool_s *lbpool;
	struct hc_url_s *url;

	GPtrArray *aliases; // <struct bean_ALIASES_s*>
	GPtrArray *headers; // <struct bean_CONTENTS_HEADERS_s*>
	GPtrArray *contents; // <struct bean_CONTENTS_s*>
	GPtrArray *chunks; // <struct bean_CHUNKS_s*>
	GPtrArray *props; // <struct bean_PROPERTIES_s*>

	GPtrArray *unavail_chunks; // <struct bean_CHUNKS_s*>

	GPtrArray *flaws; // <struct m2v2_check_error_s*>
	guint8 flags; // Private use
};

guint32 m2db_get_mask_check_put(struct namespace_info_s *ni);

struct m2v2_check_s* m2v2_check_create(struct hc_url_s *url,
		struct check_args_s *args);

void m2v2_check_feed_with_bean_list(struct m2v2_check_s *check, GSList *beans);

GError* m2v2_check_consistency(struct m2v2_check_s *check);

void m2v2_check_destroy(struct m2v2_check_s *check);

GError* m2db_check_alias_beans_list(struct hc_url_s *url, GSList *beans,
		struct check_args_s *args);

#endif /*OIO_SDS__meta2v2__meta2_utils_check_h*/
