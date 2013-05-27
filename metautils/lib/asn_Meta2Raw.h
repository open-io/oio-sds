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

#ifndef ASN_META2RAW__H
# define ASN_META2RAW__H 1
# include "./metatypes.h"
# include "./metautils.h"
# include "./metacomm.h"
# include "./Meta2Property.h"
# include "./Meta2PropertySequence.h"
# include "./Meta2RawContentHeader.h"
# include "./Meta2RawContentHeaderSequence.h"
# include "./Meta2RawContent.h"
# include "./Meta2RawContentSequence.h"
# include "./Meta2RawContentV2.h"
# include "./Meta2RawContentV2Sequence.h"
# include "./Meta2RawChunk.h"
# include "./Meta2RawChunkSequence.h"

void meta2_raw_content_cleanASN(Meta2RawContent_t * asn1_content, gboolean only_content);
gboolean meta2_raw_content_ASN2API(const Meta2RawContent_t * src, struct meta2_raw_content_s *dst);
gboolean meta2_raw_content_API2ASN(const struct meta2_raw_content_s * src, Meta2RawContent_t * dst);


void meta2_raw_chunk_cleanASN(Meta2RawChunk_t *asn, gboolean only_content);
gboolean meta2_raw_chunk_ASN2API(const Meta2RawChunk_t * src, struct meta2_raw_chunk_s * dst);
gboolean meta2_raw_chunk_API2ASN(const struct meta2_raw_chunk_s * src, Meta2RawChunk_t * dst);


void meta2_raw_content_v2_cleanASN(Meta2RawContentV2_t *asn, gboolean only_content);
gboolean meta2_raw_content_v2_ASN2API(const Meta2RawContentV2_t *asn, meta2_raw_content_v2_t *api);
gboolean meta2_raw_content_v2_API2ASN(const meta2_raw_content_v2_t *api, Meta2RawContentV2_t *asn);


void meta2_raw_content_header_cleanASN(Meta2RawContentHeader_t *asn, gboolean only_content);
gboolean meta2_raw_content_header_ASN2API(const Meta2RawContentHeader_t *asn, meta2_raw_content_header_t *api);
gboolean meta2_raw_content_header_API2ASN(const meta2_raw_content_header_t *api, Meta2RawContentHeader_t *asn);


void meta2_property_cleanASN(Meta2Property_t *asn, gboolean only_content);
gboolean meta2_property_ASN2API(const Meta2Property_t *asn, meta2_property_t *api);
gboolean meta2_property_API2ASN(const meta2_property_t *api, Meta2Property_t *asn);

#endif
