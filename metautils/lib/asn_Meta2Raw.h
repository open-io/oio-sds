/*
OpenIO SDS metautils
Copyright (C) 2014 Worldine, original work as part of Redcurrant
Copyright (C) 2015 OpenIO, modified as part of OpenIO Software Defined Storage

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

#ifndef OIO_SDS__metautils__lib__asn_Meta2Raw_h
# define OIO_SDS__metautils__lib__asn_Meta2Raw_h 1

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

#endif /*OIO_SDS__metautils__lib__asn_Meta2Raw_h*/