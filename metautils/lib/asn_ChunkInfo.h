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

#ifndef OIO_SDS__metautils__lib__asn_ChunkInfo_h
# define OIO_SDS__metautils__lib__asn_ChunkInfo_h 1

#include "./metatypes.h"
#include "./ChunkInfo.h"

gboolean chunk_info_ASN2API(const ChunkInfo_t * asn, chunk_info_t * api);
gboolean chunk_info_API2ASN(const chunk_info_t * api, ChunkInfo_t * asn);
void chunk_info_cleanASN(ChunkInfo_t * asn, gboolean only_content);

gboolean chunk_id_API2ASN(const chunk_id_t * api, ChunkId_t * asn);
gboolean chunk_id_ASN2API(const ChunkId_t * asn, chunk_id_t * api);
void chunk_id_cleanASN(ChunkId_t * asn, gboolean only_content);

#endif /*OIO_SDS__metautils__lib__asn_ChunkInfo_h*/