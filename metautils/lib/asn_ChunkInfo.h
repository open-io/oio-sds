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

#ifndef __ASN_CHUNKINFO_H__
#define __ASN_CHUNKINFO_H__

#include "./metatypes.h"
#include "./ChunkInfo.h"

gboolean chunk_info_ASN2API(const ChunkInfo_t * asn, chunk_info_t * api);
gboolean chunk_info_API2ASN(const chunk_info_t * api, ChunkInfo_t * asn);
void chunk_info_cleanASN(ChunkInfo_t * asn, gboolean only_content);

gboolean chunk_id_API2ASN(const chunk_id_t * api, ChunkId_t * asn);
gboolean chunk_id_ASN2API(const ChunkId_t * asn, chunk_id_t * api);
void chunk_id_cleanASN(ChunkId_t * asn, gboolean only_content);

#endif /*__ASN_CHUNKINFO_H__*/
