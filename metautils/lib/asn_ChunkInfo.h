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
