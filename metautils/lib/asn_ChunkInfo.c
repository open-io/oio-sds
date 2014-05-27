#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.chunk_info.asn"
#endif

#include <errno.h>
#include <glib.h>

#include "./metatypes.h"
#include "./metautils.h"
#include "./metacomm.h"

#include "./asn_AddrInfo.h"
#include "./asn_ChunkInfo.h"

gboolean
chunk_info_ASN2API(const ChunkInfo_t * asn, chunk_info_t * api)
{
	if (!api || !asn)
		return FALSE;

	/*sanity checks */
	if (asn->id.vol.size <= 0 || !(asn->id.vol.buf))
		return FALSE;

	/*id */

	/* id.id */
	memcpy(&(api->id.id), asn->id.id.buf, MIN(sizeof(api->id.id), (size_t) asn->id.id.size));

	/* id.addr */
	addr_info_ASN2API(&(asn->id.addr), &(api->id.addr));

	/* id.vol */
	memcpy(api->id.vol, asn->id.vol.buf, MIN(LIMIT_LENGTH_VOLUMENAME, asn->id.vol.size));

	memset(api->hash, 0x00, sizeof(chunk_hash_t));
	memcpy(api->hash, asn->md5.buf, MIN(sizeof(chunk_hash_t), (size_t) asn->md5.size));

	/*position */
	asn_INTEGER_to_uint32(&(asn->position), &(api->position));

	/*offset */
	asn_INTEGER_to_int64(&(asn->size), &(api->size));

	/*nb */
	asn_INTEGER_to_uint32(&(asn->nb), &(api->nb));

	return TRUE;
}


gboolean
chunk_info_API2ASN(const chunk_info_t * api, ChunkInfo_t * asn)
{
	char vol_name[LIMIT_LENGTH_VOLUMENAME];

	if (!api || !asn)
		return FALSE;

	/*id */

	/* id.id */
	OCTET_STRING_fromBuf(&(asn->id.id), (const char*)api->id.id, sizeof(api->id.id));

	/* id.addr */
	addr_info_API2ASN(&(api->id.addr), &(asn->id.addr));

	/* id.vol */
	memset(vol_name, '\0', sizeof(vol_name));
	memcpy(vol_name, api->id.vol, sizeof(vol_name) - 1);

	OCTET_STRING_fromBuf(&(asn->id.vol), vol_name, strlen(vol_name));

	/*position */
	asn_uint32_to_INTEGER(&(asn->position), api->position);

	/*size */
	asn_int64_to_INTEGER(&(asn->size), api->size);

	/*nb */
	asn_uint32_to_INTEGER(&(asn->nb), api->nb);

	OCTET_STRING_fromBuf(&(asn->md5), (const char*)api->hash, sizeof(chunk_hash_t));

	return TRUE;
}


void
chunk_info_cleanASN(ChunkInfo_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ChunkInfo, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_ChunkInfo, asn);

	errno = 0;
}


gboolean
chunk_id_API2ASN(const chunk_id_t * api, ChunkId_t * asn)
{
	char vol_name[LIMIT_LENGTH_VOLUMENAME];

	if (!asn || !api)
		return FALSE;

	/* id.id */
	OCTET_STRING_fromBuf(&(asn->id), (const char*)api->id, sizeof(api->id));

	/* id.addr */
	addr_info_API2ASN(&(api->addr), &(asn->addr));

	/* id.vol */
	memset(vol_name, '\0', sizeof(vol_name));
	memcpy(vol_name, api->vol, sizeof(vol_name) - 1);

	OCTET_STRING_fromBuf(&(asn->vol), vol_name, strlen(vol_name));

	return TRUE;
}

gboolean
chunk_id_ASN2API(const ChunkId_t * asn, chunk_id_t * api)
{
	if (!asn || !api)
		return FALSE;

	/* id */
	memcpy(&(api->id), asn->id.buf, MIN(sizeof(api->id), (size_t) asn->id.size));

	/* addr */
	addr_info_ASN2API(&(asn->addr), &(api->addr));

	/* vol */
	memcpy(api->vol, asn->vol.buf, MIN(LIMIT_LENGTH_VOLUMENAME, asn->vol.size));

	return TRUE;
}


void
chunk_id_cleanASN(ChunkId_t * asn, gboolean only_content)
{
	if (!asn) {
		errno = EINVAL;
		return;
	}

	if (only_content)
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ChunkId, asn);
	else
		ASN_STRUCT_FREE(asn_DEF_ChunkId, asn);

	errno = 0;
}
