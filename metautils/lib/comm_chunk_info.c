#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.chunk_info"
#endif

#include "./metautils_internals.h"

#include "./asn_AddrInfo.h"
#include "./asn_ChunkInfo.h"

#include "./AddrInfo.h"
#include "./AddrInfoSequence.h"
#include "./ChunkInfo.h"
#include "./ChunkInfoSequence.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ChunkInfo_t),
	sizeof(chunk_info_t),
	&asn_DEF_ChunkInfoSequence,
	(abstract_converter_f) chunk_info_ASN2API,
	(abstract_converter_f) chunk_info_API2ASN,
	(abstract_asn_cleaner_f) chunk_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"chunk_info"
};

DEFINE_MARSHALLER(chunk_info_marshall);
DEFINE_MARSHALLER_GBA(chunk_info_marshall_gba);
DEFINE_UNMARSHALLER(chunk_info_unmarshall);
DEFINE_BODY_MANAGER(chunk_info_concat, chunk_info_unmarshall);

static int
func_write(const void *b, gsize bSize, void *key)
{
	if (!g_byte_array_append((GByteArray *) key, (guint8 *) b, bSize))
		return -1;
	return 0;
}


GByteArray *
chunk_id_marshall(const chunk_id_t * chunkId, GError ** err)
{
	asn_enc_rval_t encRet;
	GByteArray *gba;
	ChunkId_t asn_cid;

	memset(&encRet, 0x00, sizeof(encRet));
	memset(&asn_cid, 0x00, sizeof(asn_cid));
	gba = g_byte_array_new();

	if (!gba) {
		GSETERROR(err, "Memory allocation failure");
		return NULL;
	}

	if (!chunk_id_API2ASN(chunkId, &asn_cid)) {
		GSETERROR(err, "Cannot map the API chunk_id_t to an ASN ChunkId_t");
		goto errorLabel;
	}

	encRet = der_encode(&asn_DEF_ChunkId, &asn_cid, func_write, gba);
	chunk_id_cleanASN(&asn_cid, TRUE);
	if (encRet.encoded == -1) {
		GSETERROR(err, "Cannot decode the AddrInfoSequence");
		goto errorLabel;
	}

	return gba;
      errorLabel:
	g_byte_array_free(gba, TRUE);
	return NULL;
}


gint
chunk_id_unmarshall(chunk_id_t * chunkId, void *src, gsize srcSize, GError ** err)
{
	gint rc = 0;
	void *result = NULL;
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	ChunkId_t *asn_cid;

	if (!chunkId || !src || !srcSize) {
		GSETERROR(err, "Invalid parameter (%p %p %d)", chunkId, src, srcSize);
		return -1;
	}

	memset(&decRet, 0x00, sizeof(decRet));
	memset(&codecCtx, 0x00, sizeof(codecCtx));
	memset(&asn_cid, 0x00, sizeof(asn_cid));

	codecCtx.max_stack_size = 1 << 16;
	decRet = ber_decode(&codecCtx, &asn_DEF_ChunkId, &result, src, srcSize);
	asn_cid = (ChunkId_t *) result;

	switch (decRet.code) {
	case RC_OK:
		break;
	case RC_FAIL:
		GSETERROR(err, "Cannot parse the serialized chunk_info_t sequence (%i consumed)", decRet.consumed);
		return -1;
	case RC_WMORE:
		GSETERROR(err, "Cannot parse the serialized chunk_info_t sequence (uncomplete)");
		return 0;
	}

	rc = chunk_id_ASN2API(asn_cid, chunkId) ? 1 : -1;
	ASN_STRUCT_FREE(asn_DEF_ChunkId, asn_cid);

	if (rc < 0) {
		GSETERROR(err, "Cannot map the ASN ChunkId_t to an API chunk_id_t");
		return -1;
	}

	return 1;
}

