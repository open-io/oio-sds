#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.namespace_info"
#endif

#include <errno.h>

#include "./metautils_internals.h"
#include "./asn_NamespaceInfo.h"
#include "./NamespaceInfo.h"
#include "./NamespaceInfoSequence.h"

static const struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(NamespaceInfo_t),
	sizeof(namespace_info_t),
	&asn_DEF_NamespaceInfoSequence,
	(abstract_converter_f) namespace_info_ASN2API,
	(abstract_converter_f) namespace_info_API2ASN,
	(abstract_asn_cleaner_f) namespace_info_cleanASN,
	(abstract_api_cleaner_f) namespace_info_free,
	"namespace_info"
};

static int
write_in_gba(const void *b, gsize bSize, void *key)
{
	GByteArray *a = g_byte_array_append((GByteArray *) key, b, bSize);

	return a ? 0 : -1;
}


GByteArray *
namespace_info_marshall(namespace_info_t * namespace_info, const char *version, GError ** err)
{
	asn_enc_rval_t encRet;
	GByteArray *result = NULL;
	NamespaceInfo_t asn1_namespace_info;

	/*sanity checks */
	if (!namespace_info) {
		GSETERROR(err, "Invalid parameter");
		goto error_params;
	}

	memset(&asn1_namespace_info, 0x00, sizeof(NamespaceInfo_t));

	/* convert version to an int to easy compare */
	// FIXME ugly piece of code! 
	gint64 versint64 = 0;
	if(NULL != version) {
		char *r = strchr(version,'.');
		if(r) {
			char tmp[256];
			memset(tmp, '\0', 256);
			g_snprintf(tmp, 256, "%.*s%s", (int)(r - version), version, r + 1);
			versint64 = g_ascii_strtoll(tmp, NULL, 10);
			TRACE("marshalling int64 : %"G_GINT64_FORMAT, versint64);
		}
	}

	/*fills an ASN.1 structure */
	if (!namespace_info_API2ASN(namespace_info, versint64, &asn1_namespace_info)) {
		GSETERROR(err, "API to ASN.1 mapping error");
		goto error_mapping;
	}

	/*serialize the ASN.1 structure */
	if (!(result = g_byte_array_sized_new(4096))) {
		GSETERROR(err, "memory allocation failure");
		goto error_alloc_gba;
	}
	encRet = der_encode(&asn_DEF_NamespaceInfo, &asn1_namespace_info, write_in_gba, result);
	if (encRet.encoded == -1) {
		GSETERROR(err, "ASN.1 encoding error");
		goto error_encode;
	}

	/*free the ASN.1 structure */
	namespace_info_cleanASN(&asn1_namespace_info, TRUE);

	return result;

      error_encode:
	g_byte_array_free(result, TRUE);
      error_alloc_gba:
      error_mapping:
	namespace_info_cleanASN(&asn1_namespace_info, TRUE);
      error_params:

	return NULL;
}

namespace_info_t *
namespace_info_unmarshall(const guint8 * buf, gsize buf_len, GError ** err)
{
	asn_dec_rval_t decRet;
	asn_codec_ctx_t codecCtx;
	namespace_info_t *result = NULL;
	NamespaceInfo_t *asn1_namespace_info = NULL;

	/*sanity checks */
	if (!buf) {
		GSETCODE(err, 500+EINVAL, "Invalid paremeter");
		return NULL;
	}

	/*deserialize the encoded form */
	codecCtx.max_stack_size = 65536;
	decRet = ber_decode(&codecCtx, &asn_DEF_NamespaceInfo, (void *) &asn1_namespace_info, buf, buf_len);
	if (decRet.code != RC_OK) {
		GSETCODE(err, 500, "Cannot deserialize: %s", (decRet.code == RC_WMORE)
				? "uncomplete data" : "invalid data");
		namespace_info_cleanASN(asn1_namespace_info, FALSE);
		return NULL;
	}

	/*prepare the working structures */
	if (!(result = g_try_malloc0(sizeof(namespace_info_t)))) {
		GSETCODE(err, 500+ENOMEM, "Memory allocation failure");
		namespace_info_cleanASN(asn1_namespace_info, FALSE);
		return NULL;
	}

	/*map the ASN.1 in a common structure */
	int rc = namespace_info_ASN2API(asn1_namespace_info, result);
	namespace_info_cleanASN(asn1_namespace_info, FALSE);
	asn1_namespace_info = NULL;
	if (rc) {
		errno = 0;
		return result;
	}

	namespace_info_free(result);
	result = NULL;

	GSETCODE(err, 500, "ASN.1 to API mapping failure");
	return NULL;
}

gint
namespace_info_unmarshall_one(struct namespace_info_s **ni, const void *s, gsize *sSize, GError **err)
{
	struct namespace_info_s *result;
	
	result = namespace_info_unmarshall(s, *sSize, err);
	if (!result) {
		GSETERROR(err, "Unmarshalling error");
		return 0;
	}
	
	if (ni)
		*ni = result;
	else
		namespace_info_free(result);

	errno = 0;
	return 1;
}

DEFINE_MARSHALLER(namespace_info_list_marshall);
DEFINE_MARSHALLER_GBA(namespace_info_list_marshall_gba);
DEFINE_UNMARSHALLER(namespace_info_list_unmarshall);
DEFINE_BODY_MANAGER(namespace_info_concat, namespace_info_list_unmarshall);

