#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.meta0_info"
#endif

#include "./metautils_internals.h"
#include "./asn_Meta0Info.h"
#include "./Meta0Info.h"
#include "./Meta0InfoSequence.h"

static const struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(Meta0Info_t),
	sizeof(meta0_info_t),
	&asn_DEF_Meta0InfoSequence,
	(abstract_converter_f) meta0_info_ASN2API,
	(abstract_converter_f) meta0_info_API2ASN,
	(abstract_asn_cleaner_f) meta0_info_cleanASN,
	(abstract_api_cleaner_f) meta0_info_clean,
	"meta0_info"
};

DEFINE_MARSHALLER(meta0_info_marshall)
DEFINE_UNMARSHALLER(meta0_info_unmarshall)
DEFINE_MARSHALLER_GBA(meta0_info_marshall_gba)

