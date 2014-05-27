#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.addr_info"
#endif

#include "metautils_internals.h"
#include "AddrInfo.h"
#include "AddrInfoSequence.h"
#include "asn_AddrInfo.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(AddrInfo_t),
	sizeof(addr_info_t),
	&asn_DEF_AddrInfoSequence,
	(abstract_converter_f) addr_info_ASN2API,
	(abstract_converter_f) addr_info_API2ASN,
	(abstract_asn_cleaner_f) addr_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"addr_info"
};

DEFINE_MARSHALLER_GBA(addr_info_marshall_gba);
DEFINE_MARSHALLER(addr_info_marshall);
DEFINE_UNMARSHALLER(addr_info_unmarshall);
DEFINE_BODY_MANAGER(addr_info_concat, addr_info_unmarshall);

