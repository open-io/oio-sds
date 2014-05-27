#ifndef G_LOG_DOMAIN
#define G_LOG_DOMAIN "metacomm.container_info"
#endif

#include "./metautils_internals.h"

#include "./asn_ContainerInfo.h"

#include "./ContainerInfo.h"
#include "./ContainerInfoSequence.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ContainerInfo_t),
	sizeof(container_info_t),
	&asn_DEF_ContainerInfoSequence,
	(abstract_converter_f) container_info_ASN2API,
	(abstract_converter_f) container_info_API2ASN,
	(abstract_asn_cleaner_f) container_info_cleanASN,
	(abstract_api_cleaner_f) g_free,
	"container_info"
};

DEFINE_MARSHALLER(container_info_marshall);
DEFINE_MARSHALLER_GBA(container_info_marshall_gba);
DEFINE_UNMARSHALLER(container_info_unmarshall);
DEFINE_BODY_MANAGER(container_info_concat, container_info_unmarshall);
