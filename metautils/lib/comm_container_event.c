#ifndef G_LOG_DOMAIN
# define G_LOG_DOMAIN "metacomm.container_event"
#endif

#include "./metautils_internals.h"
#include "./ContainerEvent.h"
#include "./ContainerEventSequence.h"
#include "./asn_ContainerEvent.h"

static struct abstract_sequence_handler_s seq_descriptor = {
	sizeof(ContainerEvent_t),
	sizeof(container_event_t),
	&asn_DEF_ContainerEventSequence,
	(abstract_converter_f) container_event_ASN2API,
	(abstract_converter_f) container_event_API2ASN,
	(abstract_asn_cleaner_f) container_event_cleanASN,
	(abstract_api_cleaner_f) container_event_clean,
	"container_event"
};

DEFINE_MARSHALLER_GBA(container_event_marshall_gba);
DEFINE_MARSHALLER(container_event_marshall);
DEFINE_UNMARSHALLER(container_event_unmarshall);
DEFINE_BODY_MANAGER(container_event_concat, container_event_unmarshall);

