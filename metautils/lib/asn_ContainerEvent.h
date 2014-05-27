#ifndef __ASN_CONTAINEREVENT_H__
#define __ASN_CONTAINEREVENT_H__

#include "./metatypes.h"
#include "./ContainerEvent.h"

gboolean container_event_ASN2API(const ContainerEvent_t * asn, container_event_t * api);
gboolean container_event_API2ASN(const container_event_t * api, ContainerEvent_t * asn);
void container_event_cleanASN(ContainerEvent_t * asn, gboolean only_content);

#endif /*__ASN_CONTAINER_H__*/
