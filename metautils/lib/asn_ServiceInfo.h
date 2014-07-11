#ifndef __ASN_SRVINFO_H__
#define __ASN_SRVINFO_H__

#include "./metatypes.h"
#include "./ServiceInfo.h"
#include "./ServiceInfoSequence.h"

gboolean service_info_ASN2API(ServiceInfo_t * asn, service_info_t * api);
gboolean service_info_API2ASN(service_info_t * api, ServiceInfo_t * asn);
void service_info_cleanASN(ServiceInfo_t * asn, gboolean only_content);

#endif
