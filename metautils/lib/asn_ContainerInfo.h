#ifndef __ASN_CONTAINERINFO_H__
#define __ASN_CONTAINERINFO_H__

#include "./metatypes.h"
#include "./ContainerInfo.h"

gboolean container_info_ASN2API(const ContainerInfo_t * asn, container_info_t * api);
gboolean container_info_API2ASN(const container_info_t * api, ContainerInfo_t * asn);
void container_info_cleanASN(ContainerInfo_t * asn, gboolean only_content);

#endif /*__ASN_CONTAINERINFO_H__*/
