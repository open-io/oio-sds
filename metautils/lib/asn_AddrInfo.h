#ifndef __ASN_ADDRINFO_H__
#define __ASN_ADDRINFO_H__

#include "./metatypes.h"
#include "./AddrInfoSequence.h"

gboolean addr_info_ASN2API(const AddrInfo_t * asn, addr_info_t * api);
gboolean addr_info_API2ASN(const addr_info_t * api, AddrInfo_t * asn);
void addr_info_cleanASN(AddrInfo_t * asn, gboolean only_content);

#endif /*__ASN_ADDRINFO_H__*/
