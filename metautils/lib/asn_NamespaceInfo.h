#ifndef __ASN_META1INFO_H__
#define __ASN_META1INFO_H__

#include "./metatypes.h"
#include "./NamespaceInfo.h"

gboolean namespace_info_ASN2API(const NamespaceInfo_t * asn, namespace_info_t * api);
gboolean namespace_info_API2ASN(const namespace_info_t * api, gint64 version, NamespaceInfo_t * asn);
void namespace_info_cleanASN(NamespaceInfo_t * asn, gboolean only_content);

#endif /*__ASN_META1INFO_H__*/
