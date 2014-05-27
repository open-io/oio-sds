#ifndef __ASN_META0INFO_H__
#define __ASN_META0INFO_H__

#include "./metatypes.h"
#include "./AddrInfo.h"
#include "./Meta0Info.h"

gboolean meta0_info_ASN2API(const Meta0Info_t * asn, meta0_info_t * api);
gboolean meta0_info_API2ASN(const meta0_info_t * api, Meta0Info_t * asn);
void meta0_info_cleanASN(Meta0Info_t * asn, gboolean only_content);

#endif /*__ASN_META0INFO_H__*/
