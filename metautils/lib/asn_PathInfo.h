#ifndef __ASN_PATHINFO_H__
#define __ASN_PATHINFO_H__

#include "./metatypes.h"
#include "./PathInfo.h"

gboolean path_info_ASN2API(const PathInfo_t * asn, path_info_t * api);
gboolean path_info_API2ASN(const path_info_t * api, PathInfo_t * asn);
void path_info_cleanASN(PathInfo_t * asn, gboolean only_content);

#endif /*__ASN_PATHINFO_H__*/
