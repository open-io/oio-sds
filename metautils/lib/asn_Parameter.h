#ifndef __ASN_PARAMETER_H__
#define __ASN_PARAMETER_H__

#include "./metatypes.h"
#include "./Parameter.h"

gboolean key_value_pair_ASN2API(const Parameter_t * asn, key_value_pair_t * api);
gboolean key_value_pair_API2ASN(const key_value_pair_t * api, Parameter_t * asn);
void key_value_pair_cleanASN(Parameter_t * asn, gboolean only_content);

#endif /*__ASN_PARAMETER_H__*/
