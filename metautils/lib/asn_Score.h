#ifndef __ASN_SCORE_H__
#define __ASN_SCORE_H__

#include "./metatypes.h"
#include "./Score.h"

gboolean score_ASN2API(const Score_t * asn, score_t * api);
gboolean score_API2ASN(const score_t * api, Score_t * asn);
void score_cleanASN(Score_t * asn, gboolean only_content);

#endif /*__ASN_SCORE_H__*/
