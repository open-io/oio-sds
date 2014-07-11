#ifndef __META2_BEAN_H__
#define __META2_BEAN_H__

#include <metautils/lib/metatypes.h>

struct M2V2Property;
struct M2V2Bean;
struct M2V2Alias;
struct M2V2Content;
struct M2V2ContentHeader;

/**
 *
 */
gpointer bean_ASN2API(const struct M2V2Bean *asn);

gboolean bean_API2ASN(gpointer * api, struct M2V2Bean * asn);

void bean_cleanASN(struct M2V2Bean * asn, gboolean only_content);

/* ------------------------------------ */

GByteArray* bean_sequence_marshall(GSList *beans);

GSList* bean_sequence_unmarshall(const guint8 *buf, gsize buf_len);

gint bean_sequence_decoder(GSList **l, const void *buf, gsize *buf_len, GError **err);

#endif /*__META2_BEAN_H__*/
