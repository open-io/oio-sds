/*
 * Copyright (C) 2013 AtoS Worldline
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __META2_BEAN_H__
#define __META2_BEAN_H__

#include "../metautils/lib/metatypes.h"
#include "../metautils/lib/M2V2Bean.h"
#include "../metautils/lib/M2V2Alias.h"
#include "../metautils/lib/M2V2Content.h"
#include "../metautils/lib/M2V2ContentHeader.h"
#include "../metautils/lib/M2V2Property.h"

/**
 *
 */
gpointer bean_ASN2API(const M2V2Bean_t * asn);

gboolean bean_API2ASN(gpointer * api, M2V2Bean_t * asn);

void bean_cleanASN(M2V2Bean_t * asn, gboolean only_content);

/* ------------------------------------ */

GByteArray* bean_sequence_marshall(GSList *beans);

GSList* bean_sequence_unmarshall(const guint8 *buf, gsize buf_len);

gint bean_sequence_decoder(GSList **l, const void *buf, gsize *buf_len, GError **err);

#endif /*__META2_BEAN_H__*/
