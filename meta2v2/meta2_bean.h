/*
OpenIO SDS meta2v2
Copyright (C) 2014 Worldline, as part of Redcurrant
Copyright (C) 2015-2017 OpenIO, as part of OpenIO SDS

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef OIO_SDS__meta2v2__meta2_bean_h
# define OIO_SDS__meta2v2__meta2_bean_h 1

#include <metautils/lib/metatypes.h>

struct M2V2Property;
struct M2V2Bean;
struct M2V2Alias;
struct M2V2Content;
struct M2V2ContentHeader;

gpointer bean_ASN2API(const struct M2V2Bean *asn);

gboolean bean_API2ASN(gpointer * api, struct M2V2Bean * asn);

void bean_cleanASN(struct M2V2Bean * asn, gboolean only_content);

GByteArray* bean_sequence_marshall(GSList *beans);

GSList* bean_sequence_unmarshall(const guint8 *buf, gsize buf_len);

gint bean_sequence_decoder(GSList **l, const void *buf, gsize len, GError **err);

#endif /*OIO_SDS__meta2v2__meta2_bean_h*/
