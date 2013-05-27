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

#ifndef __ASN_META2INFO_H__
#define __ASN_META2INFO_H__

#include "./metatypes.h"
#include "./Meta2Info.h"

gboolean meta2_info_ASN2API(const Meta2Info_t * asn, meta2_info_t * api);
gboolean meta2_info_API2ASN(const meta2_info_t * api, Meta2Info_t * asn);
void meta2_info_cleanASN(Meta2Info_t * asn, gboolean only_content);

#endif /*__ASN_META2INFO_H__*/
