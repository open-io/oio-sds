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

#ifndef __ASN_META1STAT_H__
#define __ASN_META1STAT_H__

#include "./metatypes.h"
#include "./Meta1Stat.h"

gboolean meta1_stat_ASN2API(const Meta1Stat_t * asn, meta1_stat_t * api);
gboolean meta1_stat_API2ASN(const meta1_stat_t * api, Meta1Stat_t * asn);
void meta1_stat_cleanASN(Meta1Stat_t * asn, gboolean only_content);

#endif /*__ASN_META1STAT_H__*/
