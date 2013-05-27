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

#ifndef __ASN_CONTAINEREVENT_H__
#define __ASN_CONTAINEREVENT_H__

#include "./metatypes.h"
#include "./ContainerEvent.h"

gboolean container_event_ASN2API(const ContainerEvent_t * asn, container_event_t * api);
gboolean container_event_API2ASN(const container_event_t * api, ContainerEvent_t * asn);
void container_event_cleanASN(ContainerEvent_t * asn, gboolean only_content);

#endif /*__ASN_CONTAINER_H__*/
